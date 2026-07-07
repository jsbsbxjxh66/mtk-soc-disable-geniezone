#!/usr/bin/env python3
"""
patch_gz_gpt.py - Disable MediaTek GenieZone by patching GPT partition table

将 gz 分区 LBA 指向设备容量+1（越界 1 扇区），使 preloader 的
func_40974 I/O 失败返回 -1，触发 NoGZ 标志，跳过 GZ 加载。

Usage:
  python3 patch_gz_gpt.py <pgpt.bin>                # 修改 gz 分区 LBA
  python3 patch_gz_gpt.py <pgpt.bin> --dry-run      # 仅分析不修改
  python3 patch_gz_gpt.py <pgpt.bin> --restore      # 从备份还原
"""

import struct
import binascii
import argparse
import shutil
import sys
import os


def find_gpt_header(data):
    sig = b'EFI PART'
    candidates = []
    off = 0
    while off < min(len(data), 0x100000):
        pos = data.find(sig, off)
        if pos < 0:
            break
        candidates.append(pos)
        off = pos + 1

    if not candidates:
        return None, None

    for pos in candidates:
        if pos + 92 > len(data):
            continue
        header_size = struct.unpack_from('<I', data, pos + 12)[0]
        if header_size != 92:
            continue
        my_lba = struct.unpack_from('<Q', data, pos + 24)[0]
        if my_lba == 0:
            continue

        sector_size = pos // my_lba if my_lba > 0 else 0
        if sector_size in (512, 4096):
            hdr_copy = bytearray(data[pos:pos + header_size])
            stored_crc = struct.unpack_from('<I', hdr_copy, 16)[0]
            hdr_copy[16:20] = b'\x00\x00\x00\x00'
            calc_crc = binascii.crc32(hdr_copy) & 0xFFFFFFFF
            if stored_crc == calc_crc:
                return pos, sector_size

    pos = candidates[0]
    my_lba = struct.unpack_from('<Q', data, pos + 24)[0]
    if my_lba > 0:
        sector_size = pos // my_lba
        if sector_size not in (512, 4096):
            sector_size = 4096 if pos >= 4096 else 512
    else:
        sector_size = 4096 if pos >= 4096 else 512
    return pos, sector_size


def parse_gpt_header(data, hdr_off):
    fields = {}
    fields['signature'] = data[hdr_off:hdr_off + 8]
    fields['revision'] = struct.unpack_from('<I', data, hdr_off + 8)[0]
    fields['header_size'] = struct.unpack_from('<I', data, hdr_off + 12)[0]
    fields['header_crc32'] = struct.unpack_from('<I', data, hdr_off + 16)[0]
    fields['my_lba'] = struct.unpack_from('<Q', data, hdr_off + 24)[0]
    fields['alt_lba'] = struct.unpack_from('<Q', data, hdr_off + 32)[0]
    fields['first_usable'] = struct.unpack_from('<Q', data, hdr_off + 40)[0]
    fields['last_usable'] = struct.unpack_from('<Q', data, hdr_off + 48)[0]
    fields['disk_guid'] = data[hdr_off + 56:hdr_off + 72]
    fields['entry_start_lba'] = struct.unpack_from('<Q', data, hdr_off + 72)[0]
    fields['num_entries'] = struct.unpack_from('<I', data, hdr_off + 80)[0]
    fields['entry_size'] = struct.unpack_from('<I', data, hdr_off + 84)[0]
    fields['entries_crc32'] = struct.unpack_from('<I', data, hdr_off + 88)[0]
    return fields


def parse_partitions(data, entries_off, num_entries, entry_size):
    parts = []
    for i in range(num_entries):
        off = entries_off + i * entry_size
        if off + entry_size > len(data):
            break
        type_guid = data[off:off + 16]
        if type_guid == b'\x00' * 16:
            parts.append(None)
            continue
        start_lba = struct.unpack_from('<Q', data, off + 32)[0]
        end_lba = struct.unpack_from('<Q', data, off + 40)[0]
        attributes = struct.unpack_from('<Q', data, off + 48)[0]
        name_raw = data[off + 56:off + 56 + 72]
        try:
            name = name_raw.decode('utf-16-le').rstrip('\x00')
        except UnicodeDecodeError:
            name = f"<entry_{i}>"
        parts.append({
            'index': i,
            'offset': off,
            'type_guid': type_guid,
            'unique_guid': data[off + 16:off + 32],
            'start_lba': start_lba,
            'end_lba': end_lba,
            'attributes': attributes,
            'name': name,
            'name_raw': name_raw,
        })
    return parts


def format_size(size_bytes):
    if size_bytes >= 1024 ** 3:
        return f"{size_bytes / 1024 ** 3:.1f} GB"
    if size_bytes >= 1024 ** 2:
        return f"{size_bytes / 1024 ** 2:.1f} MB"
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.0f} KB"
    return f"{size_bytes} B"


def update_crcs(data, hdr_off, entries_off, num_entries, entry_size):
    entries_blob = bytes(data[entries_off:entries_off + num_entries * entry_size])
    new_ecrc = binascii.crc32(entries_blob) & 0xFFFFFFFF
    struct.pack_into('<I', data, hdr_off + 88, new_ecrc)

    header_size = struct.unpack_from('<I', data, hdr_off + 12)[0]
    struct.pack_into('<I', data, hdr_off + 16, 0)
    hdr_blob = bytes(data[hdr_off:hdr_off + header_size])
    new_hcrc = binascii.crc32(hdr_blob) & 0xFFFFFFFF
    struct.pack_into('<I', data, hdr_off + 16, new_hcrc)

    return new_ecrc, new_hcrc


def verify_crcs(data, hdr_off, entries_off, num_entries, entry_size):
    header_size = struct.unpack_from('<I', data, hdr_off + 12)[0]
    stored_hcrc = struct.unpack_from('<I', data, hdr_off + 16)[0]
    hdr_copy = bytearray(data[hdr_off:hdr_off + header_size])
    hdr_copy[16:20] = b'\x00\x00\x00\x00'
    calc_hcrc = binascii.crc32(hdr_copy) & 0xFFFFFFFF

    stored_ecrc = struct.unpack_from('<I', data, hdr_off + 88)[0]
    entries_blob = data[entries_off:entries_off + num_entries * entry_size]
    calc_ecrc = binascii.crc32(entries_blob) & 0xFFFFFFFF

    return (stored_hcrc == calc_hcrc, stored_ecrc == calc_ecrc)


def find_gz_partitions(parts):
    gz_parts = []
    for p in parts:
        if p is None:
            continue
        name_lower = p['name'].lower()
        if name_lower in ('gz', 'gz1', 'gz2', 'gz_a', 'gz_b', 'gz1_a', 'gz1_b', 'gz2_a', 'gz2_b'):
            gz_parts.append(p)
    return gz_parts


def apply_patch(data, gz_parts, total_lbas):
    invalid_base = total_lbas
    print(f"\n  无效 LBA: {invalid_base:#x} (最后有效 LBA: {total_lbas - 1:#x})")
    print(f"  紧贴设备末尾")
    print(f"  原理: func_40974 读取越界 LBA → 返回 -1 → NoGZ")

    for i, p in enumerate(gz_parts):
        new_start = invalid_base + i * 2
        new_end = new_start

        print(f"\n  {p['name']}:")
        print(f"    Start LBA: {p['start_lba']:#x} → {new_start:#x}")
        print(f"    End LBA:   {p['end_lba']:#x} → {new_end:#x}")

        struct.pack_into('<Q', data, p['offset'] + 32, new_start)
        struct.pack_into('<Q', data, p['offset'] + 40, new_end)


def main():
    parser = argparse.ArgumentParser(
        description='修改 GPT 分区表以禁用 GenieZone',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
将 gz 分区 LBA 指向紧贴设备末尾的无效地址，触发 I/O 失败 → NoGZ。
""")
    parser.add_argument('input', help='GPT 分区表文件 (pgpt.bin)')
    parser.add_argument('-o', '--output', help='输出文件路径')
    parser.add_argument('--dry-run', action='store_true', help='仅分析不修改')
    parser.add_argument('--restore', action='store_true', help='从备份还原')
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"错误: 文件不存在: {args.input}")
        sys.exit(1)

    base, ext = os.path.splitext(args.input)
    backup_path = base + '_backup' + ext
    output_path = args.output or (base + '_patched' + ext)

    if args.restore:
        if not os.path.isfile(backup_path):
            print(f"错误: 备份文件不存在: {backup_path}")
            sys.exit(1)
        shutil.copy2(backup_path, args.input)
        print(f"已从 {backup_path} 还原到 {args.input}")
        if output_path != args.input and os.path.isfile(output_path):
            os.remove(output_path)
            print(f"已删除修改后的文件: {output_path}")
        sys.exit(0)

    with open(args.input, 'rb') as f:
        raw = f.read()

    print(f"输入文件: {args.input} ({len(raw)} 字节)")

    # ── 1. 检测 GPT 布局 ──
    hdr_off, sector_size = find_gpt_header(raw)
    if hdr_off is None:
        print("错误: 未找到有效的 GPT 头 (EFI PART 签名)")
        sys.exit(1)

    print(f"GPT 头位置: offset {hdr_off:#x}")
    print(f"扇区大小: {sector_size} 字节")

    hdr = parse_gpt_header(raw, hdr_off)
    entries_off = hdr['entry_start_lba'] * sector_size
    num_entries = hdr['num_entries']
    entry_size = hdr['entry_size']
    total_lbas = hdr['alt_lba'] + 1
    device_bytes = total_lbas * sector_size

    print(f"设备容量: {total_lbas} LBA = {format_size(device_bytes)}")
    print(f"分区条目: {num_entries} 个 × {entry_size} 字节, 起始 offset {entries_off:#x}")

    needed = entries_off + num_entries * entry_size
    if needed > len(raw):
        actual = (len(raw) - entries_off) // entry_size
        print(f"警告: 文件仅包含 {actual}/{num_entries} 个分区条目")
        num_entries = actual

    hdr_ok, ent_ok = verify_crcs(raw, hdr_off, entries_off, num_entries, entry_size)
    print(f"CRC 校验: Header={'通过' if hdr_ok else '失败!'}, Entries={'通过' if ent_ok else '失败!'}")
    if not hdr_ok or not ent_ok:
        print("警告: 输入文件 CRC 校验不通过，可能已损坏")

    # ── 2. 解析分区表 ──
    parts = parse_partitions(raw, entries_off, num_entries, entry_size)
    active_parts = [p for p in parts if p is not None]
    print(f"\n共 {len(active_parts)} 个有效分区:")
    print(f"  {'#':>3} {'名称':<20} {'起始 LBA':>12} {'结束 LBA':>12} {'大小':>10}")
    print(f"  {'─' * 3} {'─' * 20} {'─' * 12} {'─' * 12} {'─' * 10}")
    for p in active_parts:
        sectors = p['end_lba'] - p['start_lba'] + 1
        sz = format_size(sectors * sector_size)
        marker = ""
        if 'gz' in p['name'].lower():
            marker = "  ◄◄"
        print(f"  {p['index']:3d} {p['name']:<20} {p['start_lba']:>12} {p['end_lba']:>12} {sz:>10}{marker}")

    # ── 3. 查找 gz 分区 ──
    gz_parts = find_gz_partitions(parts)
    if not gz_parts:
        print("\n错误: 未找到 gz 相关分区 (gz/gz1/gz2/gz_a/gz1_a/...)")
        print("此设备可能不使用 GenieZone，或分区命名不同")
        sys.exit(1)

    print(f"\n找到 {len(gz_parts)} 个 GZ 分区:")
    for p in gz_parts:
        sectors = p['end_lba'] - p['start_lba'] + 1
        print(f"  {p['name']}: LBA {p['start_lba']:#x} - {p['end_lba']:#x} "
              f"({sectors} 扇区, {format_size(sectors * sector_size)})")

    if args.dry_run:
        print(f"\n[DRY RUN] 以上为分析结果，未进行任何修改")
        sys.exit(0)

    # ── 4. 备份 ──
    if not os.path.isfile(backup_path):
        shutil.copy2(args.input, backup_path)
        print(f"已备份原始文件到: {backup_path}")

    data = bytearray(raw)

    # ── 5. 应用修改 ──
    print(f"\n修改详情:")
    apply_patch(data, gz_parts, total_lbas)

    # ── 6. 更新 CRC ──
    new_ecrc, new_hcrc = update_crcs(data, hdr_off, entries_off, num_entries, entry_size)
    print(f"\nCRC 更新:")
    print(f"  Entries CRC32: {hdr['entries_crc32']:#010x} → {new_ecrc:#010x}")
    print(f"  Header CRC32:  {hdr['header_crc32']:#010x} → {new_hcrc:#010x}")

    # ── 7. 验证并保存 ──
    hdr_ok, ent_ok = verify_crcs(data, hdr_off, entries_off, num_entries, entry_size)
    if not hdr_ok or not ent_ok:
        print("\n错误: CRC 验证失败，未保存文件")
        sys.exit(1)

    try:
        with open(output_path, 'wb') as f:
            f.write(data)
    except OSError as e:
        print(f"\n错误: 无法写入输出文件: {e}")
        sys.exit(1)

    diff_count = sum(1 for a, b in zip(raw, data) if a != b)

    print(f"\n{'═' * 50}")
    print(f"完成! 共修改 {diff_count} 字节")
    print(f"输出文件: {output_path}")
    print(f"备份文件: {backup_path}")
    print(f"{'═' * 50}")
    print(f"\n刷写方法:")
    print(f"  fastboot flash pgpt {output_path}")
    print(f"\n还原方法:")
    print(f"  fastboot flash pgpt {backup_path}")
    print(f"  或: python3 {sys.argv[0]} {args.input} --restore")


if __name__ == '__main__':
    main()
