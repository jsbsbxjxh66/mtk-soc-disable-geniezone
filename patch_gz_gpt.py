#!/usr/bin/env python3
"""
patch_gz_gpt.py - Disable MediaTek GenieZone by patching GPT partition table

Keeps gz1/gz2 partition entries in GPT (passes preloader's get_part_info check)
but points their LBAs beyond device capacity, causing storage reads to fail
and triggering the internal NoGZ flag. No preloader signature is broken.

通过修改 GPT 分区表中 gz 分区的 LBA 地址来禁用 GenieZone。
保留分区条目（通过存在性检查），但将 LBA 指向设备容量之外，
使存储读取失败，触发 NoGZ 标志。不破坏 preloader 签名。

Usage:
  python3 patch_gz_gpt.py <pgpt.bin>                 # patch → pgpt_patched.bin
  python3 patch_gz_gpt.py <pgpt.bin> -o <output.bin>  # custom output path
  python3 patch_gz_gpt.py <pgpt.bin> --dry-run        # analyze only
  python3 patch_gz_gpt.py <pgpt.bin> --restore        # restore from backup
"""

import struct
import binascii
import argparse
import shutil
import sys
import os


def find_gpt_header(data):
    """在文件中搜索 'EFI PART' 签名，自动检测扇区大小和 GPT 头偏移。"""
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

    # 回退：使用第一个候选位置推断
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
    """解析 GPT 头，返回字段字典。"""
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
    """解析所有分区条目。"""
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
    """重新计算并写入 entries CRC32 和 header CRC32。"""
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
    """验证 CRC32 校验。"""
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
    """查找所有 gz 相关分区（gz1, gz2, gz1_a, gz1_b 等）。"""
    gz_parts = []
    for p in parts:
        if p is None:
            continue
        name_lower = p['name'].lower()
        if name_lower in ('gz1', 'gz2', 'gz1_a', 'gz1_b', 'gz2_a', 'gz2_b'):
            gz_parts.append(p)
    return gz_parts


def main():
    parser = argparse.ArgumentParser(
        description='修改 GPT 分区表中 gz 分区的 LBA 地址以禁用 GenieZone')
    parser.add_argument('input', help='输入的 GPT 分区表文件 (pgpt.bin)')
    parser.add_argument('-o', '--output', help='输出文件路径 (默认: <input>_patched.bin)')
    parser.add_argument('--dry-run', action='store_true', help='仅分析不修改')
    parser.add_argument('--restore', action='store_true', help='从备份还原原始文件')
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"错误: 文件不存在: {args.input}")
        sys.exit(1)

    base, ext = os.path.splitext(args.input)
    backup_path = base + '_backup' + ext
    output_path = args.output or (base + '_patched' + ext)

    # 还原模式
    if args.restore:
        if not os.path.isfile(backup_path):
            print(f"错误: 备份文件不存在: {backup_path}")
            sys.exit(1)
        shutil.copy2(backup_path, args.input)
        print(f"已从 {backup_path} 还原到 {args.input}")
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

    # 验证文件中包含足够的条目数据
    needed = entries_off + num_entries * entry_size
    if needed > len(raw):
        actual = (len(raw) - entries_off) // entry_size
        print(f"警告: 文件仅包含 {actual}/{num_entries} 个分区条目")
        num_entries = actual

    # 验证 CRC
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
        print("\n错误: 未找到 gz 相关分区 (gz1/gz2/gz1_a/gz1_b)")
        print("此设备可能不使用 GenieZone，或分区命名不同")
        sys.exit(1)

    print(f"\n找到 {len(gz_parts)} 个 GZ 分区:")
    for p in gz_parts:
        sectors = p['end_lba'] - p['start_lba'] + 1
        print(f"  {p['name']}: LBA {p['start_lba']:#x} - {p['end_lba']:#x} ({sectors} 扇区, {format_size(sectors * sector_size)})")

    # 检查是否已经被修改过
    already_patched = []
    for p in gz_parts:
        if p['start_lba'] > total_lbas:
            already_patched.append(p)

    if already_patched:
        print(f"\n注意: 以下分区的 LBA 已超出设备容量，可能已经被修改过:")
        for p in already_patched:
            print(f"  {p['name']}: Start LBA {p['start_lba']:#x} > 设备容量 {total_lbas:#x}")
        if len(already_patched) == len(gz_parts):
            print("\n所有 gz 分区已经是无效 LBA 状态，无需再次修改")
            sys.exit(0)

    if args.dry_run:
        print("\n[DRY RUN] 以上为分析结果，未进行任何修改")
        sys.exit(0)

    # ── 4. 执行修改 ──
    # 计算无效 LBA: 设备总 LBA 向上对齐到 2^N，确保远超设备容量且在 32 位范围内
    invalid_base = 1
    while invalid_base <= total_lbas:
        invalid_base <<= 1
    # 确保不超过 32 位 (preloader 内部结构使用 uint32)
    if invalid_base > 0x7FFFFFFE:
        invalid_base = 0x7FFFFFFE

    print(f"\n无效 LBA 基址: {invalid_base:#x} (设备容量: {total_lbas:#x})")

    # 备份原文件
    if not os.path.isfile(backup_path):
        shutil.copy2(args.input, backup_path)
        print(f"已备份原始文件到: {backup_path}")

    data = bytearray(raw)

    print(f"\n修改详情:")
    for i, p in enumerate(gz_parts):
        new_start = invalid_base + i * 4
        new_end = new_start + 1  # 2 扇区，通过 preloader 的 range check

        old_start = p['start_lba']
        old_end = p['end_lba']

        struct.pack_into('<Q', data, p['offset'] + 32, new_start)
        struct.pack_into('<Q', data, p['offset'] + 40, new_end)

        print(f"  {p['name']}:")
        print(f"    Start LBA: {old_start:#x} → {new_start:#x}")
        print(f"    End LBA:   {old_end:#x} → {new_end:#x}")
        print(f"    扇区数:    {old_end - old_start + 1} → {new_end - new_start + 1}")

    # ── 5. 更新 CRC ──
    new_ecrc, new_hcrc = update_crcs(data, hdr_off, entries_off, num_entries, entry_size)
    print(f"\nCRC 更新:")
    print(f"  Entries CRC32: {hdr['entries_crc32']:#010x} → {new_ecrc:#010x}")
    print(f"  Header CRC32:  {hdr['header_crc32']:#010x} → {new_hcrc:#010x}")

    # ── 6. 验证并保存 ──
    hdr_ok, ent_ok = verify_crcs(data, hdr_off, entries_off, num_entries, entry_size)
    if not hdr_ok or not ent_ok:
        print("\n错误: CRC 验证失败，未保存文件")
        sys.exit(1)

    with open(output_path, 'wb') as f:
        f.write(data)

    # 统计差异字节数
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
