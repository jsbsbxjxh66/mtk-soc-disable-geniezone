#!/usr/bin/env python3
"""
patch_vendor_boot.py - 修补 vendor_boot.img 中的设备树以禁用 VCP

Android GKI 设备的内核设备树嵌在 vendor_boot.img 中 (VNDRBOOT v3/v4 格式),
LK 中的 DTB 仅影响 bootloader 阶段的 VCP 固件加载,
内核 VCP 驱动是否 probe 取决于 vendor_boot DTB 中的 status 属性。

功能:
  - 自动解析 VNDRBOOT 头, 定位内嵌的 DTB
  - 扫描所有 DTB 中的 vcp-support / status 属性
  - 将主 VCP 节点 (vcp-support=1) 改为 vcp-support=0, status="fail"
  - 支持多 DTB (vendor_boot v4 可嵌多个 DTB)

用法:
  python3 patch_vendor_boot.py vendor_boot.img                  # 分析并修补
  python3 patch_vendor_boot.py vendor_boot.img --dry-run        # 仅预览
  python3 patch_vendor_boot.py vendor_boot.img -o output.img    # 指定输出
  python3 patch_vendor_boot.py vendor_boot.img --restore        # 从备份还原
"""

import struct
import argparse
import shutil
import sys
import os


VNDRBOOT_MAGIC = b'VNDRBOOT'
FDT_MAGIC = b'\xd0\x0d\xfe\xed'


def find_all_fdt_blobs(data):
    """扫描整个文件, 找到所有 FDT (Device Tree Blob) 的偏移和大小."""
    blobs = []
    offset = 0
    while offset < len(data) - 40:
        pos = data.find(FDT_MAGIC, offset)
        if pos == -1:
            break
        if pos + 8 > len(data):
            break
        totalsize = struct.unpack('>I', data[pos + 4:pos + 8])[0]
        if 0x100 <= totalsize <= 0x200000 and pos + totalsize <= len(data):
            version = struct.unpack('>I', data[pos + 20:pos + 24])[0]
            if 1 <= version <= 30:
                blobs.append((pos, totalsize))
                offset = pos + totalsize
                continue
        offset = pos + 4
    return blobs


def parse_dtb_vcp_nodes(data, dtb_offset, dtb_size):
    """解析单个 DTB, 返回其中所有 vcp-support 属性的信息."""
    d = data
    pos = dtb_offset

    off_dt_struct = struct.unpack('>I', d[pos + 8:pos + 12])[0]
    off_dt_strings = struct.unpack('>I', d[pos + 12:pos + 16])[0]

    str_base = pos + off_dt_strings
    struct_base = pos + off_dt_struct

    def get_prop_name(name_off):
        s = str_base + name_off
        if s >= len(d):
            return ''
        end = d.index(b'\x00', s) if s < len(d) else s
        return d[s:end].decode('ascii', errors='replace')

    results = []
    node_stack = []
    i = struct_base
    pending_vcp_support = {}

    while i < pos + dtb_size - 4:
        token = struct.unpack('>I', d[i:i + 4])[0]
        if token == 1:  # FDT_BEGIN_NODE
            i += 4
            if i >= len(d):
                break
            end = d.index(b'\x00', i)
            name = d[i:end].decode('ascii', errors='replace')
            node_stack.append(name)
            i = (end + 4) & ~3
        elif token == 2:  # FDT_END_NODE
            if node_stack:
                node_stack.pop()
            i += 4
        elif token == 3:  # FDT_PROP
            if i + 12 > len(d):
                break
            prop_len = struct.unpack('>I', d[i + 4:i + 8])[0]
            name_off = struct.unpack('>I', d[i + 8:i + 12])[0]
            prop_name = get_prop_name(name_off)
            path = '/' + '/'.join(node_stack)
            if prop_name == 'vcp-support' and prop_len == 4 and i + 16 <= len(d):
                val = struct.unpack('>I', d[i + 12:i + 16])[0]
                entry = {
                    'dtb_offset': dtb_offset,
                    'value_file_offset': i + 12,
                    'path': path,
                    'value': val,
                }
                pending_vcp_support[path] = entry
                results.append(entry)
            elif prop_name == 'status' and prop_len >= 4:
                status_str = d[i + 12:i + 12 + prop_len].rstrip(b'\x00') \
                    .decode('ascii', errors='replace')
                if path in pending_vcp_support:
                    pending_vcp_support[path]['status'] = status_str
                    pending_vcp_support[path]['status_file_offset'] = i + 12
                    pending_vcp_support[path]['status_len'] = prop_len
            i += 12 + ((prop_len + 3) & ~3)
        elif token == 9:  # FDT_END
            break
        else:
            i += 4

    return results


def analyze(data, path):
    """分析 vendor_boot.img, 返回检测结果."""
    info = {'path': path, 'size': len(data)}

    if data[:8] == VNDRBOOT_MAGIC:
        version = struct.unpack('<I', data[8:12])[0]
        info['format'] = f'VNDRBOOT v{version}'
    else:
        info['format'] = 'raw'

    blobs = find_all_fdt_blobs(data)
    info['dtb_count'] = len(blobs)
    info['dtb_blobs'] = blobs

    all_nodes = []
    for dtb_off, dtb_size in blobs:
        nodes = parse_dtb_vcp_nodes(data, dtb_off, dtb_size)
        all_nodes.extend(nodes)
    info['vcp_nodes'] = all_nodes

    return info


def print_analysis(info):
    """打印分析结果."""
    print(f"\n{'=' * 55}")
    print(f"vendor_boot.img 分析")
    print(f"{'=' * 55}")
    print(f"  文件: {info['path']}")
    print(f"  大小: {info['size']} 字节 ({info['size'] / 1024 / 1024:.1f} MB)")
    print(f"  格式: {info['format']}")
    print(f"  DTB 数量: {info['dtb_count']}")

    for idx, (off, sz) in enumerate(info['dtb_blobs']):
        print(f"    DTB#{idx}: 偏移=0x{off:X}, 大小={sz} 字节")

    nodes = info['vcp_nodes']
    if not nodes:
        print(f"\n  未找到 VCP 节点")
        return

    print(f"\n  VCP 节点: {len(nodes)} 个")
    patchable = 0
    for node in nodes:
        status = node.get('status', '(无)')
        marker = ''
        if node['value'] == 1 and status == 'okay':
            marker = '  <-- 可禁用'
            patchable += 1
        elif node['value'] == 0:
            marker = '  (已禁用)'
        print(f"    DTB@0x{node['dtb_offset']:X} {node['path']}:"
              f" vcp-support={node['value']} status=\"{status}\"{marker}")

    if patchable:
        print(f"\n  可禁用 VCP 节点: {patchable} 个"
              f" (vcp-support=1->0, status=\"okay\"->\"fail\")")
    else:
        print(f"\n  无需修补 (所有主 VCP 节点已禁用或不存在)")


def do_patch(data, info, output_path, dry_run=False):
    """执行 VCP 禁用补丁."""
    nodes = info['vcp_nodes']
    targets = [n for n in nodes if n['value'] == 1]

    if not targets:
        already = [n for n in nodes if n['value'] == 0]
        if already:
            print("\nVCP 已禁用 (vcp-support=0), 无需修补")
        else:
            print("\n错误: 未在 DTB 中找到 vcp-support=1 的主 VCP 节点")
        return False

    patched = bytearray(data)
    patch_count = 0

    print(f"\nVCP 禁用补丁:")
    print(f"  效果: 内核 VCP 驱动不 probe, 不初始化 VCP 子系统")
    print(f"         避免 IOMMU protect pgtable 缺失导致的 WDT 超时重启")
    print(f"         (视频硬件编解码可能不可用)\n")

    for node in targets:
        off = node['value_file_offset']
        old_bytes = data[off:off + 4]
        print(f"  DTB@0x{node['dtb_offset']:06X} {node['path']}:")
        print(f"    vcp-support: 0x{off:06X}  {old_bytes.hex()} -> 00000000")
        struct.pack_into('>I', patched, off, 0)
        patch_count += 1

        st_off = node.get('status_file_offset')
        st_val = node.get('status', '')
        st_len = node.get('status_len', 0)
        if st_off is not None and st_val == 'okay' and st_len >= 5:
            old_st = data[st_off:st_off + st_len]
            new_st = b'fail\x00' + b'\x00' * (st_len - 5)
            print(f"    status:      0x{st_off:06X}  \"{st_val}\" -> \"fail\"")
            patched[st_off:st_off + st_len] = new_st
            patch_count += 1
        elif st_off is not None and st_val != 'okay':
            print(f"    status:      \"{st_val}\" (非 okay, 跳过)")
        else:
            print(f"    status:      (无 status 属性)")

    if dry_run:
        print(f"\n[DRY RUN] 以上为补丁预览, 未修改任何文件")
        return True

    diff_count = sum(1 for a, b in zip(data, patched) if a != b)
    try:
        with open(output_path, 'wb') as f:
            f.write(patched)
    except OSError as e:
        print(f"\n错误: 无法写入文件: {e}")
        return False

    print(f"\n{'=' * 55}")
    print(f"完成! 共修改 {diff_count} 字节, 禁用 {len(targets)} 个 VCP 节点")
    print(f"输出文件: {output_path}")
    print(f"{'=' * 55}")
    return True


def main():
    parser = argparse.ArgumentParser(
        description='修补 vendor_boot.img 中的设备树以禁用 VCP',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
说明:
  LK 的 DTB 仅影响 bootloader 阶段 (是否加载 VCP 固件),
  内核 VCP 驱动是否 probe 取决于 vendor_boot.img 中 DTB 的 status 属性。
  禁用 GZ 后若 VCP 仍在运行, 需同时修补此镜像。

  配合 detect_lk_gz.py --patch-vcp 一起使用:
    1. detect_lk_gz.py lk.img --patch-vcp      → LK 不加载 VCP 固件
    2. patch_vendor_boot.py vendor_boot.img     → 内核不 probe VCP 驱动
""")
    parser.add_argument('input', help='vendor_boot.img 文件路径')
    parser.add_argument('-o', '--output', help='输出文件路径 (默认: *_patched.*)')
    parser.add_argument('--dry-run', action='store_true',
                        help='仅预览补丁, 不修改文件')
    parser.add_argument('--restore', action='store_true',
                        help='从备份还原原始文件')
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
        data = f.read()

    info = analyze(data, args.input)
    print_analysis(info)

    if not info['vcp_nodes']:
        print("\n无 VCP 节点, 无需修补")
        sys.exit(0)

    has_patchable = any(n['value'] == 1 for n in info['vcp_nodes'])
    if not has_patchable and not args.dry_run:
        sys.exit(0)

    if not args.dry_run and not os.path.isfile(backup_path):
        shutil.copy2(args.input, backup_path)
        print(f"\n已备份原始文件到: {backup_path}")

    ok = do_patch(data, info, output_path, dry_run=args.dry_run)
    if not ok and not args.dry_run:
        sys.exit(1)


if __name__ == '__main__':
    main()
