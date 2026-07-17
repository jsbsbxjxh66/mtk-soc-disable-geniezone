#!/usr/bin/env python3
"""
detect_lk_gz.py - 检测并修补 MediaTek LK 中的 GenieZone / VCP 相关逻辑

分析 LK (Little Kernel) 固件:
  1. 解析 MTK 镜像头, 提取 LK 代码段及 bl2_ext 段
  2. 检测 GZ 初始化管线 (bl2_ext) 和 DTB 中的 VCP 节点
  3. 提供补丁: 禁用 GenieZone 并释放其占用内存, 或禁用 VCP

GZ 初始化管线 (bl2_ext, 如 MT6991):
  python3 detect_lk_gz.py lk.img --patch-validate          # 方案A: 跳过GZ初始化
  python3 detect_lk_gz.py lk.img --patch-init-fail         # 方案B: 强制初始化失败+释放内存

VCP 修复 (解决 IOMMU protect pgtable 缺失导致的 WDT 重启):
  python3 detect_lk_gz.py lk.img --patch-protpgd            # 推荐: 修复 SMMU 标志, 保留 VCP
  python3 detect_lk_gz.py lk.img --patch-vcp               # 备用: 禁用 VCP

通用:
  python3 detect_lk_gz.py lk.img --dry-run                # 仅显示补丁内容
  python3 detect_lk_gz.py lk.img --restore                # 从备份还原
"""

import struct
import argparse
import shutil
import sys
import os
import re

MTK_HDR_MAGIC = 0x58881688
MTK_HDR_SIZE = 0x200


# ── Helper decoders ──

def sign_ext(val, bits):
    if val & (1 << (bits - 1)):
        return val - (1 << bits)
    return val


def a64_decode_adrp(insn, file_off, base_off):
    if (insn & 0x9F000000) != 0x90000000:
        return None, None
    rd = insn & 0x1F
    immlo = (insn >> 29) & 3
    immhi = (insn >> 5) & 0x7FFFF
    imm = sign_ext((immhi << 2) | immlo, 21)
    pc_page = (file_off - base_off) & ~0xFFF
    return rd, (pc_page + (imm << 12)) & 0xFFFFFFFF


def a64_decode_add_imm(insn):
    if (insn & 0xFFC00000) != 0x91000000:
        return None, None, None
    return insn & 0x1F, (insn >> 5) & 0x1F, (insn >> 10) & 0xFFF


def a64_decode_bl(insn, file_off):
    if (insn & 0xFC000000) != 0x94000000:
        return None
    return file_off + sign_ext(insn & 0x3FFFFFF, 26) * 4


class LKAnalyzer:
    def __init__(self, path):
        self.path = path
        with open(path, 'rb') as f:
            self.data = f.read()
        self.lk_offset = None
        self.lk_size = None
        self.code_end = None
        self.segments = []
        self.arch = None

    def parse_mtk_header(self):
        if len(self.data) < MTK_HDR_SIZE + 4:
            return False
        magic = struct.unpack_from('<I', self.data, 0)[0]
        if magic != MTK_HDR_MAGIC:
            return False
        self.lk_size = struct.unpack_from('<I', self.data, 4)[0]
        name = self.data[8:40].rstrip(b'\x00').decode('ascii', errors='replace')
        if name != 'lk':
            return False
        self.lk_offset = MTK_HDR_SIZE
        if self.lk_offset + self.lk_size > len(self.data):
            self.lk_size = len(self.data) - self.lk_offset

        off = 0
        while off < len(self.data) - 8:
            m = struct.unpack_from('<I', self.data, off)[0]
            if m == MTK_HDR_MAGIC:
                sz = struct.unpack_from('<I', self.data, off + 4)[0]
                n = self.data[off + 8:off + 40].rstrip(b'\x00').decode('ascii', errors='replace')
                self.segments.append((off, n, sz))
                off += MTK_HDR_SIZE + sz
                off = (off + 15) & ~15
            else:
                off += 4
        return True

    def detect_arch(self):
        d = self.data
        off = self.lk_offset
        if off + 32 > len(d):
            self.arch = 'unknown'
            return

        arm_b_count = sum(1 for i in range(8)
                         if (struct.unpack_from('<I', d, off + i * 4)[0] >> 24) == 0xEA)
        if arm_b_count >= 6:
            self.arch = 'arm32'
            return

        first = struct.unpack_from('<I', d, off)[0]
        if (first & 0xFC000000) in (0x14000000, 0x94000000):
            self.arch = 'aarch64'
            return

        self.arch = 'unknown'

    def find_code_boundary(self):
        if self.lk_offset is None:
            return
        end = self.lk_offset + self.lk_size
        scan_start = self.lk_offset + max(int(self.lk_size * 0.4), 0x1000)
        prev_is_code = True

        for off in range(scan_start, end - 0x100, 0x100):
            ic = 0
            sc = 0
            for j in range(off, min(off + 0x100, end), 4):
                if j + 4 > len(self.data):
                    break
                v = struct.unpack_from('<I', self.data, j)[0]

                if self.arch == 'aarch64':
                    if (v & 0xFC000000) in (0x94000000, 0x14000000):
                        ic += 1
                    elif (v & 0x9F000000) == 0x90000000:
                        ic += 1
                    elif v == 0xD65F03C0:
                        ic += 1
                    elif (v & 0xFFC00000) in (0x91000000, 0xF9400000, 0xF9000000,
                                               0xB9400000, 0xB9000000):
                        ic += 1
                else:
                    cond = (v >> 28) & 0xF
                    if cond == 0xE:
                        ic += 1
                    elif (v >> 24) == 0xEB:
                        ic += 1
                    elif v == 0xE12FFF1E:
                        ic += 1

                b = self.data[j:j + 4]
                if all(32 <= c < 127 or c == 0 for c in b) and sum(1 for c in b if 32 <= c < 127) >= 2:
                    sc += 1

            is_code = ic > sc
            if prev_is_code and not is_code:
                self.code_end = off
                return
            prev_is_code = is_code
        self.code_end = end

    # ── String search ──

    def find_string(self, s):
        if isinstance(s, str):
            s = s.encode('ascii')
        pos = self.data.find(s, self.lk_offset, self.lk_offset + self.lk_size)
        return pos if pos >= 0 else None

    def find_gz_strings(self):
        start = self.lk_offset
        end = self.lk_offset + self.lk_size
        results = []
        for m in re.finditer(rb'[\x20-\x7e]{4,}', self.data[start:end]):
            s = m.group()
            sl = s.lower()
            if (b'gz' in sl or b'geniezone' in sl or b'nebula' in sl) and b'gzip' not in sl:
                results.append((m.start() + start, s.decode('ascii', errors='replace')))
        return results

    def find_gz_func_strings(self):
        kws = [b'gz_unmap', b'GZ_UNMAP', b'boottags_gz', b'gz_enable', b'gz_init',
               b'gz_plat', b'gz_info', b'gz_para', b'gz_boot', b'geniezone',
               b'gz-tee', b'gz_check', b'gz_mem', b'gz_load']
        found = {}
        end = self.lk_offset + self.lk_size
        for kw in kws:
            pos = self.data.find(kw, self.lk_offset, end)
            if pos >= 0:
                s_start = pos
                while s_start > self.lk_offset and 32 <= self.data[s_start - 1] < 127:
                    s_start -= 1
                s_end = pos
                while s_end < end and 32 <= self.data[s_end] < 127:
                    s_end += 1
                full = self.data[s_start:s_end].decode('ascii', errors='replace')
                if s_start not in {off for off, _ in found.values()}:
                    found[full] = (s_start, full)
        return found

    def find_gz_boot_tag_hooks(self):
        hooks = {}
        for name in ['pl_boottags_gz_info_hook', 'pl_boottags_gz_plat_hook',
                      'pl_boottags_gz_para_hook']:
            off = self.find_string(name)
            if off is not None:
                hooks[name] = off
        return hooks

    def check_dtb_gz_nodes(self):
        nodes = []
        for seg_off, seg_name, seg_size in self.segments:
            if 'dtb' not in seg_name:
                continue
            start = seg_off + MTK_HDR_SIZE
            end = min(start + seg_size, len(self.data))
            if end - start < 4:
                continue
            if struct.unpack_from('>I', self.data, start)[0] != 0xD00DFEED:
                continue
            for m in re.finditer(rb'[\x20-\x7e]{4,}', self.data[start:end]):
                s = m.group().decode('ascii', errors='replace')
                if ('gz' in s.lower() and 'gzip' not in s.lower()) or 'nebula' in s.lower():
                    nodes.append(s)
            break
        return nodes

    # ────────────────────────────────────────────────────
    #  DTB VCP 节点检测
    # ────────────────────────────────────────────────────

    def _find_all_fdt_blobs(self):
        """扫描整个文件, 找到所有 FDT (Device Tree Blob) 的偏移和大小."""
        FDT_MAGIC = b'\xd0\x0d\xfe\xed'
        blobs = []
        offset = 0
        while offset < len(self.data) - 40:
            pos = self.data.find(FDT_MAGIC, offset)
            if pos == -1:
                break
            if pos + 8 > len(self.data):
                break
            totalsize = struct.unpack('>I', self.data[pos + 4:pos + 8])[0]
            if 0x100 <= totalsize <= 0x200000 and pos + totalsize <= len(self.data):
                version = struct.unpack('>I', self.data[pos + 20:pos + 24])[0]
                if 1 <= version <= 30:
                    blobs.append((pos, totalsize))
                    offset = pos + totalsize
                    continue
            offset = pos + 4
        return blobs

    def _parse_dtb_vcp_nodes(self, dtb_offset, dtb_size):
        """解析单个 DTB, 返回其中所有 vcp-support 属性的信息."""
        d = self.data
        pos = dtb_offset

        off_dt_struct = struct.unpack('>I', d[pos + 8:pos + 12])[0]
        off_dt_strings = struct.unpack('>I', d[pos + 12:pos + 16])[0]
        size_dt_strings = struct.unpack('>I', d[pos + 24:pos + 28])[0]

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
                if prop_name == 'vcp-support' and prop_len == 4 and i + 16 <= len(d):
                    val = struct.unpack('>I', d[i + 12:i + 16])[0]
                    path = '/' + '/'.join(node_stack)
                    results.append({
                        'dtb_offset': dtb_offset,
                        'value_file_offset': i + 12,
                        'path': path,
                        'value': val,
                    })
                i += 12 + ((prop_len + 3) & ~3)
            elif token == 9:  # FDT_END
                break
            else:
                i += 4

        return results

    def find_dtb_vcp_nodes(self):
        """在所有嵌入的 DTB 中查找 VCP 节点, 返回可补丁的列表."""
        all_nodes = []
        for dtb_off, dtb_size in self._find_all_fdt_blobs():
            nodes = self._parse_dtb_vcp_nodes(dtb_off, dtb_size)
            all_nodes.extend(nodes)
        return all_nodes

    # ────────────────────────────────────────────────────
    #  bl2_ext GZ 初始化管线检测 (MT6991+)
    # ────────────────────────────────────────────────────

    def _bl2_find_adrp_ref(self, target_file_off, bl2_off, bl2_size):
        rel = target_file_off - bl2_off
        page = rel & ~0xFFF
        off_in_page = rel & 0xFFF
        scan_limit = bl2_off + min(bl2_size, 0x100000) - 8
        for scan in range(bl2_off, scan_limit, 4):
            insn = struct.unpack_from('<I', self.data, scan)[0]
            rd, adrp_page = a64_decode_adrp(insn, scan, bl2_off)
            if rd is None or adrp_page != page:
                continue
            next_insn = struct.unpack_from('<I', self.data, scan + 4)[0]
            add_rd, add_rn, add_imm = a64_decode_add_imm(next_insn)
            if add_rn == rd and add_imm == off_in_page:
                return scan
        return None

    def _bl2_find_adrp_add_refs_gapped(self, target_file_off, bl2_off, bl2_size,
                                        max_gap=4):
        """查找 ADRP+ADD 引用, 允许中间有 gap 指令 (编译器优化)."""
        rel = target_file_off - bl2_off
        page = rel & ~0xFFF
        off_in_page = rel & 0xFFF
        scan_limit = bl2_off + min(bl2_size, 0x100000) - 4
        results = []
        for scan in range(bl2_off, scan_limit, 4):
            insn = struct.unpack_from('<I', self.data, scan)[0]
            rd, adrp_page = a64_decode_adrp(insn, scan, bl2_off)
            if rd is None or adrp_page != page:
                continue
            for gap in range(1, max_gap + 1):
                add_off = scan + gap * 4
                if add_off + 4 > len(self.data):
                    break
                add_insn = struct.unpack_from('<I', self.data, add_off)[0]
                add_rd, add_rn, add_imm = a64_decode_add_imm(add_insn)
                if add_rn == rd and add_imm == off_in_page:
                    results.append(scan)
                    break
        return results

    def _find_bl2ext_gz_init(self):
        bl2_off = bl2_size = None
        for seg_off, seg_name, seg_size in self.segments:
            if seg_name == 'bl2_ext':
                bl2_off = seg_off + MTK_HDR_SIZE
                bl2_size = seg_size
                break
        if bl2_off is None:
            return None

        d = self.data
        success_off = d.find(b'[GZ_INIT] init success; gz will boot!!',
                             bl2_off, bl2_off + bl2_size)
        failed_off = d.find(b'[GZ_INIT] init failed; gz is disabled from now on',
                            bl2_off, bl2_off + bl2_size)
        if success_off < 0 or failed_off < 0:
            return None

        success_ref = self._bl2_find_adrp_ref(success_off, bl2_off, bl2_size)
        failed_ref = self._bl2_find_adrp_ref(failed_off, bl2_off, bl2_size)
        if success_ref is None or failed_ref is None:
            return None
        if abs(success_ref - failed_ref) > 0x400:
            return None

        init_main = None
        for scan in range(failed_ref - 4, max(bl2_off, failed_ref - 2000), -4):
            insn = struct.unpack_from('<I', d, scan)[0]
            if (insn & 0xFFC07FFF) == 0xA9807BFD:  # STP X29, X30, [SP, #-N]!
                if scan >= bl2_off + 4:
                    prev = struct.unpack_from('<I', d, scan - 4)[0]
                    if prev in (0xD503233F, 0xD503201F):
                        init_main = scan - 4
                        break
                init_main = scan
                break
        if init_main is None:
            return None

        caller_bl = None
        for scan in range(bl2_off, bl2_off + min(bl2_size, 0x100000) - 4, 4):
            if scan == init_main:
                continue
            insn = struct.unpack_from('<I', d, scan)[0]
            bl_target = a64_decode_bl(insn, scan)
            if bl_target == init_main:
                caller_bl = scan
                break
        if caller_bl is None:
            return None

        validate_func = validate_bl = tbz_off = None
        for scan in range(caller_bl - 4, max(bl2_off, caller_bl - 48), -4):
            insn = struct.unpack_from('<I', d, scan)[0]
            is_tbz = (insn & 0x7F80001F) == 0x36000000
            is_cbz = (insn & 0xFF00001F) == 0x34000000
            if not is_tbz and not is_cbz:
                continue
            tbz_off = scan
            if scan < bl2_off + 4:
                break
            prev = struct.unpack_from('<I', d, scan - 4)[0]
            bl_t = a64_decode_bl(prev, scan - 4)
            if bl_t is not None and bl2_off <= bl_t < bl2_off + bl2_size:
                validate_bl = scan - 4
                validate_func = bl_t
            break

        validate_patch_off = None
        validate_patch_orig = None
        already_patched_validate = False
        if validate_func is not None:
            for off in range(validate_func, min(validate_func + 40,
                                                bl2_off + bl2_size - 4), 4):
                insn = struct.unpack_from('<I', d, off)[0]
                if insn == 0x52800000:
                    already_patched_validate = True
                    validate_patch_off = off
                    break
                if (insn & 0xFFE0001F) == 0x0A200000:
                    validate_patch_off = off
                    validate_patch_orig = insn
                    break
                if (insn & 0xFFE0001F) == 0x0A000000 and (insn & 0x1F) == 0:
                    validate_patch_off = off
                    validate_patch_orig = insn
                    break

        cleanup_target = None
        env_off = d.find(b'[GZ_INIT] config env not valid',
                         bl2_off, bl2_off + bl2_size)
        if env_off >= 0:
            env_ref = self._bl2_find_adrp_ref(env_off, bl2_off, bl2_size)
            if env_ref is not None and init_main <= env_ref <= init_main + 0x200:
                cleanup_target = env_ref

        init_first_bl = None
        already_patched_init = False
        for off in range(init_main, min(init_main + 48, bl2_off + bl2_size - 4), 4):
            insn = struct.unpack_from('<I', d, off)[0]
            bl_t = a64_decode_bl(insn, off)
            if bl_t is not None:
                init_first_bl = off
                break
            if (insn & 0xFC000000) == 0x14000000:
                b_target = off + sign_ext(insn & 0x3FFFFFF, 26) * 4
                if b_target == cleanup_target:
                    init_first_bl = off
                    already_patched_init = True
                    break

        return {
            'bl2_ext_off': bl2_off,
            'bl2_ext_size': bl2_size,
            'init_main': init_main,
            'caller_bl': caller_bl,
            'validate_func': validate_func,
            'validate_bl': validate_bl,
            'validate_patch_off': validate_patch_off,
            'validate_patch_orig': validate_patch_orig,
            'already_patched_validate': already_patched_validate,
            'init_first_bl': init_first_bl,
            'cleanup_target': cleanup_target,
            'already_patched_init': already_patched_init,
        }

    # ────────────────────────────────────────────────────
    #  bl2_ext SMMU protpgd 标志检测
    # ────────────────────────────────────────────────────

    def _find_bl2ext_protpgd(self):
        """检测 bl2_ext 中的 SMMU protect page table 标志位.

        当 GZ 被跳过时, bl2_ext 可自行创建 protpgd mblock 供 ATF 使用,
        但默认标志位为 1 (假定 GZ 管理 SMMU), 导致 bl2_ext 跳过分配.
        补丁: 将标志位从 1 改为 0, 使 bl2_ext 创建 protpgd → VCP 正常工作.
        """
        bl2_off = bl2_size = None
        for seg_off, seg_name, seg_size in self.segments:
            if seg_name == 'bl2_ext':
                bl2_off = seg_off + MTK_HDR_SIZE
                bl2_size = seg_size
                break
        if bl2_off is None:
            return None

        d = self.data

        str_off = d.find(b'platform_mtksmmu_protpgd', bl2_off,
                         bl2_off + bl2_size)
        if str_off < 0:
            return None

        refs = self._bl2_find_adrp_add_refs_gapped(
            str_off, bl2_off, bl2_size)
        if not refs:
            return None

        first_ref = min(refs)

        prologue_off = None
        for scan in range(first_ref - 4, max(bl2_off, first_ref - 200), -4):
            insn = struct.unpack_from('<I', d, scan)[0]
            if (insn & 0xFFC003FF) == 0xD10003FF:
                prologue_off = scan
                break
            if (insn & 0xFFC07FFF) == 0xA9807BFD:
                prologue_off = scan
                break
        if prologue_off is None:
            return None

        guard_bl_off = None
        for scan in range(prologue_off, min(prologue_off + 48, first_ref), 4):
            insn = struct.unpack_from('<I', d, scan)[0]
            bl_target = a64_decode_bl(insn, scan)
            if bl_target is not None and bl2_off <= bl_target < bl2_off + bl2_size:
                guard_bl_off = scan
                break
        if guard_bl_off is None:
            return None

        guard_func_off = a64_decode_bl(
            struct.unpack_from('<I', d, guard_bl_off)[0], guard_bl_off)

        guard_insns = []
        for i in range(8):
            off = guard_func_off + i * 4
            if off + 4 > len(d):
                break
            guard_insns.append(struct.unpack_from('<I', d, off)[0])
            if guard_insns[-1] == 0xD65F03C0:
                break

        if len(guard_insns) < 4 or guard_insns[-1] != 0xD65F03C0:
            return None

        adrp_rd, adrp_page = a64_decode_adrp(
            guard_insns[0], guard_func_off, bl2_off)
        if adrp_rd is None:
            return None

        ldr_insn = guard_insns[1]
        if (ldr_insn & 0xBFC00000) != 0xB9400000:
            return None
        ldr_rn = (ldr_insn >> 5) & 0x1F
        if ldr_rn != adrp_rd:
            return None
        ldr_imm12 = (ldr_insn >> 10) & 0xFFF
        ldr_sf = (ldr_insn >> 30) & 1
        ldr_scale = 8 if ldr_sf else 4
        ldr_offset = ldr_imm12 * ldr_scale

        flag_code_off = adrp_page + ldr_offset
        flag_file_off = bl2_off + flag_code_off
        if flag_file_off + 4 > len(d):
            return None

        flag_value = struct.unpack_from('<I', d, flag_file_off)[0]

        has_mvn = any(
            (g & 0xFFE0FFE0) == 0x2A2003E0 for g in guard_insns[2:-1])
        has_and1 = any(
            (g & 0xFFFFFC00) == 0x12000000 for g in guard_insns[2:-1])
        if not has_mvn or not has_and1:
            return None

        return {
            'protpgd_string_off': str_off,
            'code_refs': refs,
            'func_off': prologue_off,
            'guard_func_off': guard_func_off,
            'flag_file_off': flag_file_off,
            'flag_code_off': flag_code_off,
            'flag_value': flag_value,
            'already_patched': flag_value == 0,
        }

    # ────────────────────────────────────────────────────
    #  Main analysis
    # ────────────────────────────────────────────────────

    def analyze(self):
        r = {
            'file': os.path.basename(self.path),
            'file_size': len(self.data),
            'lk_valid': False,
        }

        if not self.parse_mtk_header():
            r['error'] = '非有效 MTK LK 镜像 (头部解析失败)'
            return r

        r['lk_valid'] = True
        r['lk_size'] = self.lk_size
        r['segments'] = [(n, s) for _, n, s in self.segments]

        self.detect_arch()
        r['arch'] = self.arch

        self.find_code_boundary()
        r['code_size'] = (self.code_end or self.lk_offset) - self.lk_offset

        gz_func = self.find_gz_func_strings()
        r['has_gz_code'] = len(gz_func) > 0
        r['gz_func_strings'] = gz_func

        gz_strs = self.find_gz_strings()
        r['gz_strings'] = gz_strs
        r['has_gz'] = len(gz_strs) > 0

        r['boot_tag_hooks'] = self.find_gz_boot_tag_hooks()
        r['dtb_gz_nodes'] = self.check_dtb_gz_nodes()

        gz_parts = []
        for off, s in gz_strs:
            if s in ('gz', 'gz1', 'gz2', 'gz_a', 'gz_b'):
                gz_parts.append(s)
        r['gz_part_names'] = gz_parts

        # bl2_ext GZ 初始化管线
        r['gz_init_v2'] = None
        if self.arch == 'aarch64':
            v2 = self._find_bl2ext_gz_init()
            if v2 is not None:
                r['gz_init_v2'] = v2

        # DTB VCP 节点
        r['vcp_nodes'] = self.find_dtb_vcp_nodes()

        # bl2_ext SMMU protpgd 标志
        r['protpgd_info'] = None
        if self.arch == 'aarch64':
            protpgd = self._find_bl2ext_protpgd()
            if protpgd is not None:
                r['protpgd_info'] = protpgd

        return r


# ── Output ──

def format_size(n):
    if n >= 1024 * 1024:
        return f"{n / 1024 / 1024:.1f} MB"
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} B"


ARCH_NAMES = {'aarch64': 'AArch64', 'arm32': 'ARM32', 'unknown': '未知'}


def print_results(r):
    print(f"\n{'=' * 60}")
    print(f"  {r['file']}")
    print(f"{'=' * 60}")
    print(f"\n文件大小: {r['file_size']:,} bytes ({format_size(r['file_size'])})")

    if not r['lk_valid']:
        print(f"\n  错误: {r.get('error', '解析失败')}")
        return

    arch = ARCH_NAMES.get(r.get('arch', ''), r.get('arch', ''))
    print(f"LK 代码: {format_size(r.get('code_size', 0))}"
          f"  只读数据: {format_size(r['lk_size'] - r.get('code_size', 0))}"
          f"  架构: {arch}")

    segs = r.get('segments', [])
    if segs:
        seg_names = [f"{n}({format_size(s)})" for n, s in segs if n not in ('cert1', 'cert2')]
        print(f"镜像段: {', '.join(seg_names)}")

    # GZ functional strings
    gz_func = r.get('gz_func_strings', {})
    if gz_func:
        print(f"\n  GZ 功能字符串: {len(gz_func)} 个")
        for kw, (off, s) in gz_func.items():
            print(f"    0x{off:06X}: \"{s}\"")

    if not gz_func:
        gz_strs = r.get('gz_strings', [])
        key_kws = ['gz_unmap', 'GZ_UNMAP', 'boottags_gz', 'gz-tee', 'gz-main',
                   'trusty-gz', 'nebula']
        key_strs = [(o, s) for o, s in gz_strs if any(k in s for k in key_kws)]
        if key_strs:
            print(f"\n  GZ 关键字符串: {len(key_strs)} 个")
            for off, s in key_strs:
                print(f"    0x{off:06X}: \"{s}\"")

    gz_parts = r.get('gz_part_names', [])
    if gz_parts and not gz_func:
        print(f"\n  GZ 分区名引用: {', '.join(gz_parts)} (仅分区表条目, 非 GZ 功能代码)")

    hooks = r.get('boot_tag_hooks', {})
    if hooks:
        print(f"\n  Boot Tag 钩子: {len(hooks)} 个")
        for name in hooks:
            print(f"    {name.replace('pl_boottags_', '')}")

    dtb = r.get('dtb_gz_nodes', [])
    dtb_key = [n for n in dtb if any(k in n for k in ['trusty-gz', 'nebula', 'gz-main'])]
    if dtb_key:
        print(f"  DTB GZ 节点: {', '.join(dtb_key[:6])}")

    # ── VCP 节点 ──
    vcp_nodes = r.get('vcp_nodes', [])
    if vcp_nodes:
        print(f"\n  VCP 节点 (DTB): {len(vcp_nodes)} 个")
        patchable_count = 0
        for node in vcp_nodes:
            marker = ''
            if node['value'] == 1:
                marker = '  <- 主 VCP, 可禁用'
                patchable_count += 1
            elif node['value'] == 0:
                marker = '  <- 已禁用'
            print(f"    DTB@0x{node['dtb_offset']:06X} {node['path']}:"
                  f" vcp-support={node['value']}{marker}")
        if patchable_count > 0:
            print(f"\n  可禁用 VCP 节点: {patchable_count} 个 (vcp-support=1 -> 0)")

    v2 = r.get('gz_init_v2')
    print(f"\n{'=' * 60}")

    # ── bl2_ext GZ 初始化管线 ──
    if v2 is not None:
        print(f"  GZ 类型: bl2_ext 初始化管线")
        print(f"  bl2_ext 代码: 0x{v2['bl2_ext_off']:06X}"
              f"  大小: {format_size(v2['bl2_ext_size'])}")
        print(f"  gz_init_main: 0x{v2['init_main']:06X}")
        if v2.get('validate_func') is not None:
            print(f"  gz_config_validate: 0x{v2['validate_func']:06X}")
        if v2.get('cleanup_target') is not None:
            print(f"  错误清理路径: 0x{v2['cleanup_target']:06X}"
                  f" (含 gz_mblock_free_all)")

        pa = v2.get('already_patched_validate')
        pb = v2.get('already_patched_init')
        if pa:
            print(f"\n  状态: 方案 A 已应用 (gz_config_validate 已补丁)")
        if pb:
            print(f"\n  状态: 方案 B 已应用 (gz_init_main 已补丁)")

        script = os.path.basename(sys.argv[0])
        has_a = v2.get('validate_patch_off') is not None and not pa
        has_b = (v2.get('init_first_bl') is not None
                 and v2.get('cleanup_target') is not None and not pb)
        if has_a or has_b:
            print()
        if has_a:
            print(f"  方案 A: gz_config_validate -> 返回 0 (跳过 GZ 初始化)")
            print(f"    python3 {script} {r['file']} --patch-validate")
        if has_b:
            print(f"  方案 B: gz_init_main -> 强制失败 (触发内存释放清理)")
            print(f"    python3 {script} {r['file']} --patch-init-fail")
        if has_a and has_b:
            print(f"  A+B:    python3 {script} {r['file']}"
                  f" --patch-validate --patch-init-fail")
    elif r.get('has_gz_code'):
        print(f"  GZ 功能代码存在, 但未找到 bl2_ext 初始化管线")
        print(f"  GZ 禁用应在 preloader 层面处理 (GPT 方案)")
    elif r.get('has_gz'):
        print(f"  此 LK 不包含 GZ 功能代码 (仅有分区名/DTB 节点)")
    else:
        print(f"  此 LK 未包含 GenieZone 相关内容")

    # ── SMMU protpgd 标志 ──
    ppgd = r.get('protpgd_info')
    if ppgd is not None:
        print(f"\n  SMMU Protect Page Table (protpgd):")
        print(f"    标志位偏移: 0x{ppgd['flag_file_off']:06X}"
              f"  当前值: {ppgd['flag_value']}")
        if ppgd['already_patched']:
            print(f"    状态: 已补丁 (bl2_ext 将创建 protpgd mblock)")
        else:
            print(f"    含义: 值=1 -> bl2_ext 跳过 SMMU 初始化 (假定 GZ 管理)")
            print(f"          跳过 GZ 时 protpgd 未创建 -> VCP SMC 失败 -> WDT 重启")

    # ── VCP 解决方案 ──
    vcp_patchable = [n for n in vcp_nodes if n['value'] == 1]
    if vcp_patchable or ppgd:
        script = os.path.basename(sys.argv[0])
        print(f"\n  VCP 解决方案:")
        if ppgd and not ppgd['already_patched']:
            print(f"    推荐: --patch-protpgd  修复 SMMU 标志"
                  f" (保留 VCP, 视频编解码正常)")
            print(f"      python3 {script} {r['file']} --patch-protpgd")
        if vcp_patchable:
            label = "备用" if (ppgd and not ppgd['already_patched']) else "方案"
            print(f"    {label}: --patch-vcp      禁用 VCP"
                  f" (视频硬件编解码不可用)")
            print(f"      python3 {script} {r['file']} --patch-vcp")

    print()


def do_patch(analyzer, results, output_path,
             patch_validate=False, patch_init_fail=False, patch_vcp=False,
             patch_protpgd=False, dry_run=False):
    patched = bytearray(analyzer.data)
    any_applied = False

    # ── bl2_ext 补丁 ──

    v2 = results.get('gz_init_v2')

    if patch_validate:
        if v2 is None:
            print("错误: 未找到 bl2_ext GZ 初始化管线, 无法应用方案 A")
        elif v2.get('already_patched_validate'):
            print("方案 A: gz_config_validate 已补丁, 跳过")
        elif v2.get('validate_patch_off') is None:
            print("错误: 未定位 gz_config_validate 返回值指令, 无法应用方案 A")
        else:
            off = v2['validate_patch_off']
            orig = struct.unpack_from('<I', analyzer.data, off)[0]
            new_insn = 0x52800000  # MOV W0, #0

            print(f"\n方案 A -- gz_config_validate 补丁 (bl2_ext 段):")
            print(f"  目标: 0x{off:06X}")
            print(f"  原始: {orig:08X}  (返回值取决于配置字节)")
            print(f"  补丁: {new_insn:08X}  ; MOV W0, #0")
            print(f"  效果: gz_config_validate 始终返回 0 -> 跳过 GZ 初始化")

            struct.pack_into('<I', patched, off, new_insn)
            any_applied = True

    if patch_init_fail:
        if v2 is None:
            print("错误: 未找到 bl2_ext GZ 初始化管线, 无法应用方案 B")
        elif v2.get('already_patched_init'):
            print("方案 B: gz_init_main 已补丁, 跳过")
        elif v2.get('init_first_bl') is None or v2.get('cleanup_target') is None:
            print("错误: 未定位 gz_init_main 补丁点或清理路径, 无法应用方案 B")
        else:
            bl_off = v2['init_first_bl']
            target = v2['cleanup_target']
            orig = struct.unpack_from('<I', analyzer.data, bl_off)[0]
            delta = (target - bl_off) // 4
            new_insn = 0x14000000 | (delta & 0x03FFFFFF)  # B <cleanup>

            print(f"\n方案 B -- gz_init_main 强制失败 (bl2_ext 段):")
            print(f"  目标: 0x{bl_off:06X}")
            print(f"  原始: {orig:08X}  (BL gz_config_env_get)")
            print(f"  补丁: {new_insn:08X}  ; B 0x{target:06X}")
            print(f"  效果: gz_init_main 直接跳转到错误清理路径")
            print(f"         -> gz_mblock_free_all 释放 GZ 内存")
            print(f"         -> 打印 \"init failed; gz is disabled from now on\"")

            struct.pack_into('<I', patched, bl_off, new_insn)
            any_applied = True

    # ── SMMU protpgd 标志补丁 ──

    if patch_protpgd:
        ppgd = results.get('protpgd_info')
        if ppgd is None:
            print("错误: 未在 bl2_ext 中找到 SMMU protpgd 标志, 无法应用")
        elif ppgd['already_patched']:
            print("protpgd: 标志已为 0, 跳过")
        else:
            off = ppgd['flag_file_off']
            old_val = ppgd['flag_value']

            print(f"\nSMMU protpgd 标志补丁 (bl2_ext 段):")
            print(f"  目标: 0x{off:06X}")
            print(f"  原始: {old_val:08X}  (bl2_ext 跳过 SMMU 初始化)")
            print(f"  补丁: 00000000  (bl2_ext 创建 protpgd mblock)")
            print(f"  效果: mtk_smmu_bl2_ext_init 分配 2MB protpgd 内存块")
            print(f"         ATF mblock_query 成功 -> IOMMU protect pgtable 正常")
            print(f"         VCP SMC 初始化成功 -> 视频硬件编解码正常工作")

            struct.pack_into('<I', patched, off, 0)
            any_applied = True

    # ── VCP 禁用补丁 ──

    if patch_vcp:
        vcp_nodes = results.get('vcp_nodes', [])
        vcp_targets = [n for n in vcp_nodes if n['value'] == 1]
        if not vcp_targets:
            already_disabled = [n for n in vcp_nodes if n['value'] == 0]
            if already_disabled:
                print("VCP: 主 VCP 节点已禁用 (vcp-support=0), 跳过")
            else:
                print("错误: 未在 DTB 中找到 vcp-support=1 的主 VCP 节点")
        else:
            print(f"\nVCP 禁用补丁:")
            print(f"  效果: LK 跳过 VCP 固件加载 (app_load_vcp 返回 NO_ERROR)")
            print(f"         内核 VCP 驱动不 probe, 不发起 vcp_smc_vcp_init SMC")
            print(f"         避免 IOMMU protect pgtable 缺失导致的 WDT 超时重启")
            print(f"         (视频硬件编解码可能不可用)\n")
            for node in vcp_targets:
                off = node['value_file_offset']
                old_bytes = analyzer.data[off:off + 4]
                print(f"  DTB@0x{node['dtb_offset']:06X} {node['path']}:")
                print(f"    偏移: 0x{off:06X}")
                print(f"    原始: {old_bytes.hex()}  (vcp-support=1)")
                print(f"    补丁: 00000000  (vcp-support=0)")
                struct.pack_into('>I', patched, off, 0)
                any_applied = True

    if not any_applied:
        return False

    if dry_run:
        print(f"\n[DRY RUN] 以上为补丁预览, 未修改任何文件")
        return True

    diff_count = sum(1 for a, b in zip(analyzer.data, patched) if a != b)
    try:
        with open(output_path, 'wb') as f:
            f.write(patched)
    except OSError as e:
        print(f"\n错误: 无法写入文件: {e}")
        return False

    print(f"\n{'=' * 50}")
    print(f"完成! 共修改 {diff_count} 字节")
    print(f"输出文件: {output_path}")
    print(f"{'=' * 50}")
    return True


def main():
    parser = argparse.ArgumentParser(
        description='检测并修补 MTK LK 中的 GenieZone / VCP',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
GZ 初始化管线 (bl2_ext):
  --patch-validate    方案 A: gz_config_validate 返回 0, 跳过 GZ 初始化
  --patch-init-fail   方案 B: gz_init_main 强制失败, 触发内存释放清理

VCP 修复 (跳过 GZ 后保持 VCP/视频编解码正常):
  --patch-protpgd     修复 SMMU protpgd 标志 (推荐, 保留 VCP 功能)
  --patch-vcp         禁用 VCP (备用, 视频硬件编解码不可用)

先运行不带参数的分析, 脚本会自动检测并显示可用方案。
配合已解锁的 bootloader 或签名绕过工具使用。
""")
    parser.add_argument('input', help='LK 镜像文件 (lk.img)')
    parser.add_argument('-o', '--output', help='输出文件路径')
    parser.add_argument('--patch-validate', action='store_true',
                        help='方案 A: 跳过 GZ 初始化')
    parser.add_argument('--patch-init-fail', action='store_true',
                        help='方案 B: 强制 GZ 初始化失败 + 释放内存')
    parser.add_argument('--patch-protpgd', action='store_true',
                        help='修复 SMMU protpgd 标志 (保留 VCP 功能)')
    parser.add_argument('--patch-vcp', action='store_true',
                        help='禁用 VCP (DTB vcp-support=1 -> 0)')
    parser.add_argument('--dry-run', action='store_true', help='仅预览补丁, 不修改')
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

    analyzer = LKAnalyzer(args.input)
    results = analyzer.analyze()
    print_results(results)

    want_patch = (args.patch_validate or args.patch_init_fail
                  or args.patch_vcp or args.patch_protpgd)
    if want_patch or args.dry_run:
        v2 = results.get('gz_init_v2')
        ppgd = results.get('protpgd_info')

        if args.dry_run and not want_patch:
            pv = v2 is not None and not v2.get('already_patched_validate')
            pi = v2 is not None and not v2.get('already_patched_init')
            pvcp = any(n['value'] == 1 for n in results.get('vcp_nodes', []))
            pprot = ppgd is not None and not ppgd.get('already_patched')
        else:
            pv = args.patch_validate
            pi = args.patch_init_fail
            pvcp = args.patch_vcp
            pprot = args.patch_protpgd

        can_new = v2 is not None

        if pv and not can_new:
            print("错误: 未找到 bl2_ext GZ 初始化管线 (方案 A)")
        if pi and not can_new:
            print("错误: 未找到 bl2_ext GZ 初始化管线 (方案 B)")
        if pvcp and not any(n['value'] == 1 for n in results.get('vcp_nodes', [])):
            print("错误: 未在 DTB 中找到可禁用的 VCP 节点")
        if not can_new and not pvcp and not (pprot and ppgd) and not args.dry_run:
            sys.exit(1)

        if not args.dry_run and not os.path.isfile(backup_path):
            shutil.copy2(args.input, backup_path)
            print(f"已备份原始文件到: {backup_path}")

        ok = do_patch(analyzer, results, output_path,
                      patch_validate=pv, patch_init_fail=pi, patch_vcp=pvcp,
                      patch_protpgd=pprot, dry_run=args.dry_run)
        if not ok and not args.dry_run:
            sys.exit(1)

        if ok and not args.dry_run:
            print(f"\n还原方法:")
            print(f"  python3 {os.path.basename(sys.argv[0])} {args.input} --restore")


if __name__ == '__main__':
    main()
