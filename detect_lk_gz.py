#!/usr/bin/env python3
"""
detect_lk_gz.py - 检测并修补 MediaTek LK 中的 GenieZone 内存释放逻辑

分析 LK (Little Kernel) 固件:
  1. 解析 MTK 镜像头, 提取 LK 代码段及 bl2_ext 段
  2. 检测 gz_unmap 检查函数 (旧式, 如 MT6895) 或 GZ 初始化管线 (新式, 如 MT6991)
  3. 识别 GZ boot tag 钩子和 DTB 节点
  4. 提供补丁: 禁用 GenieZone 并释放其占用内存

支持架构: AArch64, ARM32

旧式 (gz_unmap_check, 如 MT6833/MT6895):
  python3 detect_lk_gz.py lk.img --patch                  # 方案A: 补丁函数
  python3 detect_lk_gz.py lk.img --patch-default           # 方案B: 改默认值

新式 (bl2_ext GZ 初始化管线, 如 MT6991):
  python3 detect_lk_gz.py lk.img --patch-validate          # 方案A: 跳过GZ初始化
  python3 detect_lk_gz.py lk.img --patch-init-fail         # 方案B: 强制初始化失败+释放内存

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


# AArch64 decoders

def a64_decode_adrp(insn, file_off, lk_offset):
    if (insn & 0x9F000000) != 0x90000000:
        return None, None
    rd = insn & 0x1F
    immlo = (insn >> 29) & 3
    immhi = (insn >> 5) & 0x7FFFF
    imm = sign_ext((immhi << 2) | immlo, 21)
    pc_page = (file_off - lk_offset) & ~0xFFF
    return rd, (pc_page + (imm << 12)) & 0xFFFFFFFF


def a64_decode_add_imm(insn):
    if (insn & 0xFFC00000) != 0x91000000:
        return None, None, None
    return insn & 0x1F, (insn >> 5) & 0x1F, (insn >> 10) & 0xFFF


def a64_decode_bl(insn, file_off):
    if (insn & 0xFC000000) != 0x94000000:
        return None
    return file_off + sign_ext(insn & 0x3FFFFFF, 26) * 4


# ARM32 decoders

def arm32_decode_bl(insn, file_off):
    if (insn >> 24) != 0xEB:
        return None
    return file_off + 8 + sign_ext(insn & 0xFFFFFF, 24) * 4


def arm32_decode_ldr_pc(insn, file_off):
    """Decode LDR Rd, [PC, #+/-off]. Returns (Rd, literal_pool_file_off) or (None, None)."""
    if (insn & 0x0F7F0000) != 0x051F0000:
        return None, None
    rd = (insn >> 12) & 0xF
    off12 = insn & 0xFFF
    if (insn >> 23) & 1:
        target = file_off + 8 + off12
    else:
        target = file_off + 8 - off12
    return rd, target


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
        self.arm32_base = None

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

        # ARM32 exception vector table: 6+ out of first 8 words are B (0xEA??????)
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

    # ── String search (architecture-independent) ──

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
        """Search for GZ functional strings (not partition names, not DTB)."""
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
    #  AArch64-specific detection
    # ────────────────────────────────────────────────────

    def _a64_find_string_ref(self, string_file_off):
        if self.code_end is None:
            return []
        str_code_off = string_file_off - self.lk_offset
        target_page = str_code_off & ~0xFFF
        target_pageoff = str_code_off & 0xFFF
        refs = []
        for i in range(self.lk_offset, self.code_end - 8, 4):
            insn = struct.unpack_from('<I', self.data, i)[0]
            rd, page = a64_decode_adrp(insn, i, self.lk_offset)
            if rd is None or page != target_page:
                continue
            for j in range(i + 4, min(i + 20, self.code_end), 4):
                insn2 = struct.unpack_from('<I', self.data, j)[0]
                rd2, rn2, imm12 = a64_decode_add_imm(insn2)
                if rd2 is not None and rn2 == rd and imm12 == target_pageoff:
                    refs.append(i)
                    break
                if (insn2 & 0x9F000000) == 0x90000000:
                    break
        return refs

    def _a64_match_check_pattern(self, func_off):
        d = self.data
        if func_off + 20 > len(d):
            return None

        # Pattern A: ADRP + LDR W + MVN + AND #1 + RET
        insns = [struct.unpack_from('<I', d, func_off + k * 4)[0] for k in range(5)]
        rd0, page0 = a64_decode_adrp(insns[0], func_off, self.lk_offset)
        if rd0 is not None and (insns[1] & 0xFFC00000) == 0xB9400000:
            ldr_rn = (insns[1] >> 5) & 0x1F
            ldr_rt = insns[1] & 0x1F
            ldr_imm = ((insns[1] >> 10) & 0xFFF) * 4
            if ldr_rn == rd0 and (insns[2] & 0xFFE003E0) == 0x2A2003E0:
                mvn_rm = (insns[2] >> 16) & 0x1F
                mvn_rd = insns[2] & 0x1F
                if mvn_rm == ldr_rt:
                    and_rd = insns[3] & 0x1F
                    and_rn = (insns[3] >> 5) & 0x1F
                    if and_rd == 0 and and_rn == mvn_rd and (insns[3] & 0xFFE00000) == 0x12000000:
                        if insns[4] == 0xD65F03C0:
                            return {
                                'pattern': 'A', 'desc': 'ADRP+LDR+MVN+AND#1+RET',
                                'func_off': func_off, 'func_size': 20,
                                'global_code_off': page0 + ldr_imm,
                                'logic': 'return (~gz_enabled) & 1',
                            }

        # Pattern B: ADRP + LDR + EOR #1 + RET (4 insns)
        if func_off + 16 <= len(d):
            insns = [struct.unpack_from('<I', d, func_off + k * 4)[0] for k in range(4)]
            rd0, page0 = a64_decode_adrp(insns[0], func_off, self.lk_offset)
            if rd0 is not None and (insns[1] & 0xFFC00000) == 0xB9400000:
                ldr_rn = (insns[1] >> 5) & 0x1F
                ldr_rt = insns[1] & 0x1F
                ldr_imm = ((insns[1] >> 10) & 0xFFF) * 4
                if ldr_rn == rd0 and (insns[2] & 0xFFE00000) == 0x52000000:
                    if (insns[2] & 0x1F) == 0 and ((insns[2] >> 5) & 0x1F) == ldr_rt:
                        if insns[3] == 0xD65F03C0:
                            return {
                                'pattern': 'B', 'desc': 'ADRP+LDR+EOR#1+RET',
                                'func_off': func_off, 'func_size': 16,
                                'global_code_off': page0 + ldr_imm,
                                'logic': 'return gz_enabled ^ 1',
                            }

        # Pattern C: ADRP + LDR + CMP #0 + CSET EQ + RET
        if func_off + 20 <= len(d):
            insns = [struct.unpack_from('<I', d, func_off + k * 4)[0] for k in range(5)]
            rd0, page0 = a64_decode_adrp(insns[0], func_off, self.lk_offset)
            if rd0 is not None and (insns[1] & 0xFFC00000) == 0xB9400000:
                ldr_rn = (insns[1] >> 5) & 0x1F
                ldr_rt = insns[1] & 0x1F
                ldr_imm = ((insns[1] >> 10) & 0xFFF) * 4
                if ldr_rn == rd0:
                    if (insns[2] & 0xFFC003FF) == 0x7100001F:
                        cmp_rn = (insns[2] >> 5) & 0x1F
                        if cmp_rn == ldr_rt and ((insns[2] >> 10) & 0xFFF) == 0:
                            if insns[3] == 0x1A9F17E0 and insns[4] == 0xD65F03C0:
                                return {
                                    'pattern': 'C', 'desc': 'ADRP+LDR+CMP#0+CSET_EQ+RET',
                                    'func_off': func_off, 'func_size': 20,
                                    'global_code_off': page0 + ldr_imm,
                                    'logic': 'return (gz_enabled == 0) ? 1 : 0',
                                }
        return None

    def _a64_check_already_patched(self, off):
        if off + 8 > len(self.data):
            return False
        return (struct.unpack_from('<I', self.data, off)[0] == 0x52800020 and
                struct.unpack_from('<I', self.data, off + 4)[0] == 0xD65F03C0)

    def _a64_find_callers(self, func_off):
        callers = []
        limit = self.code_end or (self.lk_offset + self.lk_size)
        for i in range(self.lk_offset, limit - 4, 4):
            if a64_decode_bl(struct.unpack_from('<I', self.data, i)[0], i) == func_off:
                callers.append(i)
        return callers

    def _a64_find_cbz_after(self, bl_off):
        for j in range(bl_off + 4, min(bl_off + 20, self.lk_offset + self.lk_size), 4):
            insn = struct.unpack_from('<I', self.data, j)[0]
            if (insn & 0xFF00001F) == 0x34000000:
                return j, 'CBZ'
            if (insn & 0xFF00001F) == 0x35000000:
                return j, 'CBNZ'
        return None, None

    def _a64_find_gz_unmap_via_string(self):
        for name in ['gz_unmap2()', 'gz_unmap()']:
            str_off = self.find_string(name)
            if str_off is None:
                continue
            refs = self._a64_find_string_ref(str_off)
            for ref in refs:
                for scan in range(ref - 4, max(ref - 160, self.lk_offset + 4), -4):
                    insn = struct.unpack_from('<I', self.data, scan)[0]
                    is_cbz = (insn & 0xFF00001F) == 0x34000000
                    is_cbnz = (insn & 0xFF00001F) == 0x35000000
                    if not is_cbz and not is_cbnz:
                        continue
                    prev = struct.unpack_from('<I', self.data, scan - 4)[0]
                    bl_target = a64_decode_bl(prev, scan - 4)
                    if bl_target is None or not (self.lk_offset <= bl_target < self.code_end):
                        continue
                    if self._a64_check_already_patched(bl_target):
                        return {
                            'method': 'string', 'string': name,
                            'check_func': bl_target, 'bl_off': scan - 4,
                            'cbz_off': scan, 'cbz_type': 'CBZ' if is_cbz else 'CBNZ',
                            'already_patched': True, 'pattern': None,
                        }
                    pat = self._a64_match_check_pattern(bl_target)
                    if pat is not None:
                        return {
                            'method': 'string', 'string': name,
                            'check_func': bl_target, 'bl_off': scan - 4,
                            'cbz_off': scan, 'cbz_type': 'CBZ' if is_cbz else 'CBNZ',
                            'already_patched': False, **pat,
                        }
                    break
        return None

    def _a64_find_gz_unmap_via_pattern(self):
        limit = self.code_end or (self.lk_offset + self.lk_size)
        for i in range(self.lk_offset, limit - 20, 4):
            if self._a64_check_already_patched(i):
                for c in self._a64_find_callers(i):
                    cbz, ctype = self._a64_find_cbz_after(c)
                    if cbz is not None:
                        return {
                            'method': 'pattern', 'check_func': i, 'bl_off': c,
                            'cbz_off': cbz, 'cbz_type': ctype,
                            'already_patched': True, 'pattern': None,
                        }
                continue
            pat = self._a64_match_check_pattern(i)
            if pat is None:
                continue
            for c in self._a64_find_callers(i):
                cbz, ctype = self._a64_find_cbz_after(c)
                if cbz is not None:
                    return {
                        'method': 'pattern', 'check_func': i, 'bl_off': c,
                        'cbz_off': cbz, 'cbz_type': ctype, 'already_patched': False, **pat,
                    }
        return None

    def _a64_find_el2_access(self):
        accesses = []
        limit = self.code_end or (self.lk_offset + self.lk_size)
        for i in range(self.lk_offset, limit - 4, 4):
            insn = struct.unpack_from('<I', self.data, i)[0]
            if (insn & 0xFFFFFFE0) == 0xD51C1100:
                accesses.append((i, f"MSR HCR_EL2, X{insn & 0x1F}"))
            elif (insn & 0xFFFFFFE0) == 0xD5384240:
                accesses.append((i, f"MRS X{insn & 0x1F}, CurrentEL"))
        return accesses

    # ────────────────────────────────────────────────────
    #  ARM32-specific detection
    # ────────────────────────────────────────────────────

    def _arm32_detect_base(self):
        """Auto-detect ARM32 load base from literal pool references to known strings."""
        test_strings = [b'platform_init()', b'platform_init', b'[PROFILE]']
        d = self.data
        code_limit = self.code_end or (self.lk_offset + self.lk_size)

        for test_str in test_strings:
            str_off = d.find(test_str, self.lk_offset, self.lk_offset + self.lk_size)
            if str_off < 0:
                continue
            str_code_off = str_off - self.lk_offset

            for i in range(self.lk_offset, code_limit - 4, 4):
                insn = struct.unpack_from('<I', d, i)[0]
                rd, lit_off = arm32_decode_ldr_pc(insn, i)
                if rd is None:
                    continue
                if lit_off < self.lk_offset or lit_off + 4 > len(d):
                    continue
                v = struct.unpack_from('<I', d, lit_off)[0]
                base = v - str_code_off
                if base < 0x10000 or base > 0xFFFF0000:
                    continue
                if base & 0xFFF:
                    continue
                # Verify: at least 2 other literal pool entries are consistent
                hits = 0
                for test2 in test_strings:
                    off2 = d.find(test2, self.lk_offset, self.lk_offset + self.lk_size)
                    if off2 < 0 or off2 == str_off:
                        continue
                    expected = base + (off2 - self.lk_offset)
                    # Search for this value in a reasonable range of literal pool
                    for lp in range(self.lk_offset, code_limit, 4):
                        if struct.unpack_from('<I', d, lp)[0] == expected:
                            hits += 1
                            break
                if hits >= 1:
                    self.arm32_base = base
                    return base
        return None

    def _arm32_find_string_ref(self, string_file_off):
        """Find ARM32 LDR [PC, #off] references to a string via literal pool."""
        if self.arm32_base is None:
            return []
        target_addr = self.arm32_base + (string_file_off - self.lk_offset)
        d = self.data
        code_limit = self.code_end or (self.lk_offset + self.lk_size)
        refs = []

        # Find literal pool entries containing the target address
        lit_offsets = []
        for lp in range(self.lk_offset, code_limit, 4):
            if struct.unpack_from('<I', d, lp)[0] == target_addr:
                lit_offsets.append(lp)

        # Find LDR [PC, #off] instructions that point to these literal pool entries
        for i in range(self.lk_offset, code_limit - 4, 4):
            insn = struct.unpack_from('<I', d, i)[0]
            rd, lit_off = arm32_decode_ldr_pc(insn, i)
            if rd is not None and lit_off in lit_offsets:
                refs.append(i)
        return refs

    def _arm32_match_check_pattern(self, func_off):
        """
        ARM32 gz_unmap check patterns:
          A: LDR Rn,[PC,#off] + LDR Rm,[Rn] + MVN Rd,Rm + AND R0,Rd,#1 + BX LR
          B: LDR Rn,[PC,#off] + LDR R0,[Rn] + EOR R0,R0,#1 + BX LR
          C: LDR Rn,[PC,#off] + LDR R0,[Rn] + CMP R0,#0 + MOVEQ R0,#1 + MOVNE R0,#0 + BX LR
        """
        d = self.data

        # Pattern A: 5 instructions (20 bytes)
        if func_off + 20 <= len(d):
            insns = [struct.unpack_from('<I', d, func_off + k * 4)[0] for k in range(5)]

            rd0, _ = arm32_decode_ldr_pc(insns[0], func_off)
            if rd0 is not None:
                # LDR Rm, [Rn] or LDR Rm, [Rn, #0]
                if (insns[1] & 0x0FFF0FFF) == 0x05900000:
                    ldr_rn = (insns[1] >> 16) & 0xF
                    ldr_rd = (insns[1] >> 12) & 0xF
                    if ldr_rn == rd0:
                        # MVN Rd, Rm
                        if (insns[2] & 0x0FFF0FF0) == 0x01E00000:
                            mvn_rd = (insns[2] >> 12) & 0xF
                            mvn_rm = insns[2] & 0xF
                            if mvn_rm == ldr_rd:
                                # AND R0, Rd, #1
                                if (insns[3] & 0x0FFF0FFF) == 0x02000001:
                                    and_rn = (insns[3] >> 16) & 0xF
                                    and_rd = (insns[3] >> 12) & 0xF
                                    if and_rd == 0 and and_rn == mvn_rd:
                                        if insns[4] == 0xE12FFF1E:
                                            return {
                                                'pattern': 'A',
                                                'desc': 'LDR[PC]+LDR+MVN+AND#1+BX_LR',
                                                'func_off': func_off, 'func_size': 20,
                                                'logic': 'return (~gz_enabled) & 1',
                                            }

        # Pattern B: 4 instructions (16 bytes)
        if func_off + 16 <= len(d):
            insns = [struct.unpack_from('<I', d, func_off + k * 4)[0] for k in range(4)]
            rd0, _ = arm32_decode_ldr_pc(insns[0], func_off)
            if rd0 is not None:
                if (insns[1] & 0x0FFF0FFF) == 0x05900000:
                    ldr_rn = (insns[1] >> 16) & 0xF
                    ldr_rd = (insns[1] >> 12) & 0xF
                    if ldr_rn == rd0:
                        # EOR R0, Rm, #1
                        if (insns[2] & 0x0FFF0FFF) == 0x02200001:
                            eor_rn = (insns[2] >> 16) & 0xF
                            eor_rd = (insns[2] >> 12) & 0xF
                            if eor_rd == 0 and eor_rn == ldr_rd:
                                if insns[3] == 0xE12FFF1E:
                                    return {
                                        'pattern': 'B',
                                        'desc': 'LDR[PC]+LDR+EOR#1+BX_LR',
                                        'func_off': func_off, 'func_size': 16,
                                        'logic': 'return gz_enabled ^ 1',
                                    }

        # Pattern C: 6 instructions (24 bytes)
        if func_off + 24 <= len(d):
            insns = [struct.unpack_from('<I', d, func_off + k * 4)[0] for k in range(6)]
            rd0, _ = arm32_decode_ldr_pc(insns[0], func_off)
            if rd0 is not None:
                if (insns[1] & 0x0FFF0FFF) == 0x05900000:
                    ldr_rn = (insns[1] >> 16) & 0xF
                    ldr_rd = (insns[1] >> 12) & 0xF
                    if ldr_rn == rd0:
                        # CMP Rm, #0
                        if (insns[2] & 0x0FFF0FFF) == 0x03500000:
                            cmp_rn = (insns[2] >> 16) & 0xF
                            if cmp_rn == ldr_rd:
                                # MOVEQ R0, #1 = 0x03A00001
                                # MOVNE R0, #0 = 0x13A00000
                                if insns[3] == 0x03A00001 and insns[4] == 0x13A00000:
                                    if insns[5] == 0xE12FFF1E:
                                        return {
                                            'pattern': 'C',
                                            'desc': 'LDR[PC]+LDR+CMP#0+MOVEQ/MOVNE+BX_LR',
                                            'func_off': func_off, 'func_size': 24,
                                            'logic': 'return (gz_enabled == 0) ? 1 : 0',
                                        }

        return None

    def _arm32_check_already_patched(self, off):
        if off + 8 > len(self.data):
            return False
        return (struct.unpack_from('<I', self.data, off)[0] == 0xE3A00001 and
                struct.unpack_from('<I', self.data, off + 4)[0] == 0xE12FFF1E)

    def _arm32_find_callers(self, func_off):
        callers = []
        limit = self.code_end or (self.lk_offset + self.lk_size)
        for i in range(self.lk_offset, limit - 4, 4):
            if arm32_decode_bl(struct.unpack_from('<I', self.data, i)[0], i) == func_off:
                callers.append(i)
        return callers

    def _arm32_find_cmp_bcc_after(self, bl_off):
        """Find CMP R0, #0 + BEQ/BNE after a BL (ARM32 equivalent of CBZ/CBNZ)."""
        limit = min(bl_off + 24, self.lk_offset + self.lk_size)
        for j in range(bl_off + 4, limit, 4):
            insn = struct.unpack_from('<I', self.data, j)[0]
            # CMP R0, #0 = 0xE3500000
            if (insn & 0x0FFF0FFF) == 0x03500000 and ((insn >> 16) & 0xF) == 0:
                # Next should be BEQ or BNE
                if j + 4 < limit:
                    next_insn = struct.unpack_from('<I', self.data, j + 4)[0]
                    if (next_insn >> 24) == 0x0A:
                        return j + 4, 'BEQ'
                    if (next_insn >> 24) == 0x1A:
                        return j + 4, 'BNE'
            # Direct CBZ-like: some compilers emit BEQ/BNE right after BL
            # (relying on BL setting flags if the function does CMP before return)
            # But this is rare; CMP R0, #0 is more common
        return None, None

    def _arm32_find_gz_unmap_via_string(self):
        for name in ['gz_unmap2()', 'gz_unmap()']:
            str_off = self.find_string(name)
            if str_off is None:
                continue
            refs = self._arm32_find_string_ref(str_off)
            for ref in refs:
                for scan in range(ref - 4, max(ref - 160, self.lk_offset + 4), -4):
                    insn = struct.unpack_from('<I', self.data, scan)[0]
                    # BEQ or BNE
                    is_beq = (insn >> 24) == 0x0A
                    is_bne = (insn >> 24) == 0x1A
                    if not is_beq and not is_bne:
                        continue
                    # CMP R0, #0 should be right before
                    if scan < self.lk_offset + 8:
                        continue
                    prev_cmp = struct.unpack_from('<I', self.data, scan - 4)[0]
                    if (prev_cmp & 0x0FFF0FFF) != 0x03500000:
                        continue
                    if ((prev_cmp >> 16) & 0xF) != 0:
                        continue
                    # BL should be right before CMP
                    prev_bl = struct.unpack_from('<I', self.data, scan - 8)[0]
                    bl_target = arm32_decode_bl(prev_bl, scan - 8)
                    if bl_target is None or not (self.lk_offset <= bl_target < self.code_end):
                        continue
                    if self._arm32_check_already_patched(bl_target):
                        return {
                            'method': 'string', 'string': name,
                            'check_func': bl_target, 'bl_off': scan - 8,
                            'cbz_off': scan, 'cbz_type': 'BEQ' if is_beq else 'BNE',
                            'already_patched': True, 'pattern': None,
                        }
                    pat = self._arm32_match_check_pattern(bl_target)
                    if pat is not None:
                        return {
                            'method': 'string', 'string': name,
                            'check_func': bl_target, 'bl_off': scan - 8,
                            'cbz_off': scan, 'cbz_type': 'BEQ' if is_beq else 'BNE',
                            'already_patched': False, **pat,
                        }
                    break
        return None

    def _arm32_find_gz_unmap_via_pattern(self):
        limit = self.code_end or (self.lk_offset + self.lk_size)
        for i in range(self.lk_offset, limit - 24, 4):
            if self._arm32_check_already_patched(i):
                for c in self._arm32_find_callers(i):
                    bcc, btype = self._arm32_find_cmp_bcc_after(c)
                    if bcc is not None:
                        return {
                            'method': 'pattern', 'check_func': i, 'bl_off': c,
                            'cbz_off': bcc, 'cbz_type': btype,
                            'already_patched': True, 'pattern': None,
                        }
                continue
            pat = self._arm32_match_check_pattern(i)
            if pat is None:
                continue
            for c in self._arm32_find_callers(i):
                bcc, btype = self._arm32_find_cmp_bcc_after(c)
                if bcc is not None:
                    return {
                        'method': 'pattern', 'check_func': i, 'bl_off': c,
                        'cbz_off': bcc, 'cbz_type': btype,
                        'already_patched': False, **pat,
                    }
        return None

    # ────────────────────────────────────────────────────
    #  gz_enabled global detection
    # ────────────────────────────────────────────────────

    def _find_gz_enabled_global(self, gz_unmap_result):
        """Find gz_enabled global variable file offset and current value."""
        if gz_unmap_result is None:
            return None, None

        if not gz_unmap_result.get('already_patched'):
            if self.arch == 'aarch64':
                code_off = gz_unmap_result.get('global_code_off')
                if code_off is not None:
                    file_off = code_off + self.lk_offset
                    if file_off + 4 <= len(self.data):
                        return file_off, struct.unpack_from('<I', self.data, file_off)[0]
            elif self.arch == 'arm32':
                func_off = gz_unmap_result.get('func_off')
                if func_off is not None and self.arm32_base is not None:
                    insn = struct.unpack_from('<I', self.data, func_off)[0]
                    _, lit_off = arm32_decode_ldr_pc(insn, func_off)
                    if lit_off is not None and lit_off + 4 <= len(self.data):
                        abs_addr = struct.unpack_from('<I', self.data, lit_off)[0]
                        file_off = abs_addr - self.arm32_base + self.lk_offset
                        if self.lk_offset <= file_off < self.lk_offset + self.lk_size - 3:
                            return file_off, struct.unpack_from('<I', self.data, file_off)[0]
            return None, None

        # Already patched (method A) — scan for gz_plat_hook after the patched func
        if self.arch == 'aarch64':
            func_off = gz_unmap_result['check_func']
            for off in range(func_off + 8, min(func_off + 48, len(self.data) - 12), 4):
                insn = struct.unpack_from('<I', self.data, off)[0]
                if (insn & 0xFFC00000) != 0xB9400000:
                    continue
                ldr_rt = insn & 0x1F
                insn2 = struct.unpack_from('<I', self.data, off + 4)[0]
                rd2, page2 = a64_decode_adrp(insn2, off + 4, self.lk_offset)
                if rd2 is None:
                    continue
                insn3 = struct.unpack_from('<I', self.data, off + 8)[0]
                if (insn3 & 0xFFC00000) != 0xB9000000:
                    continue
                str_rt = insn3 & 0x1F
                str_rn = (insn3 >> 5) & 0x1F
                str_imm = ((insn3 >> 10) & 0xFFF) * 4
                if str_rt == ldr_rt and str_rn == rd2:
                    file_off = page2 + str_imm + self.lk_offset
                    if file_off + 4 <= len(self.data):
                        return file_off, struct.unpack_from('<I', self.data, file_off)[0]

        return None, None

    # ────────────────────────────────────────────────────
    #  New-style GZ init detection (bl2_ext, MT6991+)
    # ────────────────────────────────────────────────────

    def _bl2_find_adrp_ref(self, target_file_off, bl2_off, bl2_size):
        """Find ADRP+ADD reference to a target address within bl2_ext."""
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

    def _find_bl2ext_gz_init(self):
        """Detect new-style GZ init pipeline in bl2_ext segment (MT6991+).

        Returns dict with patch locations or None if not found.
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

        # Find gz_init_main function start (scan back from failed_ref for prologue)
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

        # Find BL caller of gz_init_main (in gz_init_wrapper)
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

        # Look before the BL for TBZ/CBZ + BL pattern → gz_config_validate
        validate_func = validate_bl = tbz_off = None
        for scan in range(caller_bl - 4, max(bl2_off, caller_bl - 48), -4):
            insn = struct.unpack_from('<I', d, scan)[0]
            is_tbz = (insn & 0x7F80001F) == 0x36000000  # TBZ Wn, #0
            is_cbz = (insn & 0xFF00001F) == 0x34000000   # CBZ W0
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

        # Scan validate function for the W0 return-value instruction
        validate_patch_off = None
        validate_patch_orig = None
        already_patched_validate = False
        if validate_func is not None:
            for off in range(validate_func, min(validate_func + 40,
                                                bl2_off + bl2_size - 4), 4):
                insn = struct.unpack_from('<I', d, off)[0]
                if insn == 0x52800000:  # MOV W0, #0 — already patched
                    already_patched_validate = True
                    validate_patch_off = off
                    break
                # BIC W0, Wn, Wm (0A20xxxx with Rd=0)
                if (insn & 0xFFE0001F) == 0x0A200000:
                    validate_patch_off = off
                    validate_patch_orig = insn
                    break
                # AND W0, Wn, Wm
                if (insn & 0xFFE0001F) == 0x0A000000 and (insn & 0x1F) == 0:
                    validate_patch_off = off
                    validate_patch_orig = insn
                    break

        # Find cleanup target ("config env not valid" ADRP ref within gz_init_main)
        cleanup_target = None
        env_off = d.find(b'[GZ_INIT] config env not valid',
                         bl2_off, bl2_off + bl2_size)
        if env_off >= 0:
            env_ref = self._bl2_find_adrp_ref(env_off, bl2_off, bl2_size)
            if env_ref is not None and init_main <= env_ref <= init_main + 0x200:
                cleanup_target = env_ref

        # Find gz_init_main's first BL or B (for method B: force failure)
        # After patching, the BL becomes B, so scan for both.
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

        # GZ functional string search (architecture-independent)
        gz_func = self.find_gz_func_strings()
        r['has_gz_code'] = len(gz_func) > 0
        r['gz_func_strings'] = gz_func

        # GZ display strings
        gz_strs = self.find_gz_strings()
        r['gz_strings'] = gz_strs
        r['has_gz'] = len(gz_strs) > 0

        # Boot tag hooks
        r['boot_tag_hooks'] = self.find_gz_boot_tag_hooks()

        # DTB
        r['dtb_gz_nodes'] = self.check_dtb_gz_nodes()

        # Partition name references (gz1/gz2 in partition tables)
        gz_parts = []
        for off, s in gz_strs:
            if s in ('gz', 'gz1', 'gz2', 'gz_a', 'gz_b'):
                gz_parts.append(s)
        r['gz_part_names'] = gz_parts

        if self.arch == 'aarch64':
            el2 = self._a64_find_el2_access()
            r['el2_accesses'] = len(el2)
            if el2:
                r['el2_first'] = el2[0]

            if r['has_gz_code']:
                result = self._a64_find_gz_unmap_via_string()
                if result is None:
                    result = self._a64_find_gz_unmap_via_pattern()
                r['gz_unmap'] = result
            else:
                r['gz_unmap'] = None

        elif self.arch == 'arm32':
            self._arm32_detect_base()
            r['arm32_base'] = self.arm32_base

            if r['has_gz_code']:
                result = self._arm32_find_gz_unmap_via_string()
                if result is None:
                    result = self._arm32_find_gz_unmap_via_pattern()
                r['gz_unmap'] = result
            else:
                r['gz_unmap'] = None
        else:
            r['gz_unmap'] = None

        result = r.get('gz_unmap')
        r['patchable'] = result is not None and not result.get('already_patched', False)
        r['already_patched'] = result is not None and result.get('already_patched', False)

        gz_off, gz_val = self._find_gz_enabled_global(result)
        if gz_off is not None:
            r['gz_enabled_off'] = gz_off
            r['gz_enabled_value'] = gz_val

        # New-style GZ init detection (bl2_ext, MT6991+)
        # Try this when old-style gz_unmap is not found and arch is aarch64
        r['gz_init_v2'] = None
        if r.get('gz_unmap') is None and self.arch == 'aarch64':
            v2 = self._find_bl2ext_gz_init()
            if v2 is not None:
                r['gz_init_v2'] = v2

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

    if r.get('arm32_base') is not None:
        print(f"加载基址: 0x{r['arm32_base']:08X}")

    # GZ functional strings
    gz_func = r.get('gz_func_strings', {})
    if gz_func:
        print(f"\n  GZ 功能字符串: {len(gz_func)} 个")
        for kw, (off, s) in gz_func.items():
            print(f"    0x{off:06X}: \"{s}\"")

    # Key display strings (if functional strings not found, show display strings)
    if not gz_func:
        gz_strs = r.get('gz_strings', [])
        key_kws = ['gz_unmap', 'GZ_UNMAP', 'boottags_gz', 'gz-tee', 'gz-main',
                   'trusty-gz', 'nebula']
        key_strs = [(o, s) for o, s in gz_strs if any(k in s for k in key_kws)]
        if key_strs:
            print(f"\n  GZ 关键字符串: {len(key_strs)} 个")
            for off, s in key_strs:
                print(f"    0x{off:06X}: \"{s}\"")

    # Partition name references
    gz_parts = r.get('gz_part_names', [])
    if gz_parts and not gz_func:
        print(f"\n  GZ 分区名引用: {', '.join(gz_parts)} (仅分区表条目, 非 GZ 功能代码)")

    hooks = r.get('boot_tag_hooks', {})
    if hooks:
        print(f"\n  Boot Tag 钩子: {len(hooks)} 个")
        for name in hooks:
            print(f"    {name.replace('pl_boottags_', '')}")

    el2_n = r.get('el2_accesses', 0)
    if el2_n:
        first = r.get('el2_first')
        print(f"\n  EL2 寄存器访问: {el2_n} 处 (首个 @ 0x{first[0]:06X}: {first[1]})")

    dtb = r.get('dtb_gz_nodes', [])
    dtb_key = [n for n in dtb if any(k in n for k in ['trusty-gz', 'nebula', 'gz-main'])]
    if dtb_key:
        print(f"  DTB GZ 节点: {', '.join(dtb_key[:6])}")

    gz = r.get('gz_unmap')
    v2 = r.get('gz_init_v2')
    print(f"\n{'=' * 60}")

    if gz is None and v2 is None:
        if not r.get('has_gz_code'):
            if r.get('has_gz'):
                print(f"  此 LK 不包含 GZ 功能代码 (仅有分区名/DTB 节点)")
                print(f"  GZ 禁用应在 preloader 层面处理 (GPT 方案)")
            else:
                print(f"  此 LK 未包含 GenieZone 相关内容")
        else:
            print(f"  gz_unmap 检查函数: 未找到")
            print(f"  无法自动补丁, 需手动逆向分析")
        return

    # ── Old-style (gz_unmap_check) ──
    if gz is not None:
        if gz.get('already_patched'):
            print(f"  gz_unmap 检查函数: 0x{gz['check_func']:06X}")
            print(f"  状态: 已补丁 (方案 A)")
        else:
            print(f"  gz_unmap 检查函数: 0x{gz['check_func']:06X}")
            print(f"  检测方式: {gz.get('method', '?')}", end='')
            if gz.get('string'):
                print(f" (字符串 \"{gz['string']}\")", end='')
            print()
            print(f"  模式: {gz.get('desc', '?')}")
            print(f"  逻辑: {gz.get('logic', '?')}")
            print(f"  调用点: 0x{gz['bl_off']:06X} → {gz['cbz_type']} @ 0x{gz['cbz_off']:06X}")

        gz_off = r.get('gz_enabled_off')
        gz_val = r.get('gz_enabled_value')
        if gz_off is not None:
            status = '默认启用' if gz_val == 1 else ('默认禁用' if gz_val == 0 else f'值={gz_val}')
            print(f"\n  gz_enabled 全局变量: 0x{gz_off:06X} = {gz_val} ({status})")

        script = os.path.basename(sys.argv[0])
        has_a = r.get('patchable')
        has_b = gz_off is not None and gz_val == 1

        if has_a or has_b:
            print()
        if has_a:
            print(f"  方案 A: gz_unmap_check → 始终返回 1 (强制释放 GZ 内存)")
            print(f"    python3 {script} {r['file']} --patch")
        if has_b:
            print(f"  方案 B: gz_enabled 默认值 1→0 (GZ 默认禁用)")
            print(f"    python3 {script} {r['file']} --patch-default")
        if has_a and has_b:
            print(f"  A+B:    python3 {script} {r['file']} --patch --patch-default")
        print()
        return

    # ── New-style (bl2_ext GZ init pipeline) ──
    print(f"  GZ 类型: 新式初始化管线 (bl2_ext 段)")
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
    if pa and pb:
        print()
        return

    script = os.path.basename(sys.argv[0])
    has_a = v2.get('validate_patch_off') is not None and not pa
    has_b = (v2.get('init_first_bl') is not None
             and v2.get('cleanup_target') is not None and not pb)
    if has_a or has_b:
        print()
    if has_a:
        print(f"  方案 A: gz_config_validate → 返回 0 (跳过 GZ 初始化)")
        print(f"    python3 {script} {r['file']} --patch-validate")
    if has_b:
        print(f"  方案 B: gz_init_main → 强制失败 (触发内存释放清理)")
        print(f"    python3 {script} {r['file']} --patch-init-fail")
    if has_a and has_b:
        print(f"  A+B:    python3 {script} {r['file']}"
              f" --patch-validate --patch-init-fail")
    print()


def do_patch(analyzer, results, output_path, patch_func=False, patch_default=False,
             patch_validate=False, patch_init_fail=False, dry_run=False):
    patched = bytearray(analyzer.data)
    any_applied = False

    # ── Old-style patches ──

    if patch_func:
        gz = results.get('gz_unmap')
        if gz is None:
            print("错误: 未找到 gz_unmap 检查函数, 无法应用方案 A")
        elif gz.get('already_patched'):
            print("方案 A: gz_unmap_check 已补丁, 跳过")
        else:
            func_off = gz['check_func']
            func_size = gz.get('func_size', 20)
            arch = results.get('arch', 'aarch64')
            orig = analyzer.data[func_off:func_off + func_size]

            if arch == 'arm32':
                patch = bytearray()
                patch += struct.pack('<I', 0xE3A00001)  # MOV R0, #1
                patch += struct.pack('<I', 0xE12FFF1E)  # BX LR
                while len(patch) < func_size:
                    patch += struct.pack('<I', 0xE1A00000)  # NOP
                insn_labels = {0: 'MOV R0, #1', 4: 'BX LR'}
            else:
                patch = bytearray()
                patch += struct.pack('<I', 0x52800020)  # MOV W0, #1
                patch += struct.pack('<I', 0xD65F03C0)  # RET
                while len(patch) < func_size:
                    patch += struct.pack('<I', 0xD503201F)  # NOP
                insn_labels = {0: 'MOV W0, #1', 4: 'RET'}

            print(f"\n方案 A — gz_unmap_check 函数补丁:")
            print(f"  目标: 0x{func_off:06X} ({func_size} 字节)")
            print(f"  效果: 始终返回 1, 强制释放 GZ 内存\n")
            print(f"  原始指令:")
            for k in range(0, func_size, 4):
                v = struct.unpack_from('<I', orig, k)[0]
                print(f"    0x{func_off + k:06X}: {v:08X}")
            print(f"  补丁指令:")
            for k in range(0, func_size, 4):
                v = struct.unpack_from('<I', patch, k)[0]
                label = insn_labels.get(k, 'NOP')
                print(f"    0x{func_off + k:06X}: {v:08X}  ; {label}")

            patched[func_off:func_off + func_size] = patch
            any_applied = True

    if patch_default:
        gz_off = results.get('gz_enabled_off')
        gz_val = results.get('gz_enabled_value')
        if gz_off is None:
            print("错误: 未找到 gz_enabled 全局变量, 无法应用方案 B")
        elif gz_val == 0:
            print("方案 B: gz_enabled 已为 0, 跳过")
        else:
            print(f"\n方案 B — gz_enabled 默认值修改:")
            print(f"  目标: 0x{gz_off:06X}")
            print(f"  修改: {gz_val} (0x{gz_val:08X}) → 0 (0x00000000)")
            print(f"  效果: GZ 默认禁用, 仅当 preloader boot tag 明确启用时才生效")
            struct.pack_into('<I', patched, gz_off, 0)
            any_applied = True

    # ── New-style patches (bl2_ext) ──

    v2 = results.get('gz_init_v2')

    if patch_validate:
        if v2 is None:
            print("错误: 未找到新式 GZ 初始化管线, 无法应用方案 A")
        elif v2.get('already_patched_validate'):
            print("方案 A: gz_config_validate 已补丁, 跳过")
        elif v2.get('validate_patch_off') is None:
            print("错误: 未定位 gz_config_validate 返回值指令, 无法应用方案 A")
        else:
            off = v2['validate_patch_off']
            orig = struct.unpack_from('<I', analyzer.data, off)[0]
            new_insn = 0x52800000  # MOV W0, #0

            print(f"\n方案 A — gz_config_validate 补丁 (bl2_ext 段):")
            print(f"  目标: 0x{off:06X}")
            print(f"  原始: {orig:08X}  (返回值取决于配置字节)")
            print(f"  补丁: {new_insn:08X}  ; MOV W0, #0")
            print(f"  效果: gz_config_validate 始终返回 0 → 跳过 GZ 初始化")

            struct.pack_into('<I', patched, off, new_insn)
            any_applied = True

    if patch_init_fail:
        if v2 is None:
            print("错误: 未找到新式 GZ 初始化管线, 无法应用方案 B")
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

            print(f"\n方案 B — gz_init_main 强制失败 (bl2_ext 段):")
            print(f"  目标: 0x{bl_off:06X}")
            print(f"  原始: {orig:08X}  (BL gz_config_env_get)")
            print(f"  补丁: {new_insn:08X}  ; B 0x{target:06X}")
            print(f"  效果: gz_init_main 直接跳转到错误清理路径")
            print(f"         → gz_mblock_free_all 释放 GZ 内存")
            print(f"         → 打印 \"init failed; gz is disabled from now on\"")

            struct.pack_into('<I', patched, bl_off, new_insn)
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

    print(f"\n{'═' * 50}")
    print(f"完成! 共修改 {diff_count} 字节")
    print(f"输出文件: {output_path}")
    print(f"{'═' * 50}")
    return True


def main():
    parser = argparse.ArgumentParser(
        description='检测并修补 MTK LK 中的 GenieZone 内存释放逻辑',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
旧式 (gz_unmap_check, 如 MT6833/MT6895):
  --patch             方案 A: 补丁 gz_unmap_check 始终返回 1
  --patch-default     方案 B: 修改 gz_enabled 默认值 1→0

新式 (bl2_ext GZ 初始化管线, 如 MT6991):
  --patch-validate    方案 A: gz_config_validate 返回 0, 跳过 GZ 初始化
  --patch-init-fail   方案 B: gz_init_main 强制失败, 触发内存释放清理

先运行不带参数的分析, 脚本会自动检测类型并显示可用方案。
配合已解锁的 bootloader 或签名绕过工具使用。
""")
    parser.add_argument('input', help='LK 镜像文件 (lk.img)')
    parser.add_argument('-o', '--output', help='输出文件路径')
    parser.add_argument('--patch', action='store_true',
                        help='旧式方案 A: 补丁 gz_unmap_check 函数')
    parser.add_argument('--patch-default', action='store_true',
                        help='旧式方案 B: 修改 gz_enabled 默认值 1→0')
    parser.add_argument('--patch-validate', action='store_true',
                        help='新式方案 A: 跳过 GZ 初始化')
    parser.add_argument('--patch-init-fail', action='store_true',
                        help='新式方案 B: 强制 GZ 初始化失败 + 释放内存')
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

    want_patch = (args.patch or args.patch_default
                  or args.patch_validate or args.patch_init_fail)
    if want_patch or args.dry_run:
        v2 = results.get('gz_init_v2')

        # Determine which patches to apply
        if args.dry_run and not want_patch:
            # Dry-run with no specific flag: show all available patches
            pf = results.get('patchable') or results.get('already_patched')
            pd = results.get('gz_enabled_off') is not None
            pv = v2 is not None and not v2.get('already_patched_validate')
            pi = v2 is not None and not v2.get('already_patched_init')
        else:
            pf = args.patch
            pd = args.patch_default
            pv = args.patch_validate
            pi = args.patch_init_fail

        can_old = (results.get('patchable') or results.get('already_patched')
                   or results.get('gz_enabled_off') is not None)
        can_new = v2 is not None

        if pf and not (results.get('patchable') or results.get('already_patched')):
            print("错误: 未找到 gz_unmap 检查函数 (旧式方案 A)")
        if pd and results.get('gz_enabled_off') is None:
            print("错误: 未找到 gz_enabled 全局变量 (旧式方案 B)")
        if pv and not can_new:
            print("错误: 未找到新式 GZ 初始化管线 (新式方案 A)")
        if pi and not can_new:
            print("错误: 未找到新式 GZ 初始化管线 (新式方案 B)")
        if not can_old and not can_new and not args.dry_run:
            sys.exit(1)

        if not args.dry_run and not os.path.isfile(backup_path):
            shutil.copy2(args.input, backup_path)
            print(f"已备份原始文件到: {backup_path}")

        ok = do_patch(analyzer, results, output_path,
                      patch_func=pf, patch_default=pd,
                      patch_validate=pv, patch_init_fail=pi,
                      dry_run=args.dry_run)
        if not ok and not args.dry_run:
            sys.exit(1)

        if ok and not args.dry_run:
            print(f"\n还原方法:")
            print(f"  python3 {os.path.basename(sys.argv[0])} {args.input} --restore")


if __name__ == '__main__':
    main()
