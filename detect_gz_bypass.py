#!/usr/bin/env python3
"""
detect_gz_bypass.py - 检测 MediaTek preloader 可用的 GenieZone 绕过方案

分析 preloader 固件, 自动检测:
  1. GenieZone 加载代码是否存在
  2. halt_on_assert 是否无条件置 1
  3. 判断 GPT 修改方案是否可用

支持:
  - Thumb (非 PIC, 如 MT6895)
  - Thumb PIC (位置无关代码, 如 MT6833)
  - AArch64 (如 MT6983)

Usage:
  python3 detect_gz_bypass.py preloader.img
  python3 detect_gz_bypass.py preloader_*.img    # 批量分析
"""

import struct
import sys
import os

GFH_MAGIC = 0x014D4D4D
NOGZ_MAGIC = 0x4E6F475A


class PreloaderAnalyzer:
    def __init__(self, path):
        self.path = path
        with open(path, 'rb') as f:
            self.data = f.read()
        self.base = None
        self.gfh_offset = 0
        self.code_start = None
        self.code_end = None
        self.gfh_info = {}
        self.is_pic = False
        self.is_a64 = False

    def parse_gfh(self):
        data = self.data
        gfh_off = None
        scan_limit = min(len(data) - 4, 0x10000)
        for off in range(0, scan_limit, 4):
            if struct.unpack_from('<I', data, off)[0] == GFH_MAGIC:
                sz = struct.unpack_from('<H', data, off + 4)[0]
                ht = struct.unpack_from('<H', data, off + 6)[0]
                if ht == 0 and sz >= 0x38:
                    gfh_off = off
                    break
        if gfh_off is None:
            return False

        self.gfh_offset = gfh_off
        content_offset_field = struct.unpack_from('<I', data, gfh_off + 0x28)[0]

        self.gfh_info = {
            'gfh_offset': gfh_off,
            'load_addr': struct.unpack_from('<I', data, gfh_off + 0x1C)[0],
            'file_len': struct.unpack_from('<I', data, gfh_off + 0x20)[0],
            'content_offset': content_offset_field,
            'sig_len': struct.unpack_from('<I', data, gfh_off + 0x2C)[0],
        }
        self.code_start = gfh_off + content_offset_field
        self.code_end = gfh_off + self.gfh_info['file_len']
        self.base = self.gfh_info['load_addr'] - self.code_start
        self._detect_arch()
        return True

    def _detect_arch(self):
        data = self.data
        start = self.code_start or 0
        self.is_a64 = False
        self.is_pic = False

        if start + 16 > len(data):
            return

        first_hw = struct.unpack_from('<H', data, start)[0]
        if (first_hw & 0xFF00) == 0xB500:
            # Thumb PUSH prologue — definitely not AArch64
            pass
        else:
            scan_start = start
            a64_score = 0
            first_insn = struct.unpack_from('<I', data, start)[0]
            # Entry-point B jumps over metadata — follow it
            if (first_insn & 0xFC000000) == 0x14000000:
                imm26 = first_insn & 0x3FFFFFF
                if 0 < imm26 < 0x100:
                    scan_start = start + imm26 * 4
                    a64_score = 2
                    if scan_start + 16 > len(data):
                        scan_start = start

            for k in range(4):
                off = scan_start + k * 4
                if off + 4 > len(data):
                    break
                insn = struct.unpack_from('<I', data, off)[0]
                if (insn & 0xFC000000) == 0x14000000:
                    a64_score += 2
                elif (insn & 0xFC000000) == 0x94000000:
                    a64_score += 2
                elif (insn & 0xFF800000) in (0xA9800000, 0xA9000000):
                    a64_score += 2
                elif (insn & 0xFFC00000) in (0x91000000, 0xD1000000):
                    a64_score += 1
                elif (insn >> 24) == 0xD5:
                    a64_score += 1
                elif (insn & 0x9F000000) == 0x90000000:
                    a64_score += 1
                elif (insn & 0xFFE00000) in (0x52800000, 0xD2800000):
                    a64_score += 1
                elif (insn & 0xFF000000) == 0x58000000:
                    a64_score += 1
                elif (insn & 0xFF000000) in (0xAA000000, 0xB9000000, 0xF9000000):
                    a64_score += 1

            if a64_score >= 3:
                self.is_a64 = True
                return

        limit = min(self.code_end or len(data), len(data))
        add_pc_count = 0
        ldr_count = 0
        for i in range(start, min(start + 0x10000, limit), 2):
            w = struct.unpack_from('<H', data, i)[0]
            if (w & 0xF800) == 0x4800:
                ldr_count += 1
            if (w & 0xFF78) == 0x4478:
                add_pc_count += 1
        self.is_pic = ldr_count > 0 and (add_pc_count / max(ldr_count, 1)) > 0.1

    def file2mem(self, off):
        return off + self.base if self.base is not None else None

    def _code_limit(self):
        return min(self.code_end or len(self.data), len(self.data))

    # ── Thumb helpers ──

    def _decode_movw(self, w, w2):
        dw = (w << 16) | w2
        if (dw & 0xFBF08000) == 0xF2400000:
            imm4 = w & 0xF
            i_bit = (w >> 10) & 1
            imm3 = (w2 >> 12) & 7
            imm8 = w2 & 0xFF
            rd = (w2 >> 8) & 0xF
            return rd, (imm4 << 12) | (i_bit << 11) | (imm3 << 8) | imm8
        return None, None

    def _decode_movt(self, w, w2):
        dw = (w << 16) | w2
        if (dw & 0xFBF08000) == 0xF2C00000:
            imm4 = w & 0xF
            i_bit = (w >> 10) & 1
            imm3 = (w2 >> 12) & 7
            imm8 = w2 & 0xFF
            rd = (w2 >> 8) & 0xF
            return rd, (imm4 << 12) | (i_bit << 11) | (imm3 << 8) | imm8
        return None, None

    # ── AArch64 helpers ──

    @staticmethod
    def _sign_ext(val, bits):
        if val & (1 << (bits - 1)):
            return val - (1 << bits)
        return val

    def _decode_adrp(self, insn, file_off):
        if (insn & 0x9F000000) != 0x90000000:
            return None, None
        rd = insn & 0x1F
        immlo = (insn >> 29) & 3
        immhi = (insn >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        imm = self._sign_ext(imm, 21)
        pc = (file_off + self.base) & 0xFFFFFFFF
        pc_page = pc & ~0xFFF
        page = (pc_page + (imm << 12)) & 0xFFFFFFFF
        return rd, page

    def _decode_add_imm64(self, insn):
        if (insn & 0xFFC00000) != 0x91000000:
            return None, None, None
        rd = insn & 0x1F
        rn = (insn >> 5) & 0x1F
        imm12 = (insn >> 10) & 0xFFF
        sh = (insn >> 22) & 1
        if sh:
            imm12 <<= 12
        return rd, rn, imm12

    # ── String reference counting ──

    def count_string_refs(self, file_off):
        if self.is_a64:
            return self._count_string_refs_a64(file_off)
        if self.base is None:
            return 0
        mem_addr = file_off + self.base
        data = self.data
        limit = self._code_limit()
        start = self.code_start or 0
        lo16 = mem_addr & 0xFFFF
        hi16 = (mem_addr >> 16) & 0xFFFF
        count = 0

        if not self.is_pic:
            addr_bytes = struct.pack('<I', mem_addr)
            pos = start
            while True:
                p = data.find(addr_bytes, pos, limit)
                if p < 0:
                    break
                for scan in range(max(start, p - 1024), p, 2):
                    w = struct.unpack_from('<H', data, scan)[0]
                    if (w & 0xF800) == 0x4800:
                        imm = (w & 0xFF) * 4
                        lit_off = ((scan + 4) & ~3) + imm
                        if lit_off == p:
                            count += 1
                            break
                pos = p + 1

            for i in range(start, limit - 8, 2):
                w = struct.unpack_from('<H', data, i)[0]
                if (w >> 11) < 0x1D:
                    continue
                w2 = struct.unpack_from('<H', data, i + 2)[0]

                if w == 0xF8DF:
                    imm12 = w2 & 0xFFF
                    lit_off = ((i + 4) & ~3) + imm12
                    if lit_off + 4 <= len(data):
                        v = struct.unpack_from('<I', data, lit_off)[0]
                        if v == mem_addr:
                            count += 1
                    continue

                rd_w, imm_w = self._decode_movw(w, w2)
                if rd_w is not None and imm_w == lo16:
                    for j in range(i + 4, min(i + 16, limit - 4), 2):
                        jw = struct.unpack_from('<H', data, j)[0]
                        if (jw >> 11) < 0x1D:
                            continue
                        jw2 = struct.unpack_from('<H', data, j + 2)[0]
                        rd_t, imm_t = self._decode_movt(jw, jw2)
                        if rd_t == rd_w and imm_t == hi16:
                            count += 1
                            break
            return count

        for i in range(start, limit - 6, 2):
            w = struct.unpack_from('<H', data, i)[0]
            if (w & 0xF800) != 0x4800:
                continue
            rt = (w >> 8) & 7
            imm = (w & 0xFF) * 4
            lit_off = ((i + 4) & ~3) + imm
            if lit_off + 4 > limit:
                continue
            lit_val = struct.unpack_from('<I', data, lit_off)[0]
            for j in range(i + 2, min(i + 8, limit - 2), 2):
                nw = struct.unpack_from('<H', data, j)[0]
                if nw == 0x4478 + rt:
                    resolved_file = lit_val + (j + 4)
                    if resolved_file == file_off:
                        count += 1
                    break
                if (nw >> 11) >= 0x1D or (nw & 0xF800) == 0x4800:
                    break
        return count

    def _count_string_refs_a64(self, file_off):
        if self.base is None:
            return 0
        mem_addr = (file_off + self.base) & 0xFFFFFFFF
        target_page = mem_addr & ~0xFFF
        target_off = mem_addr & 0xFFF
        data = self.data
        start = self.code_start or 0
        limit = self._code_limit()
        count = 0

        for i in range(start, limit - 8, 4):
            insn = struct.unpack_from('<I', data, i)[0]
            rd, page = self._decode_adrp(insn, i)
            if rd is None or page != target_page:
                continue
            for j in range(i + 4, min(i + 20, limit - 4), 4):
                insn2 = struct.unpack_from('<I', data, j)[0]
                rd2, rn2, imm12 = self._decode_add_imm64(insn2)
                if rd2 is not None and rn2 == rd and imm12 == target_off:
                    count += 1
                    break
                if (insn2 & 0x9F000000) == 0x90000000:
                    break
                if (insn2 & 0xFC000000) in (0x14000000, 0x94000000):
                    break
        return count

    # ── String search ──

    def find_string(self, s, find_start=False):
        if isinstance(s, str):
            s = s.encode('ascii')
        pos = self.data.find(s)
        if pos < 0:
            return None
        if find_start:
            while pos > 0 and self.data[pos - 1] != 0:
                pos -= 1
        return pos

    def _find_bare_gz_strings(self):
        offsets = []
        data = self.data
        pos = 0
        while pos < len(data) - 2:
            p = data.find(b'gz\x00', pos)
            if p < 0:
                break
            if p == 0 or data[p - 1:p] == b'\x00':
                offsets.append(p)
            pos = p + 1
        return offsets

    def _find_main_boot_area(self):
        if self.base is None:
            return None, None
        data = self.data
        limit = self._code_limit()
        start = self.code_start or 0

        markers = [b'Second Bootloader Load Failed',
                   b'Loading LK Partition',
                   b'Loading LK2 Partition',
                   b'load images',
                   b'LK addr:']
        for marker in markers:
            marker_off = data.find(marker)
            if marker_off < 0:
                continue
            while marker_off > 0 and data[marker_off - 1] != 0:
                marker_off -= 1

            if not self.is_pic:
                marker_end = data.find(b'\x00', marker_off + 1)
                if marker_end < 0:
                    continue
                for sub in range(marker_off, min(marker_end, marker_off + 60)):
                    sub_mem = sub + self.base
                    sub_bytes = struct.pack('<I', sub_mem)
                    pp = 0
                    while True:
                        pp = data.find(sub_bytes, pp, limit)
                        if pp < 0:
                            break
                        for scan in range(max(start, pp - 1024), pp, 2):
                            w = struct.unpack_from('<H', data, scan)[0]
                            if (w & 0xF800) == 0x4800:
                                imm = (w & 0xFF) * 4
                                if ((scan + 4) & ~3) + imm == pp:
                                    a = max(start, scan - 0x800)
                                    b = min(limit, scan + 0x1000)
                                    return a, b
                        pp += 1
            else:
                for i in range(start, limit - 6, 2):
                    w = struct.unpack_from('<H', data, i)[0]
                    if (w & 0xF800) != 0x4800:
                        continue
                    rt = (w >> 8) & 7
                    imm = (w & 0xFF) * 4
                    lit_off = ((i + 4) & ~3) + imm
                    if lit_off + 4 > len(data):
                        continue
                    lit_val = struct.unpack_from('<I', data, lit_off)[0]
                    for j in range(i + 2, min(i + 8, len(data) - 2), 2):
                        nw = struct.unpack_from('<H', data, j)[0]
                        if nw == 0x4478 + rt:
                            resolved = lit_val + (j + 4)
                            if resolved == marker_off:
                                a = max(start, i - 0x800)
                                b = min(limit, i + 0x1000)
                                return a, b
                            break
                        if (nw >> 11) >= 0x1D or (nw & 0xF800) == 0x4800:
                            break
        return None, None

    def _main_boot_has_gz_partition_ref(self, area_start, area_end):
        if area_start is None or area_end is None:
            return None
        data = self.data
        gz_offsets = self._find_bare_gz_strings()
        if not gz_offsets:
            return None
        gz_mem_addrs = set(off + self.base for off in gz_offsets)

        if not self.is_pic:
            for i in range(area_start, min(area_end, len(data) - 2), 2):
                w = struct.unpack_from('<H', data, i)[0]
                if (w & 0xF800) == 0x4800:
                    imm = (w & 0xFF) * 4
                    pool_off = ((i + 4) & ~3) + imm
                    if pool_off + 4 <= len(data):
                        val = struct.unpack_from('<I', data, pool_off)[0]
                        if val in gz_mem_addrs:
                            return True
            for gz_off in gz_offsets:
                gz_mem = gz_off + self.base
                lo16 = gz_mem & 0xFFFF
                hi16 = (gz_mem >> 16) & 0xFFFF
                for i in range(area_start, min(area_end, len(data) - 8), 2):
                    w = struct.unpack_from('<H', data, i)[0]
                    if (w >> 11) < 0x1D:
                        continue
                    w2 = struct.unpack_from('<H', data, i + 2)[0]
                    rd_w, imm_w = self._decode_movw(w, w2)
                    if rd_w is not None and imm_w == lo16:
                        for j in range(i + 4, min(i + 16, len(data) - 4), 2):
                            jw = struct.unpack_from('<H', data, j)[0]
                            if (jw >> 11) < 0x1D:
                                continue
                            jw2 = struct.unpack_from('<H', data, j + 2)[0]
                            rd_t, imm_t = self._decode_movt(jw, jw2)
                            if rd_t == rd_w and imm_t == hi16:
                                return True
                            break
            return False
        else:
            gz_off_set = set(gz_offsets)
            for i in range(area_start, min(area_end, len(data) - 6), 2):
                w = struct.unpack_from('<H', data, i)[0]
                if (w & 0xF800) != 0x4800:
                    continue
                rt = (w >> 8) & 7
                imm = (w & 0xFF) * 4
                lit_off = ((i + 4) & ~3) + imm
                if lit_off + 4 > len(data):
                    continue
                lit_val = struct.unpack_from('<I', data, lit_off)[0]
                for j in range(i + 2, min(i + 8, len(data) - 2), 2):
                    nw = struct.unpack_from('<H', data, j)[0]
                    if nw == 0x4478 + rt:
                        resolved = lit_val + (j + 4)
                        if resolved in gz_off_set:
                            return True
                        break
                    if (nw >> 11) >= 0x1D or (nw & 0xF800) == 0x4800:
                        break
            return False

    # ── CMP #512 detection ──

    def find_cmp_512(self):
        if self.is_a64:
            return self._find_cmp_512_a64()
        results = []
        data = self.data
        limit = self._code_limit()
        for i in range(self.code_start or 0, limit - 4, 2):
            w = struct.unpack_from('<H', data, i)[0]
            w2 = struct.unpack_from('<H', data, i + 2)[0]
            if (w & 0xFFF0) == 0xF5B0 and w2 == 0x7F00:
                rn = w & 0xF
                results.append((i, rn))
        return results

    def _find_cmp_512_a64(self):
        results = []
        data = self.data
        start = self.code_start or 0
        limit = self._code_limit()
        for i in range(start, limit - 4, 4):
            insn = struct.unpack_from('<I', data, i)[0]
            if (insn & 0xFFFFFC1F) == 0x7108001F:
                rn = (insn >> 5) & 0x1F
                results.append((i, rn))
            elif (insn & 0xFFFFFC1F) == 0xF108001F:
                rn = (insn >> 5) & 0x1F
                results.append((i, rn))
        return results

    # ── Conditional branch detection ──

    def find_conditional_branch(self, start, max_bytes=16):
        if self.is_a64:
            return self._find_conditional_branch_a64(start, max(max_bytes, 32))
        data = self.data
        for i in range(start, min(start + max_bytes, len(data) - 2), 2):
            w = struct.unpack_from('<H', data, i)[0]

            if (w & 0xFF00) == 0xD000 and ((w >> 8) & 0xF) < 0xE:
                cond = (w >> 8) & 0xF
                off8 = w & 0xFF
                if off8 & 0x80:
                    off8 -= 256
                target = i + 4 + off8 * 2
                return i, cond, target, 2

            if (w >> 11) >= 0x1D and i + 4 <= len(data):
                w2 = struct.unpack_from('<H', data, i + 2)[0]
                dw = (w << 16) | w2
                if (dw & 0xF800D000) == 0xF0008000:
                    cond = (dw >> 22) & 0xF
                    if cond < 0xE:
                        s_bit = (dw >> 26) & 1
                        j1 = (dw >> 13) & 1
                        j2 = (dw >> 11) & 1
                        imm6 = (dw >> 16) & 0x3F
                        imm11 = dw & 0x7FF
                        offset = (s_bit << 20) | (j2 << 19) | (j1 << 18) | (imm6 << 12) | (imm11 << 1)
                        if s_bit:
                            offset |= 0xFFE00000
                        target = (i + 4 + offset) & 0xFFFFFFFF
                        return i, cond, target, 4
        return None

    def _find_conditional_branch_a64(self, start, max_bytes=32):
        data = self.data
        for i in range(start, min(start + max_bytes, len(data) - 4), 4):
            insn = struct.unpack_from('<I', data, i)[0]
            # B.cond
            if (insn & 0xFF000010) == 0x54000000:
                cond = insn & 0xF
                imm19 = (insn >> 5) & 0x7FFFF
                imm19 = self._sign_ext(imm19, 19)
                target = i + imm19 * 4
                return i, cond, target, 4
            # CBZ
            if (insn & 0xFF000000) in (0x34000000, 0xB4000000):
                imm19 = (insn >> 5) & 0x7FFFF
                imm19 = self._sign_ext(imm19, 19)
                target = i + imm19 * 4
                return i, 0, target, 4
            # CBNZ
            if (insn & 0xFF000000) in (0x35000000, 0xB5000000):
                imm19 = (insn >> 5) & 0x7FFFF
                imm19 = self._sign_ext(imm19, 19)
                target = i + imm19 * 4
                return i, 1, target, 4
        return None

    # ── BL target scanning ──

    def find_bl_targets(self, start, end):
        if self.is_a64:
            return self._find_bl_targets_a64(start, end)
        targets = []
        data = self.data
        i = start
        while i < min(end, len(data) - 4):
            w = struct.unpack_from('<H', data, i)[0]
            w2 = struct.unpack_from('<H', data, i + 2)[0]
            dw = (w << 16) | w2
            if (dw & 0xF800D000) == 0xF000D000:
                s_bit = (dw >> 26) & 1
                j1 = (dw >> 13) & 1
                j2 = (dw >> 11) & 1
                imm10 = (dw >> 16) & 0x3FF
                imm11 = dw & 0x7FF
                i1 = 1 - (j1 ^ s_bit)
                i2 = 1 - (j2 ^ s_bit)
                offset = (s_bit << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
                if s_bit:
                    offset |= 0xFE000000
                target = (i + 4 + offset) & 0xFFFFFFFF
                targets.append((i, target))
                i += 4
            elif (w >> 11) >= 0x1D:
                i += 4
            else:
                i += 2
        return targets

    def _find_bl_targets_a64(self, start, end):
        targets = []
        data = self.data
        for i in range(start, min(end, len(data) - 4), 4):
            insn = struct.unpack_from('<I', data, i)[0]
            if (insn & 0xFC000000) == 0x94000000:
                imm26 = insn & 0x3FFFFFF
                imm26 = self._sign_ext(imm26, 26)
                target = i + imm26 * 4
                targets.append((i, target))
        return targets

    # ── NoGZ magic detection ──

    def range_has_nogz_magic(self, start, end):
        if self.is_a64:
            return self._range_has_nogz_magic_a64(start, end)
        data = self.data
        limit = min(end, len(data))
        magic_bytes = struct.pack('<I', NOGZ_MAGIC)
        if data.find(magic_bytes, start, limit) >= 0:
            return True
        for i in range(start, min(limit, len(data) - 2), 2):
            w = struct.unpack_from('<H', data, i)[0]
            if (w & 0xF800) == 0x4800:
                imm = (w & 0xFF) * 4
                lit_off = ((i + 4) & ~3) + imm
                if lit_off + 4 <= len(data):
                    v = struct.unpack_from('<I', data, lit_off)[0]
                    if v == NOGZ_MAGIC:
                        return True
        return False

    def _range_has_nogz_magic_a64(self, start, end):
        data = self.data
        limit = min(end, len(data))
        magic_bytes = struct.pack('<I', NOGZ_MAGIC)
        if data.find(magic_bytes, start, limit) >= 0:
            return True
        for i in range(start, limit - 4, 4):
            insn = struct.unpack_from('<I', data, i)[0]
            # MOVZ Wd, #0x475A
            if (insn & 0xFFE00000) == 0x52800000:
                imm16 = (insn >> 5) & 0xFFFF
                rd = insn & 0x1F
                if imm16 == 0x475A:
                    for j in range(i + 4, min(i + 20, limit), 4):
                        insn2 = struct.unpack_from('<I', data, j)[0]
                        # MOVK Wd, #0x4E6F, LSL#16
                        if (insn2 & 0xFFE00000) == 0x72A00000:
                            rd2 = insn2 & 0x1F
                            imm16_2 = (insn2 >> 5) & 0xFFFF
                            if rd2 == rd and imm16_2 == 0x4E6F:
                                return True
            # LDR Wt, label (PC-relative literal)
            if (insn & 0xFF000000) == 0x18000000:
                imm19 = (insn >> 5) & 0x7FFFF
                imm19 = self._sign_ext(imm19, 19)
                lit_off = i + imm19 * 4
                if 0 <= lit_off < len(data) - 3:
                    v = struct.unpack_from('<I', data, lit_off)[0]
                    if v == NOGZ_MAGIC:
                        return True
        return False

    def func_has_nogz_magic(self, func_addr, search_range=256):
        if self.is_a64:
            return self._range_has_nogz_magic_a64(func_addr, func_addr + search_range)
        data = self.data
        end = min(func_addr + search_range, len(data) - 4)
        for i in range(func_addr, end, 2):
            w = struct.unpack_from('<H', data, i)[0]
            if (w & 0xF800) == 0x4800:
                imm = (w & 0xFF) * 4
                lit_off = ((i + 4) & ~3) + imm
                if lit_off + 4 <= len(data):
                    v = struct.unpack_from('<I', data, lit_off)[0]
                    if v == NOGZ_MAGIC:
                        return True
        return False

    def _count_nogz_movzk_a64(self):
        data = self.data
        start = self.code_start or 0
        limit = self._code_limit()
        count = 0
        for i in range(start, limit - 8, 4):
            insn = struct.unpack_from('<I', data, i)[0]
            if (insn & 0xFFE00000) != 0x52800000:
                continue
            imm16 = (insn >> 5) & 0xFFFF
            rd = insn & 0x1F
            if imm16 != 0x475A:
                continue
            for j in range(i + 4, min(i + 20, limit - 4), 4):
                insn2 = struct.unpack_from('<I', data, j)[0]
                if (insn2 & 0xFFE00000) == 0x72A00000:
                    rd2 = insn2 & 0x1F
                    imm16_2 = (insn2 >> 5) & 0xFFFF
                    if rd2 == rd and imm16_2 == 0x4E6F:
                        count += 1
                        break
        return count

    # ── halt_on_assert detection ──

    def find_halt_on_assert_in_func(self, func_addr, search_range=200):
        if self.is_a64:
            return self._find_halt_on_assert_in_func_a64(func_addr, search_range)
        data = self.data
        code_mem_end = self.file2mem(self._code_limit()) if self.base else 0x02080000
        i = func_addr
        end = min(func_addr + search_range, len(data) - 4)
        while i < end:
            w = struct.unpack_from('<H', data, i)[0]
            is_ldrb = False
            ldrb_rn = -1
            ldrb_size = 0

            if (w >> 11) >= 0x1D and i + 4 <= len(data):
                w2 = struct.unpack_from('<H', data, i + 2)[0]
                dw = (w << 16) | w2
                if (dw & 0xFFF08000) == 0xF8900000:
                    rn = (dw >> 16) & 0xF
                    imm = dw & 0xFFF
                    if imm == 0:
                        is_ldrb = True
                        ldrb_rn = rn
                        ldrb_size = 4
                i += 4
            else:
                if (w & 0xF800) == 0x7800:
                    imm5 = (w >> 6) & 0x1F
                    if imm5 == 0:
                        is_ldrb = True
                        ldrb_rn = (w >> 3) & 7
                        ldrb_size = 2
                i += 2

            if not is_ldrb:
                continue

            ldrb_off = i - ldrb_size
            cbz_off = ldrb_off + ldrb_size
            if cbz_off + 2 > end:
                continue
            nw = struct.unpack_from('<H', data, cbz_off)[0]
            is_cbz = (nw & 0xFD00) == 0xB100 or (nw & 0xFD00) == 0xB900
            if not is_cbz:
                continue

            for gap in range(2, 12, 2):
                ldr_off = ldrb_off - gap
                if ldr_off < func_addr:
                    continue
                sw = struct.unpack_from('<H', data, ldr_off)[0]
                if (sw & 0xF800) == 0x4800:
                    srt = (sw >> 8) & 7
                    if srt == ldrb_rn:
                        simm = (sw & 0xFF) * 4
                        lit_off = ((ldr_off + 4) & ~3) + simm
                        if lit_off + 4 <= len(data):
                            lit_val = struct.unpack_from('<I', data, lit_off)[0]
                            if not self.is_pic:
                                if lit_val >= code_mem_end:
                                    return lit_val
                            else:
                                for k in range(ldr_off + 2, ldrb_off, 2):
                                    kw = struct.unpack_from('<H', data, k)[0]
                                    if kw == 0x4478 + srt:
                                        mem_addr = (lit_val + (k + 4) + self.base) & 0xFFFFFFFF
                                        if mem_addr >= code_mem_end:
                                            return mem_addr
                                        break
                    break
                if (sw >> 11) >= 0x1D:
                    break
        return None

    def _find_halt_on_assert_in_func_a64(self, func_addr, search_range=200):
        data = self.data
        code_mem_end = self.file2mem(self._code_limit()) if self.base else 0x02080000
        limit = min(func_addr + search_range, len(data) - 4)
        adrp_regs = {}

        for i in range(func_addr, limit, 4):
            insn = struct.unpack_from('<I', data, i)[0]

            rd, page = self._decode_adrp(insn, i)
            if rd is not None:
                adrp_regs[rd] = page
                continue

            rd_a, rn_a, imm_a = self._decode_add_imm64(insn)
            if rd_a is not None and rn_a in adrp_regs:
                adrp_regs[rd_a] = (adrp_regs[rn_a] + imm_a) & 0xFFFFFFFF
                continue

            # LDRB Wt, [Xn, #imm12]
            if (insn & 0xFFC00000) == 0x39400000:
                rt = insn & 0x1F
                rn = (insn >> 5) & 0x1F
                imm12 = (insn >> 10) & 0xFFF
                if rn not in adrp_regs:
                    continue
                bss_addr = (adrp_regs[rn] + imm12) & 0xFFFFFFFF
                if bss_addr < code_mem_end:
                    continue
                if i + 4 < limit:
                    nxt = struct.unpack_from('<I', data, i + 4)[0]
                    # CBZ/CBNZ on rt
                    if (nxt & 0x7E000000) == 0x34000000 and (nxt & 0x1F) == rt:
                        return bss_addr

            if insn == 0xD65F03C0:  # RET
                break
        return None

    # ── Unconditional STRB #1 detection ──

    def check_unconditional_strb_one(self, bss_addr):
        if self.is_a64:
            return self._check_unconditional_strb_one_a64(bss_addr)
        data = self.data
        limit = self._code_limit()
        start = self.code_start or 0
        writers = []

        if not self.is_pic:
            addr_bytes = struct.pack('<I', bss_addr)
            pos = start
            while True:
                p = data.find(addr_bytes, pos, limit)
                if p < 0:
                    break
                for scan in range(max(start, p - 1024), p, 2):
                    w = struct.unpack_from('<H', data, scan)[0]
                    if (w & 0xF800) == 0x4800:
                        rt = (w >> 8) & 7
                        imm = (w & 0xFF) * 4
                        lit_off = ((scan + 4) & ~3) + imm
                        if lit_off == p:
                            if self._find_mov1_strb_after(scan, rt, 24):
                                writers.append(scan)
                            break
                pos = p + 1
        else:
            for i in range(start, limit - 6, 2):
                w = struct.unpack_from('<H', data, i)[0]
                if (w & 0xF800) != 0x4800:
                    continue
                rt = (w >> 8) & 7
                imm = (w & 0xFF) * 4
                lit_off = ((i + 4) & ~3) + imm
                if lit_off + 4 > limit:
                    continue
                lit_val = struct.unpack_from('<I', data, lit_off)[0]
                for j in range(i + 2, min(i + 8, limit - 2), 2):
                    nw = struct.unpack_from('<H', data, j)[0]
                    if nw == 0x4478 + rt:
                        resolved_mem = (lit_val + (j + 4) + self.base) & 0xFFFFFFFF
                        if resolved_mem == bss_addr:
                            if self._find_mov1_strb_after(i, rt, 24):
                                writers.append(i)
                        break
                    if (nw >> 11) >= 0x1D or (nw & 0xF800) == 0x4800:
                        break

        return writers

    def _check_unconditional_strb_one_a64(self, bss_addr):
        data = self.data
        start = self.code_start or 0
        limit = self._code_limit()
        target_page = bss_addr & ~0xFFF
        target_off = bss_addr & 0xFFF
        writers = []

        for i in range(start, limit - 4, 4):
            insn = struct.unpack_from('<I', data, i)[0]
            # STRB Wt, [Xn, #imm12]
            if (insn & 0xFFC00000) != 0x39000000:
                continue
            rn = (insn >> 5) & 0x1F
            rt = insn & 0x1F
            strb_imm12 = (insn >> 10) & 0xFFF

            adrp_found = False
            adrp_off = None
            for j in range(i - 4, max(i - 48, start - 4), -4):
                if j < start:
                    break
                prev = struct.unpack_from('<I', data, j)[0]
                # Direct ADRP → STRB
                rd_a, page = self._decode_adrp(prev, j)
                if rd_a is not None and rd_a == rn:
                    if page == target_page and strb_imm12 == target_off:
                        adrp_found = True
                        adrp_off = j
                    break
                # ADD between ADRP and STRB
                rd_add, rn_add, imm_add = self._decode_add_imm64(prev)
                if rd_add is not None and rd_add == rn:
                    for k in range(j - 4, max(j - 32, start - 4), -4):
                        if k < start:
                            break
                        prev2 = struct.unpack_from('<I', data, k)[0]
                        rd_a2, page2 = self._decode_adrp(prev2, k)
                        if rd_a2 is not None and rd_a2 == rn_add:
                            full_addr = (page2 + imm_add + strb_imm12) & 0xFFFFFFFF
                            if full_addr == bss_addr:
                                adrp_found = True
                                adrp_off = k
                            break
                    break

            if not adrp_found:
                continue

            search_start = max(adrp_off if adrp_off else i - 32, start)
            for m in range(search_start, i, 4):
                mv = struct.unpack_from('<I', data, m)[0]
                # MOVZ Wd, #1
                if (mv & 0xFFE00000) == 0x52800000:
                    mv_rd = mv & 0x1F
                    mv_imm = (mv >> 5) & 0xFFFF
                    if mv_rd == rt and mv_imm == 1:
                        writers.append(m)
                        break
                # ORR Wd, WZR, #1
                if (mv & 0xFF800000) == 0x32000000:
                    mv_rd = mv & 0x1F
                    n_bit = (mv >> 22) & 1
                    immr = (mv >> 16) & 0x3F
                    imms = (mv >> 10) & 0x3F
                    if mv_rd == rt and n_bit == 0 and immr == 0 and imms == 0:
                        writers.append(m)
                        break

        return writers

    def _find_mov1_strb_after(self, ldr_off, base_reg, max_search):
        data = self.data
        for ws in range(ldr_off + 2, min(ldr_off + max_search, len(data) - 2), 2):
            ww = struct.unpack_from('<H', data, ws)[0]
            if (ww & 0xF800) == 0x7000:
                w_rt = ww & 7
                w_rn = (ww >> 3) & 7
                w_imm = (ww >> 6) & 0x1F
                if w_rn == base_reg and w_imm == 0:
                    for ms in range(ldr_off, ws, 2):
                        mw = struct.unpack_from('<H', data, ms)[0]
                        if (mw & 0xFF00) == 0x2000:
                            mrd = (mw >> 8) & 7
                            mval = mw & 0xFF
                            if mrd == w_rt and mval == 1:
                                return True
            if (ww & 0xFF00) == 0xBD00:
                break
            if (ww & 0xFF00) == 0xB500:
                break
        return False

    # ── assert_fatal global scan ──

    def find_assert_fatal_global(self):
        if self.is_a64:
            return self._find_assert_fatal_global_a64()
        data = self.data
        code_mem_end = self.file2mem(self._code_limit()) if self.base else 0x02080000
        limit = self._code_limit()
        candidates = []

        i = self.code_start or 0
        while i < limit - 8:
            w = struct.unpack_from('<H', data, i)[0]

            if (w & 0xFF00) != 0xB500:
                i += 2
                continue

            hoa = self.find_halt_on_assert_in_func(i, search_range=80)
            if hoa is not None:
                candidates.append((i, hoa))

            i += 2

        for func_addr, hoa in candidates:
            for check in range(func_addr, min(func_addr + 80, limit - 4), 2):
                cw = struct.unpack_from('<H', data, check)[0]
                if (cw & 0xFF80) == 0x4780:
                    return func_addr, hoa
                if check + 4 <= limit:
                    cw2 = struct.unpack_from('<H', data, check + 2)[0]
                    cdw = (cw << 16) | cw2
                    if (cdw & 0xF800D000) == 0xF000D000:
                        pass

        if candidates:
            return candidates[0]
        return None, None

    def _find_assert_fatal_global_a64(self):
        data = self.data
        limit = self._code_limit()
        start = self.code_start or 0
        candidates = []

        for i in range(start, limit - 4, 4):
            insn = struct.unpack_from('<I', data, i)[0]
            # STP x29, x30, [sp, ...] — AArch64 function prologue
            lower15 = insn & 0x7FFF
            top10 = (insn >> 22) & 0x3FF
            if lower15 != 0x7BFD or top10 not in (0x2A4, 0x2A6):
                continue

            hoa = self._find_halt_on_assert_in_func_a64(i, search_range=80)
            if hoa is not None:
                candidates.append((i, hoa))

        for func_addr, hoa in candidates:
            for check in range(func_addr, min(func_addr + 80, limit - 4), 4):
                cinsn = struct.unpack_from('<I', data, check)[0]
                # BLR Xn (indirect call)
                if (cinsn & 0xFFFFFC1F) == 0xD63F0000:
                    return func_addr, hoa

        if candidates:
            return candidates[0]
        return None, None

    # ── Main analysis ──

    def analyze(self):
        results = {
            'file': os.path.basename(self.path),
            'file_size': len(self.data),
            'gfh_valid': False,
            'has_gz': False,
            'nogz_refs': 0,
            'halt_on_assert_forced': None,
            'bldr_load_gz_part': None,
            'assert_fatal_addr': None,
            'halt_on_assert_addr': None,
            'gpt_viable': None,
        }

        results['gfh_valid'] = self.parse_gfh()
        if results['gfh_valid']:
            results['base'] = f"0x{self.base:08X}"
            results['load_addr'] = f"0x{self.gfh_info['load_addr']:08X}"
            results['gfh_offset'] = self.gfh_offset
            results['code_start'] = f"0x{self.code_start:X}"
            results['content_offset'] = f"0x{self.gfh_info['content_offset']:X}"
            results['file_len'] = self.gfh_info['file_len']
            results['is_pic'] = self.is_pic
            results['is_a64'] = self.is_a64

        if not results['gfh_valid']:
            results['error'] = '非有效 MTK preloader (GFH 解析失败)'
            return results

        # GZ presence
        gz_indicators = [
            self.find_string(b'bldr_load_gz_part'),
            self.find_string(b'GZ fatal error'),
            self.find_string(b'gz_init'),
        ]
        results['has_gz'] = any(x is not None for x in gz_indicators)

        nogz_bytes = struct.pack('<I', NOGZ_MAGIC)
        nogz_positions = []
        pos = 0
        while True:
            p = self.data.find(nogz_bytes, pos, self._code_limit())
            if p < 0:
                break
            nogz_positions.append(p)
            pos = p + 1
        results['nogz_refs'] = len(nogz_positions)

        if self.is_a64:
            results['nogz_refs'] += self._count_nogz_movzk_a64()

        if not results['has_gz'] and results['nogz_refs'] == 0:
            results['error'] = '未检测到 GenieZone 代码'
            return results
        results['has_gz'] = True

        # Find bldr_load_gz_part via CMP #512 + conditional branch
        cmp_sites = self.find_cmp_512()
        results['cmp_512_count'] = len(cmp_sites)
        found_gz_func = False
        assert_in_error_path = False

        for cmp_off, cmp_rn in cmp_sites:
            br = self.find_conditional_branch(cmp_off + 4, max_bytes=16)
            if br is None:
                continue

            br_off, cond, br_target, br_size = br

            if cond == 1:  # BNE / CBNZ
                error_start = br_target
                error_end = br_target + 128
            elif cond == 0:  # BEQ / CBZ
                error_start = br_off + br_size
                error_end = min(br_target, br_off + br_size + 128)
            else:
                continue

            if not self.range_has_nogz_magic(error_start, error_end + 256):
                bl_targets_pre = self.find_bl_targets(error_start, error_end)
                found_in_bl = any(
                    t < len(self.data) and self.func_has_nogz_magic(t)
                    for _, t in bl_targets_pre
                )
                if not found_in_bl:
                    continue

            found_gz_func = True
            results['bldr_load_gz_part'] = f"0x{cmp_off:05X}"

            # Find assert_fatal in error path BL targets
            assert_in_error_path = False
            bl_targets = self.find_bl_targets(error_start, error_end)
            for bl_off, bl_target in bl_targets:
                if bl_target >= len(self.data):
                    continue
                if self.func_has_nogz_magic(bl_target):
                    results['set_nogz_addr'] = f"0x{bl_target:05X}"
                    continue
                hoa = self.find_halt_on_assert_in_func(bl_target)
                if hoa is not None:
                    assert_in_error_path = True
                    results['assert_fatal_addr'] = f"0x{bl_target:05X}"
                    results['halt_on_assert_addr'] = f"0x{hoa:08X}"
                    strb_sites = self.check_unconditional_strb_one(hoa)
                    results['halt_on_assert_forced'] = len(strb_sites) > 0
                    if strb_sites:
                        results['halt_on_assert_writers'] = [f"0x{s:05X}" for s in strb_sites]
                    break
            break

        # Fallback: global scan for halt_on_assert if not found via error path
        if found_gz_func and results.get('halt_on_assert_addr') is None:
            assert_in_error_path = False
            af_addr, hoa = self.find_assert_fatal_global()
            if af_addr is not None and hoa is not None:
                results['assert_fatal_addr'] = f"0x{af_addr:05X} (global)"
                results['halt_on_assert_addr'] = f"0x{hoa:08X}"
                strb_sites = self.check_unconditional_strb_one(hoa)
                results['halt_on_assert_forced'] = len(strb_sites) > 0
                if strb_sites:
                    results['halt_on_assert_writers'] = [f"0x{s:05X}" for s in strb_sites]

        results['assert_in_error_path'] = assert_in_error_path

        # GPT approach evaluation
        # halt_on_assert only blocks GPT when assert_fatal is in gz_init's
        # own error path. If found only via global scan, the error path
        # does not call assert_fatal and GPT manipulation is safe.
        if assert_in_error_path and results['halt_on_assert_forced'] is True:
            results['gpt_viable'] = False
        elif results['halt_on_assert_forced'] is False:
            results['gpt_viable'] = True
        elif not assert_in_error_path and found_gz_func:
            results['gpt_viable'] = True
        else:
            results['gpt_viable'] = None

        # ── Rename viability (primary + secondary cross-check) ──
        gz_str_offsets = self._find_bare_gz_strings()
        gz_total_refs = 0
        gz_ref_details = []
        for off in gz_str_offsets:
            refs = self.count_string_refs(off)
            gz_total_refs += refs
            gz_ref_details.append(f"0x{off:05X}({refs})")
        results['rename_gz_refs'] = gz_total_refs
        results['rename_gz_details'] = [d for d in gz_ref_details if not d.endswith('(0)')]

        boot_start, boot_end = self._find_main_boot_area()
        main_boot_gz = None
        if boot_start is not None:
            main_boot_gz = self._main_boot_has_gz_partition_ref(boot_start, boot_end)
            results['main_boot_area'] = f"0x{boot_start:05X}-0x{boot_end:05X}"
            results['main_boot_gz_ref'] = main_boot_gz

        if assert_in_error_path and results['halt_on_assert_forced'] is True:
            results['rename_viable'] = False
            results['rename_blocked_by_hoa'] = True
        elif gz_total_refs >= 2:
            results['rename_viable'] = False
        elif main_boot_gz is True:
            results['rename_viable'] = False
            results['rename_secondary'] = True
        elif gz_total_refs == 1 and main_boot_gz is False:
            results['rename_viable'] = True
        elif gz_total_refs == 1 and main_boot_gz is None:
            results['rename_viable'] = True
        elif gz_total_refs == 0 and main_boot_gz is False:
            results['rename_viable'] = True
            results['rename_secondary'] = True
        elif gz_total_refs == 0 and boot_start is not None:
            results['rename_viable'] = None
        else:
            results['rename_viable'] = None

        # ── Storage type & LBA risk ──
        has_ufs = any(self.data.find(s) >= 0
                      for s in [b'[UFS]', b'ufs_aio', b'UFS_'])
        has_emmc = any(self.data.find(s) >= 0
                       for s in [b'[eMMC]', b'emmc_', b'EMMC_'])
        results['storage_type'] = 'UFS' if has_ufs else ('eMMC' if has_emmc else None)
        lba_checks = []
        for s in [b'LBA out of range', b'lba_out_of_range',
                  b'ufs_aio_check_lba', b'invalid LBA', b'INVALID_LBA']:
            p = self.data.find(s)
            if p >= 0:
                lba_checks.append(f'"{s.decode()}" @0x{p:05X}')
        results['lba_risk'] = len(lba_checks) > 0
        results['lba_risk_strings'] = lba_checks
        results['lba_ufs_risk'] = has_ufs and results['lba_risk']

        return results


def print_results(r):
    print(f"\n{'='*60}")
    print(f"  {r['file']}")
    print(f"{'='*60}")

    print(f"\n文件大小: {r['file_size']:,} bytes ({r['file_size']/1024/1024:.1f} MB)")

    if not r['gfh_valid']:
        print(f"\n  错误: {r.get('error', '非有效 MTK preloader')}")
        return

    if r.get('is_a64'):
        arch_str = "AArch64"
    elif r.get('is_pic'):
        arch_str = "Thumb PIC"
    else:
        arch_str = "Thumb"
    gfh_off = r.get('gfh_offset', 0)
    gfh_str = f"  GFH偏移=0x{gfh_off:X}" if gfh_off > 0 else ""
    print(f"GFH: load_addr={r['load_addr']}  BASE={r['base']}  {arch_str}{gfh_str}")

    if not r['has_gz']:
        print(f"\n  未检测到 GenieZone 代码, 此 preloader 不加载 GZ")
        return

    print(f"\n  NoGZ: {r['nogz_refs']} 处", end="")
    if r.get('bldr_load_gz_part'):
        print(f"  CMP #512: {r['bldr_load_gz_part']}", end="")
    if r.get('set_nogz_addr'):
        print(f"  set_nogz: {r['set_nogz_addr']}", end="")
    print()

    if r.get('assert_fatal_addr'):
        print(f"  assert_fatal: {r['assert_fatal_addr']}", end="")
    if r.get('halt_on_assert_addr'):
        print(f"  halt_on_assert: {r['halt_on_assert_addr']}", end="")
    if r.get('halt_on_assert_writers'):
        print(f"  写入点: {', '.join(r['halt_on_assert_writers'])}", end="")
    print()

    gpt = r.get('gpt_viable')
    rename = r.get('rename_viable')
    lba_ufs_risk = r.get('lba_ufs_risk', False)
    storage = r.get('storage_type')

    assert_in_ep = r.get('assert_in_error_path', False)
    print(f"\n{'='*60}")
    print(f"  GPT 修改方案: {'可用' if gpt is True else '不可用' if gpt is False else '未知'}")
    if gpt is True and not assert_in_ep and r.get('halt_on_assert_forced') is True:
        print(f"  halt_on_assert 被置 1, 但 gz_init 错误路径不调用 assert_fatal")
    elif gpt is True:
        print(f"  halt_on_assert 未强制置 1, assert 非致命")
    elif gpt is False:
        print(f"  halt_on_assert 被无条件置 1, assert_fatal 在 gz_init 错误路径中")
    else:
        print(f"  无法自动检测 halt_on_assert 状态, 需手动分析")

    if storage:
        print(f"  存储类型: {storage}")

    gz_refs = r.get('rename_gz_refs', 0)
    gz_details = r.get('rename_gz_details', [])
    secondary = r.get('rename_secondary', False)
    main_boot_gz = r.get('main_boot_gz_ref')
    boot_area = r.get('main_boot_area', '?')
    blocked_by_hoa = r.get('rename_blocked_by_hoa', False)
    print(f"\n  重名方案 (gz→gx):", end="")
    if rename is True:
        print(f" 可行")
        if gz_refs > 0:
            print(f"    \"gz\" {gz_refs} 处代码引用 ({', '.join(gz_details)})")
        if main_boot_gz is False:
            print(f"    主引导函数 ({boot_area}) 无 gz 分区名引用")
        elif main_boot_gz is None and gz_refs <= 1:
            print(f"    仅 gz_init 引用, 主循环无硬依赖")
    elif rename is False:
        print(f" 不可行")
        if blocked_by_hoa:
            print(f"    halt_on_assert 被无条件置 1, 重名触发 assert_fatal → WDT reset")
        if gz_refs >= 2:
            print(f"    \"gz\" {gz_refs} 处代码引用 ({', '.join(gz_details)})")
        if main_boot_gz is True:
            print(f"    主引导函数 ({boot_area}) 包含 gz 分区名引用")
        if not blocked_by_hoa:
            print(f"    主引导循环依赖 gz 名称解析, 重名导致引导流水线中断")
    else:
        print(f" 未知 (未找到 \"gz\" 引用或使用内联构造)")

    print(f"  无效 LBA 欺骗:", end="")
    if not lba_ufs_risk:
        print(f"    可行")
    else:
        print(f"    有 UFS 越界风险")
        for s in r.get('lba_risk_strings', []):
            print(f"      {s}")
        print(f"    patch 设定的 LBA 若超出 UFS 容量, 控制器可能拒绝 I/O")

    print(f"\n{'='*60}")
    if gpt is False:
        print(f"  GPT 方案不可用 → 需修改 LK 或 bl2_ext 补丁 (v6 设备)")
    elif gpt is True or gpt is None:
        prefix = "推荐" if gpt is True else "如 GPT 可用"
        print(f"  {prefix}: 无效 LBA 方案 (只需修改 PGPT)")
        print(f"  python3 patch_gz_gpt.py <pgpt.bin>")
        if rename is True:
            print(f"  备选: 重名方案 (可能需同时修改 PGPT 和 SGPT)")
            print(f"  python3 patch_gz_gpt.py --rename <pgpt.bin> --sgpt <sgpt.bin>")
        elif rename is False:
            print(f"  重名方案: 不可行")
        else:
            print(f"  重名方案: 未知")

    print(f"\n  * 以上结果仅供参考, 实际可行性因固件版本和设备而异")
    print()


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <preloader.img> [preloader2.img ...]")
        print(f"\n分析 MediaTek preloader 固件, 检测可用的 GenieZone 绕过方案")
        print(f"支持 Thumb (PIC/非PIC) 和 AArch64 架构")
        sys.exit(1)

    for path in sys.argv[1:]:
        if not os.path.isfile(path):
            print(f"错误: 文件不存在: {path}")
            continue
        analyzer = PreloaderAnalyzer(path)
        results = analyzer.analyze()
        print_results(results)


if __name__ == '__main__':
    main()
