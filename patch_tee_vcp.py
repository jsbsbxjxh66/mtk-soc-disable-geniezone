#!/usr/bin/env python3
"""
patch_tee_vcp.py - Patch MTK ATF (tee.img) to skip VCP SMMU protection setup

When GenieZone (GZ) is disabled, the SMMU protection page table (protpgd) has
no valid entries -- GZ normally fills them at boot. Without valid entries, VCP
DMA maps to PA=0x0, causing infinite IOMMU translation fault / WDT resets.

This script patches ATF's vcp_smc_vcp_init to skip the SMMU protection setup
call, zero the protection registers, and continue to the existing "skip+succeed"
code path. VCP then runs with only the kernel's M4U IOMMU (which works fine).

Usage:
    python3 patch_tee_vcp.py tee.img -o tee_patched.img
    python3 patch_tee_vcp.py tee.img --dry-run     # analysis only
    python3 patch_tee_vcp.py tee.img --restore      # revert patch

Note: do NOT use --patch-protpgd in detect_lk_gz.py together with this patch.
      The protpgd mblock is no longer needed when the SMMU protection is skipped.
"""

import struct
import sys
import os
import argparse
import shutil

MTK_IMG_HDR_SIZE = 0x200
NOP = 0xD503201F


def read_u32(data, off):
    return struct.unpack_from('<I', data, off)[0]


def decode_bl_target(word, code_off):
    if (word & 0xFC000000) != 0x94000000:
        return None
    imm = word & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    return code_off + imm * 4


def decode_b_target(word, code_off):
    if (word & 0xFC000000) != 0x14000000:
        return None
    imm = word & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    return code_off + imm * 4


def encode_b(src_code_off, dst_code_off):
    offset = (dst_code_off - src_code_off) // 4
    return 0x14000000 | (offset & 0x03FFFFFF)


def encode_stp_xzr_xzr(rn, simm7):
    """STP XZR, XZR, [Xn, #simm7*8] signed-offset form."""
    return 0xA9000000 | ((simm7 & 0x7F) << 15) | (31 << 10) | (rn << 5) | 31


class PatchSite:
    """Describes a located VCP SMMU protection patch site."""
    def __init__(self):
        self.anchor_off = None       # file offset of STR Wn, [Xm, #0xC]
        self.prot_rn = None          # register number for protection MMIO base
        self.bl_file_off = None      # file offset of the BL (or B if patched)
        self.skip_file_off = None    # file offset of skip path
        self.is_patched = False      # True if patch is already applied
        self.pre_ldr_offsets = []    # file offsets of LDR instructions before BL


def find_vcp_anchor(data):
    """
    Find the VCP SMMU protection call site using a device-independent strategy:
    1. Locate 'vcp_smc_vcp_init' string as a proximity hint
    2. Find MOVZ Wrt, #0x38 + STR Wrt, [Xrn, #0xC] (protection register write)
    3. From that anchor, locate the protection BL or patched B
    4. Locate the skip path (STR WZR + STUR XZR)
    """
    code_base = MTK_IMG_HDR_SIZE
    site = PatchSite()

    # --- Step 1: find the function string for proximity filtering ---
    str_idx = data.find(b'vcp_smc_vcp_init\x00')
    if str_idx < 0:
        # Try alternative string names on different platforms
        for alt in [b'vcp_init\x00', b'smc_vcp_init\x00']:
            str_idx = data.find(alt)
            if str_idx >= 0:
                break
    str_name = 'vcp_smc_vcp_init'
    if str_idx >= 0:
        found_str = data[str_idx:data.index(b'\x00', str_idx)].decode('ascii', errors='replace')
        print("  [+] String '%s' at file 0x%06X" % (found_str, str_idx))
    else:
        print("  [!] String '%s' not found, searching by pattern only" % str_name)

    # --- Step 2: find MOVZ Wrt, #0x38 + STR Wrt, [Xrn, #0xC] ---
    # MOVZ W?, #0x38: 0x52800700 | Rd (bits 0-4)
    # STR  W?, [X?, #0xC]: 0xB9000C00 | (Rn << 5) | Rt, where Rt == MOVZ.Rd
    # (imm12 in STR W is scaled by 4, so #0xC → field = 3, at bits 21-10)
    anchors = []
    for off in range(code_base, len(data) - 8, 4):
        w0 = read_u32(data, off)
        w1 = read_u32(data, off + 4)
        if (w0 & 0xFFFFFFE0) != 0x52800700:
            continue
        movz_rd = w0 & 0x1F
        if (w1 & 0xFFFFFC00) != 0xB9000C00:
            continue
        str_rt = w1 & 0x1F
        if str_rt != movz_rd:
            continue
        str_rn = (w1 >> 5) & 0x1F
        anchors.append((off + 4, str_rn))  # (STR file offset, protection reg)

    if not anchors:
        raise RuntimeError("MOVZ #0x38 + STR [Xn, #0xC] pattern not found")

    # Pick the anchor closest to the string reference (if available)
    if str_idx >= 0 and len(anchors) > 1:
        anchors.sort(key=lambda a: abs(a[0] - str_idx))

    site.anchor_off, site.prot_rn = anchors[0]
    print("  [+] Anchor: STR W?, [X%d, #0xC] at file 0x%06X" %
          (site.prot_rn, site.anchor_off))

    # --- Step 3: search forward for protection BL or patched B ---
    # Look for either:
    #   Original: LDR; LDR; MOVZ W3,#1; MOV W2,WZR; BL; CBZ X0
    #   Patched:  STP XZR,XZR,[Xn,#-16]; NOP; NOP; NOP; B
    stp_expected = encode_stp_xzr_xzr(site.prot_rn, (-16 // 8) & 0x7F)

    found_original = False
    found_patched = False
    scan_start = site.anchor_off + 4
    scan_end = min(site.anchor_off + 128, len(data) - 20)

    for off in range(scan_start, scan_end, 4):
        w = read_u32(data, off)

        # Check for original pattern: MOVZ W3, #1 (0x52800023)
        if w == 0x52800023 and not found_original:
            w_next = read_u32(data, off + 4)
            if w_next == 0x2A1F03E2:  # MOV W2, WZR
                w_bl = read_u32(data, off + 8)
                if (w_bl & 0xFC000000) == 0x94000000:  # BL
                    w_cbz = read_u32(data, off + 12)
                    if (w_cbz & 0xFF00001F) == 0xB4000000:  # CBZ X0
                        site.bl_file_off = off + 8
                        bl_co = site.bl_file_off - code_base
                        bl_tgt = decode_bl_target(w_bl, bl_co)
                        print("  [+] Original BL at file 0x%06X (code 0x%06X) → 0x%06X" %
                              (site.bl_file_off, bl_co, bl_tgt))
                        # Record LDR positions (two LDRs before the MOVZ)
                        for pre in [off - 8, off - 4]:
                            pw = read_u32(data, pre)
                            if (pw & 0xFFC00000) == 0xF9400000:
                                site.pre_ldr_offsets.append(pre)
                        found_original = True
                        break

        # Check for patched pattern: STP XZR,XZR,[Xn,#-16]
        if w == stp_expected and not found_patched:
            if (read_u32(data, off + 4) == NOP and
                read_u32(data, off + 8) == NOP and
                read_u32(data, off + 12) == NOP):
                w_b = read_u32(data, off + 16)
                if (w_b & 0xFC000000) == 0x14000000:
                    site.bl_file_off = off + 16
                    site.is_patched = True
                    b_co = site.bl_file_off - code_base
                    b_tgt = decode_b_target(w_b, b_co)
                    print("  [+] Patch detected: B at file 0x%06X → skip 0x%06X" %
                          (site.bl_file_off, b_tgt))
                    # Recover original LDR offsets from before the STP
                    for pre in [off - 8, off - 4]:
                        if pre >= code_base:
                            site.pre_ldr_offsets.append(pre)
                    found_patched = True
                    break

    if not found_original and not found_patched:
        raise RuntimeError(
            "Neither original BL nor patched B found after anchor at 0x%06X" %
            site.anchor_off)

    # --- Step 4: find skip path ---
    # STR WZR, [Xn, #0]: 0xB900001F | (Rn << 5)
    # STUR XZR, [Xn, #4]: 0xF8000000 | (4 << 12) | (Rn << 5) | 0x1F
    exp_str = 0xB900001F | (site.prot_rn << 5)
    exp_stur = 0xF8000000 | (4 << 12) | (site.prot_rn << 5) | 0x1F

    search_from = site.bl_file_off
    for off in range(search_from, search_from + 0x200, 4):
        if off + 8 > len(data):
            break
        if read_u32(data, off) == exp_str and read_u32(data, off + 4) == exp_stur:
            site.skip_file_off = off
            print("  [+] Skip path at file 0x%06X (code 0x%06X)" %
                  (off, off - code_base))
            break

    if site.skip_file_off is None:
        raise RuntimeError("Skip path (STR WZR + STUR XZR with X%d) not found" %
                           site.prot_rn)

    return site


def build_patches(data, site):
    """
    Build patch entries: list of (file_offset, original_4bytes, patched_4bytes, desc).

    Patch layout (replacing 5 instructions ending at the BL):
      BL-16: [LDR]  →  STP XZR, XZR, [Xn, #-16]   (zero protection regs)
      BL-12: [LDR]  →  NOP
      BL-8:  MOVZ   →  NOP
      BL-4:  MOV    →  NOP
      BL:    BL     →  B <skip_path>
    """
    code_base = MTK_IMG_HDR_SIZE
    patches = []

    stp_word = encode_stp_xzr_xzr(site.prot_rn, (-16 // 8) & 0x7F)
    b_word = encode_b(site.bl_file_off - code_base,
                       site.skip_file_off - code_base)

    offsets_and_descs = [
        (site.bl_file_off - 16,
         stp_word,
         "STP XZR, XZR, [X%d, #-16] (zero protect regs)" % site.prot_rn),
        (site.bl_file_off - 12,
         NOP,
         "NOP"),
        (site.bl_file_off - 8,
         NOP,
         "NOP"),
        (site.bl_file_off - 4,
         NOP,
         "NOP"),
        (site.bl_file_off,
         b_word,
         "B 0x%06X (skip to zero+succeed)" % (site.skip_file_off - code_base)),
    ]

    if site.is_patched:
        # For restore: the "original" is what we want to restore TO,
        # and "patched" is what's currently there.
        # We need the original bytes -- they were saved during patching? No.
        # We can't restore without knowing the original bytes.
        # BUT: we know the pattern:
        #   Original[-16]: LDR X?, [X?, #imm] → we stored offsets in pre_ldr_offsets
        #   Original[-12]: LDR X?, [X?, #imm]
        #   Original[-8]:  MOVZ W3, #1 = 0x52800023
        #   Original[-4]:  MOV W2, WZR = 0x2A1F03E2
        #   Original[0]:   BL <addr> → we can't recover the target!
        raise RuntimeError(
            "Cannot auto-restore: original BL target address is lost.\n"
            "  Use the original unpatched tee.img to restore.")

    for foff, patch_word, desc in offsets_and_descs:
        orig_bytes = data[foff:foff + 4]
        patches.append((foff, orig_bytes, struct.pack('<I', patch_word), desc))

    return patches


def verify_state(data, patches):
    """
    Returns:
      'original'  -- all original bytes match
      'patched'   -- all patched bytes match
      'unknown'   -- mixed or neither
    """
    orig_match = all(data[off:off+4] == orig for off, orig, patch, _ in patches)
    patch_match = all(data[off:off+4] == patch for off, orig, patch, _ in patches)
    if orig_match:
        return 'original'
    if patch_match:
        return 'patched'
    return 'unknown'


def apply_patches(data, patches):
    buf = bytearray(data)
    for foff, orig, patch, desc in patches:
        actual = buf[foff:foff + 4]
        if actual != orig:
            raise RuntimeError(
                "Byte mismatch at 0x%06X: expected %s, got %s" %
                (foff, orig.hex(), actual.hex()))
        buf[foff:foff + 4] = patch
    return bytes(buf)


def restore_patches(data, patches):
    buf = bytearray(data)
    for foff, orig, patch, desc in patches:
        actual = buf[foff:foff + 4]
        if actual != patch:
            raise RuntimeError(
                "Cannot restore at 0x%06X: expected %s, got %s" %
                (foff, patch.hex(), actual.hex()))
        buf[foff:foff + 4] = orig
    return bytes(buf)


def main():
    parser = argparse.ArgumentParser(
        description="Patch MTK ATF (tee.img) to skip VCP SMMU protection setup",
        epilog="""
This patch allows VCP to function when GenieZone is disabled.
Without GZ, the SMMU protection page table has no valid entries,
causing VCP DMA translation faults. The patch skips the protection
setup so VCP uses only the kernel's IOMMU (which is properly configured).

IMPORTANT: Do NOT use --patch-protpgd when this ATF patch is applied.
           The protpgd mblock allocation is no longer needed.

Detection strategy (device-independent):
  1. Find 'vcp_smc_vcp_init' string as proximity hint
  2. Locate MOVZ Wn,#0x38 + STR Wn,[Xm,#0xC] (VCP MMIO register write)
  3. Search forward for MOVZ W3,#1; MOV W2,WZR; BL (protection call)
  4. Find STR WZR,[Xm,#0]; STUR XZR,[Xm,#4] (skip/zero path)
""",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('input', help='Input tee.img file')
    parser.add_argument('-o', '--output', help='Output patched file (default: overwrite input)')
    parser.add_argument('--dry-run', action='store_true',
                        help='Analyze only, do not write')
    parser.add_argument('--restore', action='store_true',
                        help='Restore original bytes (revert patch)')

    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print("Error: file not found: %s" % args.input)
        return 1

    data = open(args.input, 'rb').read()
    print("[*] Loaded %s (%d bytes)" % (args.input, len(data)))

    if len(data) < MTK_IMG_HDR_SIZE + 0x100:
        print("Error: file too small for tee.img")
        return 1

    magic = data[0:4]
    if magic != b'\x88\x16\x88\x58':
        print("[!] Warning: unexpected MTK header magic: %s" % magic.hex())

    print("[*] Searching for VCP SMMU protection call site...")
    try:
        site = find_vcp_anchor(data)
    except RuntimeError as e:
        print("[!] %s" % e)
        return 1

    if site.is_patched:
        print()
        if args.restore:
            print("[!] Auto-restore is not supported — the original BL target cannot be recovered.")
            print("    To restore, re-flash the original (unpatched) tee.img.")
            return 1
        print("[*] Patch is already applied. Nothing to do.")
        print("    To re-flash original, use the unpatched tee.img.")
        return 0

    print("[*] Building patch...")
    try:
        patches = build_patches(data, site)
    except RuntimeError as e:
        print("[!] %s" % e)
        return 1

    state = verify_state(data, patches)

    print()
    print("  Patch plan (%d instructions):" % len(patches))
    print("  %-12s  %-10s  %-10s  %s" %
          ("File offset", "Original", "Patched", "Description"))
    print("  " + "-" * 72)
    for foff, orig, patch, desc in patches:
        actual = data[foff:foff + 4]
        marker = ""
        if actual == patch:
            marker = " [already patched]"
        elif actual != orig:
            marker = " [MISMATCH: %s]" % actual.hex()
        print("  0x%06X      %s      %s      %s%s" %
              (foff, orig.hex(), patch.hex(), desc, marker))

    if state == 'patched':
        print()
        if args.restore:
            print("[*] Restoring original bytes...")
            if args.dry_run:
                print("[*] Dry run — not writing.")
                return 0
            result = restore_patches(data, patches)
            out_path = args.output or args.input
            if out_path == args.input:
                shutil.copy2(args.input, args.input + '.bak')
                print("[*] Backup: %s.bak" % args.input)
            open(out_path, 'wb').write(result)
            print("[+] Restored to: %s" % out_path)
            return 0
        print("[*] Patch is already applied. Nothing to do.")
        print("    Use --restore to revert.")
        return 0

    if state == 'unknown':
        print()
        print("[!] Bytes at patch site don't match expected original or patched values.")
        print("    This tee.img may be from a different firmware version or partially patched.")
        return 1

    if args.restore:
        print()
        print("[!] Patch is not applied, nothing to restore.")
        return 0

    if args.dry_run:
        print()
        print("[*] Dry run — patch verification passed, not writing.")
        print()
        print("  Effect when applied:")
        print("    1. Zero SMMU protection registers at [X%d-16 .. X%d-1]" %
              (site.prot_rn, site.prot_rn))
        print("    2. Skip BL to protection setup function")
        print("    3. Jump to existing zero+succeed path")
        print("    4. VCP init returns success without SMMU protection")
        print()
        print("  VCP will use only the kernel's M4U IOMMU (no secure SMMU protection).")
        print("  Do NOT use --patch-protpgd with this patch.")
        return 0

    print()
    print("[*] Applying patch...")
    result = apply_patches(data, patches)
    out_path = args.output or args.input
    if out_path == args.input:
        shutil.copy2(args.input, args.input + '.bak')
        print("[*] Backup: %s.bak" % args.input)
    open(out_path, 'wb').write(result)
    print("[+] Patched tee.img written to: %s" % out_path)
    print()
    print("[!] IMPORTANT:")
    print("    - This patch is specific to this firmware's ATF binary")
    print("    - Do NOT use --patch-protpgd in detect_lk_gz.py")
    print("    - VCP DMA will not be SMMU-protected (acceptable when GZ is disabled)")
    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)
