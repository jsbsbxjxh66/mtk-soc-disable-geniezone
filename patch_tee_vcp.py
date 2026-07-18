#!/usr/bin/env python3
"""
patch_tee_vcp.py - Patch MTK ATF (tee.img) to disable SMMU/EMI MPU for GZ bypass

When GenieZone (GZ) is disabled, two hardware protection systems cause boot
failures that must be patched in ATF:

A) SMMU: The protection page table (protpgd) has no valid entries -- GZ normally
   fills them at boot. Without valid entries, DMA through SMMU maps to PA=0x0,
   causing IOMMU translation faults / WDT resets.

B) EMI MPU: Domain 7 (VCP/APU) loses access to PROT_SHARED memory region
   because GZ normally proxied VCP memory requests. Without GZ, VCP hits EMI
   MPU violations directly, causing a 12K+ IRQ storm and kernel crash.

Three-layer patch:
  1. Global SMMU bypass: NOP the SMMU programming BL inside the protection
     function so ALL callers skip SMMU hardware configuration.
  2. VCP handler skip: patch vcp_smc_vcp_init to skip the protection call
     and jump to the existing "zero+succeed" path.
  3. EMI MPU domain 7 access: patch emi_mpu_config function entry to clear
     domain 7's APC bits (positions [15:14]) from the APC parameter, granting
     VCP/APU full access to all EMI MPU regions. This covers ALL callers:
     both ATF boot-time init (mpu_init chain) and runtime SMC handlers.

Usage:
    python3 patch_tee_vcp.py tee.img -o tee_patched.img
    python3 patch_tee_vcp.py tee.img --dry-run     # analysis only
    python3 patch_tee_vcp.py tee.img --restore      # revert patch

Note: do NOT use --patch-protpgd in detect_lk_gz.py together with this patch.
      The protpgd mblock allocation is no longer needed when SMMU is bypassed.
"""

import struct
import sys
import os
import argparse
import shutil

MTK_IMG_HDR_SIZE = 0x200
NOP = 0xD503201F
# AND Xd, X2, #0xFFFFFFFFFFFF3FFF -- clears bits [15:14] (domain 7 APC = "no protection")
# Base encoding for AND Xd, X2, #mask: 0x9270F440 | Rd
AND_XD_X2_CLR_D7_BASE = 0x9270F440
# MOV Xd, X2 base encoding: 0xAA0203E0 | Rd (for emi_mpu_config entry match)
MOV_XD_X2_BASE = 0xAA0203E0
# MOV X2, X3 -- SMC handler arg shift pattern (X2=APC from X3)
MOV_X2_X3 = 0xAA0303E2


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



class PatchSite:
    """Describes a located VCP SMMU protection patch site."""
    def __init__(self):
        self.anchor_off = None       # file offset of STR Wn, [Xm, #0xC]
        self.prot_rn = None          # register number for protection MMIO base
        self.bl_file_off = None      # file offset of the BL (or B if patched)
        self.skip_file_off = None    # file offset of skip path
        self.is_patched = False      # True if patch is already applied
        self.pre_ldr_offsets = []    # file offsets of LDR instructions before BL
        self.prot_func_file_off = None   # file offset of the protection function
        self.prot_prog_bl_off = None     # file offset of SMMU programming BL inside prot func


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
    #   Patched:  NOP; NOP; NOP; NOP; B
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
                        site.prot_func_file_off = bl_tgt + code_base
                        print("  [+] Original BL at file 0x%06X (code 0x%06X) → 0x%06X" %
                              (site.bl_file_off, bl_co, bl_tgt))
                        # Record LDR positions (two LDRs before the MOVZ)
                        for pre in [off - 8, off - 4]:
                            pw = read_u32(data, pre)
                            if (pw & 0xFFC00000) == 0xF9400000:
                                site.pre_ldr_offsets.append(pre)
                        found_original = True
                        break

        # Check for patched pattern: 4 NOPs + B (or old STP + 3 NOPs + B)
        if not found_patched:
            has_tail = (read_u32(data, off + 4) == NOP and
                        read_u32(data, off + 8) == NOP and
                        read_u32(data, off + 12) == NOP)
            if has_tail and (w == NOP or (w & 0xFF000000) == 0xA9000000):
                w_b = read_u32(data, off + 16)
                if (w_b & 0xFC000000) == 0x14000000:
                    site.bl_file_off = off + 16
                    site.is_patched = True
                    b_co = site.bl_file_off - code_base
                    b_tgt = decode_b_target(w_b, b_co)
                    print("  [+] Patch detected: B at file 0x%06X → skip 0x%06X" %
                          (site.bl_file_off, b_tgt))
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

    # --- Step 5: find the SMMU programming BL inside the protection function ---
    # The protection function has two BL calls:
    #   1st BL: validation/lookup (returns protpgd pointer)
    #   2nd BL: SMMU hardware programming (uses protpgd)
    # We replace the 2nd BL with MOVZ W0,#0 so ALL callers skip SMMU config.
    if site.prot_func_file_off is not None:
        bl_count = 0
        for off in range(site.prot_func_file_off, site.prot_func_file_off + 0x80, 4):
            if off + 4 > len(data):
                break
            w = read_u32(data, off)
            if (w & 0xFC000000) == 0x94000000:  # BL
                bl_count += 1
                if bl_count == 2:
                    site.prot_prog_bl_off = off
                    prog_co = off - code_base
                    prog_tgt = decode_bl_target(w, prog_co)
                    print("  [+] Protection func programming BL at file 0x%06X → 0x%06X" %
                          (off, prog_tgt))
                    break
            elif w == 0xD65F03C0:  # RET
                break
        if site.prot_prog_bl_off is None:
            print("  [!] Warning: could not find programming BL in protection function")

    return site


def find_emi_mpu_entry_patch(data):
    """
    Find emi_mpu_config function entry and the MOV Xd, X2 that saves the APC
    parameter to a callee-saved register. Patching this single instruction
    covers ALL callers: both ATF boot-time init (mpu_init → sub_fce0) and
    runtime SMC handlers.

    Discovery:
    1. Find MOV X0,X1; MOV X1,X2; *; B <target> patterns (SMC handler sites)
    2. Group by B target; the target with >=2 callers is emi_mpu_config
    3. At emi_mpu_config entry, find MOV Xd, X2 (Xd in X19-X28) in first 12 insns
    4. Return patch: MOV Xd, X2 → AND Xd, X2, #0xFFFFFFFFFFFF3FFF

    Returns (file_off, orig_word, patch_word) or None.
    """
    code_base = MTK_IMG_HDR_SIZE
    pattern = struct.pack('<III', 0xAA0103E0, 0xAA0203E1, MOV_X2_X3)

    candidates = []
    pos = code_base
    while True:
        idx = data.find(pattern, pos)
        if idx < 0:
            break
        b_off = idx + 12
        if b_off + 4 <= len(data):
            w = read_u32(data, b_off)
            if (w & 0xFC000000) == 0x14000000:
                imm = w & 0x3FFFFFF
                if imm & 0x2000000:
                    imm -= 0x4000000
                b_foff = b_off + imm * 4
                candidates.append((idx, b_foff))
        pos = idx + 4

    if not candidates:
        print("  [!] No EMI MPU handler sites found (can't locate emi_mpu_config)")
        return None

    from collections import Counter
    tgt_counts = Counter(tgt for _, tgt in candidates)
    best_tgt, best_count = tgt_counts.most_common(1)[0]

    if best_count < 2:
        print("  [!] No shared emi_mpu_config target among %d candidates" %
              len(candidates))
        return None

    print("  [+] emi_mpu_config at file 0x%06X (found via %d SMC handler B sites)" %
          (best_tgt, best_count))

    for i in range(12):
        addr = best_tgt + i * 4
        if addr + 4 > len(data):
            break
        w = read_u32(data, addr)
        rd = w & 0x1F

        if (w & 0xFFFFFFE0) == MOV_XD_X2_BASE and 19 <= rd <= 28:
            patch_word = AND_XD_X2_CLR_D7_BASE | rd
            print("  [+] MOV X%d, X2 at file 0x%06X (entry +%d)" % (rd, addr, i * 4))
            return (addr, w, patch_word)

        if (w & 0xFFFFFFE0) == AND_XD_X2_CLR_D7_BASE and 19 <= rd <= 28:
            orig_word = MOV_XD_X2_BASE | rd
            print("  [+] AND X%d, X2, #~0xC000 at file 0x%06X (entry +%d) [already patched]" %
                  (rd, addr, i * 4))
            return (addr, orig_word, w)

    print("  [!] Could not find MOV Xd, X2 at emi_mpu_config entry")
    return None


def build_patches(data, site, emi_entry=None):
    """
    Build patch entries: list of (file_offset, original_4bytes, patched_4bytes, desc).

    Three patch groups:
      A) Global: inside the protection function, NOP the SMMU programming BL
         so ALL callers skip actual SMMU hardware configuration.
      B) VCP handler: replace 5 instructions ending at the BL to skip the
         protection call entirely and jump to the zero+succeed path.
      C) EMI MPU: patch emi_mpu_config entry MOV Xd,X2 → AND Xd,X2,#~0xC000
         to clear domain 7 APC bits for ALL callers.
    """
    code_base = MTK_IMG_HDR_SIZE
    patches = []

    if site.is_patched:
        raise RuntimeError(
            "Cannot auto-restore: original BL target address is lost.\n"
            "  Use the original unpatched tee.img to restore.")

    # --- Group A: Global SMMU programming bypass ---
    # Replace the programming BL with MOVZ W0, #0 (report success, skip SMMU config)
    # In this ATF, return 0 = success for the programming sub-function.
    if site.prot_prog_bl_off is not None:
        MOVZ_W0_0 = 0x52800000
        foff = site.prot_prog_bl_off
        orig_bytes = data[foff:foff + 4]
        patches.append((foff, orig_bytes, struct.pack('<I', MOVZ_W0_0),
                         "MOVZ W0, #0 (skip SMMU programming, report success)"))

    # --- Group B: VCP handler skip ---
    # Replace 4 arg-setup instructions + BL with NOPs + B to skip_path.
    # skip_path already zeros the protection registers and returns success.
    # NOTE: do NOT use STP here -- X24 points to MMIO at non-8-byte-aligned
    # address (e.g. 0x1EA00014), causing alignment fault in EL3.
    b_word = encode_b(site.bl_file_off - code_base,
                       site.skip_file_off - code_base)

    vcp_descs = [
        (site.bl_file_off - 16,
         NOP,
         "NOP (was LDR X0)"),
        (site.bl_file_off - 12,
         NOP,
         "NOP (was LDR X1)"),
        (site.bl_file_off - 8,
         NOP,
         "NOP (was MOVZ W3)"),
        (site.bl_file_off - 4,
         NOP,
         "NOP (was MOV W2)"),
        (site.bl_file_off,
         b_word,
         "B 0x%06X (skip to zero+succeed)" % (site.skip_file_off - code_base)),
    ]

    for foff, patch_word, desc in vcp_descs:
        orig_bytes = data[foff:foff + 4]
        patches.append((foff, orig_bytes, struct.pack('<I', patch_word), desc))

    # --- Group C: EMI MPU domain 7 access ---
    if emi_entry is not None:
        foff, orig_word, patch_word = emi_entry
        rd = orig_word & 0x1F
        patches.append((foff, struct.pack('<I', orig_word), struct.pack('<I', patch_word),
                         "AND X%d, X2, #~0xC000 (clear domain 7 APC in emi_mpu_config)" % rd))

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

    print("[*] Searching for EMI MPU emi_mpu_config entry...")
    emi_entry = find_emi_mpu_entry_patch(data)

    if site.is_patched:
        print()
        if args.restore:
            print("[!] Auto-restore is not supported — the original BL target cannot be recovered.")
            print("    To restore, re-flash the original (unpatched) tee.img.")
            return 1
        print("[*] Patch already applied. Nothing to do.")
        print("    To restore, re-flash the original (unpatched) tee.img.")
        return 0

    print("[*] Building patch...")
    try:
        patches = build_patches(data, site, emi_entry)
    except RuntimeError as e:
        print("[!] %s" % e)
        return 1

    state = verify_state(data, patches)

    print()
    has_global = site.prot_prog_bl_off is not None
    has_emi = emi_entry is not None
    n_layers = 1 + int(has_global) + int(has_emi)
    print("  Patch plan (%d instructions, %d layers):" % (len(patches), n_layers))
    print("  %-12s  %-10s  %-10s  %s" %
          ("File offset", "Original", "Patched", "Description"))
    print("  " + "-" * 72)
    layer1_count = 1 if has_global else 0
    layer2_count = 5
    layer3_start = layer1_count + layer2_count
    if has_global:
        print("  --- Layer 1: global SMMU programming bypass ---")
    for i, (foff, orig, patch, desc) in enumerate(patches):
        if has_global and i == 1:
            print("  --- Layer 2: VCP handler skip ---")
        if has_emi and i == layer3_start:
            print("  --- Layer 3: EMI MPU domain 7 access ---")
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
        print("    Layer 1 (global): SMMU programming function always reports success")
        print("      → no SMMU hardware configured with empty protpgd for ANY subsystem")
        print("      → covers iommu_secure init, cmdq, display, and VCP IOMMU banks")
        print("    Layer 2 (VCP handler): vcp_smc_vcp_init skips protection call")
        print("      → zeros SMMU protection registers")
        print("      → jumps to existing zero+succeed path")
        print("      → VCP init returns success without processing protpgd pointer")
        if has_emi:
            print("    Layer 3 (EMI MPU): domain 7 APC bits cleared at emi_mpu_config entry")
            print("      → covers ALL callers: ATF boot init AND runtime SMC handlers")
            print("      → VCP/APU (domain 7) gets full access to all EMI MPU regions")
            print("      → prevents 12K+ EMI MPU violation IRQ storm on PROT_SHARED")
        print()
        print("  All devices use only the kernel's M4U IOMMU (no secure SMMU protection).")
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
