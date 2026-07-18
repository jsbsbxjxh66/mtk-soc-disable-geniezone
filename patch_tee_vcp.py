#!/usr/bin/env python3
"""
patch_tee_vcp.py - Patch MTK ATF (tee.img) to disable SMMU/DEVMPU for GZ bypass

When GenieZone (GZ) is disabled, two hardware protection systems cause boot
failures that must be patched in ATF:

A) SMMU: The protection page table (protpgd) has no valid entries -- GZ normally
   fills them at boot. Without valid entries, DMA through SMMU maps to PA=0x0,
   causing IOMMU translation faults / WDT resets.

B) DEVMPU: Domain 7 (VCP/APU) loses access to PROT_SHARED memory region
   (region 10) because GZ normally proxied VCP memory requests. Without GZ,
   the DEVMPU (Device Memory Protection Unit) at 0x10351000/0x10355000
   enforces access restrictions set by the preloader, causing a 12K+ violation
   IRQ storm and HWT kernel crash ~33 seconds after boot.

Three-layer patch:
  1. Global SMMU bypass: NOP the SMMU programming BL inside the protection
     function so ALL callers skip SMMU hardware configuration.
  2. VCP handler skip: patch vcp_smc_vcp_init to skip the protection call
     and jump to the existing "zero+succeed" path.
  3. DEVMPU reset: inject a devmpu_reset call (write 7 then 1 to control
     registers 0x10351104/0x10355104) into the DEVMPU init function via a
     trampoline in a code cave. This clears ALL DEVMPU APC (access permission
     control) values set by the preloader, including domain 7's restriction
     on PROT_SHARED (region 10). After reset, only region boundaries are
     reprogrammed (no APC restrictions), so VCP/APU get unrestricted access.

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

DEVMPU_INIT_SIG_0 = 0x52822308   # MOVZ W8, #0x1118 (DEVMPU ch0 enable register low)
DEVMPU_INIT_SIG_1 = 0x528A230A   # MOVZ W10, #0x5118 (DEVMPU ch1 enable register low)
DEVMPU_ENABLE_STR = 0xB9000109   # STR W9, [X8] (write 1 to enable register)

TRAMPOLINE_INSNS = [
    (0xA9BF2BE8, "STP X8, X10, [SP, #-0x10]!"),
    (0x52822088, "MOVZ W8, #0x1104"),
    (0x528A208B, "MOVZ W11, #0x5104"),
    (0x72A206A8, "MOVK W8, #0x1035, LSL#16"),
    (0x528000E9, "MOVZ W9, #7"),
    (0x5280002A, "MOVZ W10, #1"),
    (0x72A206AB, "MOVK W11, #0x1035, LSL#16"),
    (0xB9000109, "STR W9, [X8]"),
    (0xB900010A, "STR W10, [X8]"),
    (0xB9000169, "STR W9, [X11]"),
    (0xB900016A, "STR W10, [X11]"),
    (0xA8C12BE8, "LDP X8, X10, [SP], #0x10"),
    (0x52800029, "MOVZ W9, #1"),
    (0xB9000109, "STR W9, [X8]"),
    (0xD65F03C0, "RET"),
]


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


def encode_bl(src_code_off, dst_code_off):
    offset = (dst_code_off - src_code_off) // 4
    return 0x94000000 | (offset & 0x03FFFFFF)


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
        anchors.append((off + 4, str_rn))

    if not anchors:
        raise RuntimeError("MOVZ #0x38 + STR [Xn, #0xC] pattern not found")

    if str_idx >= 0 and len(anchors) > 1:
        anchors.sort(key=lambda a: abs(a[0] - str_idx))

    site.anchor_off, site.prot_rn = anchors[0]
    print("  [+] Anchor: STR W?, [X%d, #0xC] at file 0x%06X" %
          (site.prot_rn, site.anchor_off))

    # --- Step 3: search forward for protection BL or patched B ---
    found_original = False
    found_patched = False
    scan_start = site.anchor_off + 4
    scan_end = min(site.anchor_off + 128, len(data) - 20)

    for off in range(scan_start, scan_end, 4):
        w = read_u32(data, off)

        if w == 0x52800023 and not found_original:
            w_next = read_u32(data, off + 4)
            if w_next == 0x2A1F03E2:
                w_bl = read_u32(data, off + 8)
                if (w_bl & 0xFC000000) == 0x94000000:
                    w_cbz = read_u32(data, off + 12)
                    if (w_cbz & 0xFF00001F) == 0xB4000000:
                        site.bl_file_off = off + 8
                        bl_co = site.bl_file_off - code_base
                        bl_tgt = decode_bl_target(w_bl, bl_co)
                        site.prot_func_file_off = bl_tgt + code_base
                        print("  [+] Original BL at file 0x%06X (code 0x%06X) → 0x%06X" %
                              (site.bl_file_off, bl_co, bl_tgt))
                        for pre in [off - 8, off - 4]:
                            pw = read_u32(data, pre)
                            if (pw & 0xFFC00000) == 0xF9400000:
                                site.pre_ldr_offsets.append(pre)
                        found_original = True
                        break

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
    if site.prot_func_file_off is not None:
        bl_count = 0
        for off in range(site.prot_func_file_off, site.prot_func_file_off + 0x80, 4):
            if off + 4 > len(data):
                break
            w = read_u32(data, off)
            if (w & 0xFC000000) == 0x94000000:
                bl_count += 1
                if bl_count == 2:
                    site.prot_prog_bl_off = off
                    prog_co = off - code_base
                    prog_tgt = decode_bl_target(w, prog_co)
                    print("  [+] Protection func programming BL at file 0x%06X → 0x%06X" %
                          (off, prog_tgt))
                    break
            elif w == 0xD65F03C0:
                break
        if site.prot_prog_bl_off is None:
            print("  [!] Warning: could not find programming BL in protection function")

    return site


def find_devmpu_reset_patch(data):
    """
    Find the DEVMPU init function and a code cave for the reset trampoline.

    The DEVMPU init function enables DEVMPU and programs region boundaries,
    but does NOT reset APC values left by the preloader. We inject a
    devmpu_reset (write 7 then 1 to DEVMPU control registers) before the
    enable, clearing all preloader APC restrictions.

    Discovery:
    1. Search for MOVZ W8, #0x1118; MOVZ W10, #0x5118 (DEVMPU enable addrs)
    2. Find the STR W9, [X8] that writes the enable value
    3. Find a code cave (60+ zero bytes, 4-aligned) for the trampoline
    4. Compute BL encoding from the STR location to the trampoline

    Returns (init_str_foff, cave_foff) or None.
    """
    code_base = MTK_IMG_HDR_SIZE

    # Step 1: find DEVMPU init signature
    sig = struct.pack('<II', DEVMPU_INIT_SIG_0, DEVMPU_INIT_SIG_1)
    sig_idx = data.find(sig, code_base)
    if sig_idx < 0:
        print("  [!] DEVMPU init signature (MOVZ W8,#0x1118 + MOVZ W10,#0x5118) not found")
        return None

    print("  [+] DEVMPU init signature at file 0x%06X" % sig_idx)

    # Step 2: find STR W9, [X8] (enable ch0) within 48 bytes after signature
    init_str_foff = None
    for off in range(sig_idx, sig_idx + 48, 4):
        w = read_u32(data, off)
        if w == DEVMPU_ENABLE_STR:
            init_str_foff = off
            break

    if init_str_foff is None:
        bl_word = None
        for off in range(sig_idx, sig_idx + 48, 4):
            w = read_u32(data, off)
            if (w & 0xFC000000) == 0x94000000:
                init_str_foff = off
                bl_word = w
                break

        if init_str_foff is not None:
            print("  [+] BL (patched trampoline) at file 0x%06X [already patched]" %
                  init_str_foff)
        else:
            print("  [!] Could not find STR W9, [X8] in DEVMPU init")
            return None
    else:
        print("  [+] STR W9, [X8] (DEVMPU enable ch0) at file 0x%06X" % init_str_foff)

    # Step 3: find code cave for trampoline
    tramp_size = len(TRAMPOLINE_INSNS) * 4
    cave_search_start = 0x028000
    cave_search_end = min(0x02C000, len(data) - tramp_size)
    cave_foff = None

    for off in range(cave_search_start, cave_search_end, 4):
        if all(data[off + i] == 0 for i in range(tramp_size)):
            cave_foff = off
            break

    if cave_foff is None:
        print("  [!] No code cave (%d+ zero bytes) found in 0x%06X-0x%06X" %
              (tramp_size, cave_search_start, cave_search_end))
        return None

    print("  [+] Code cave at file 0x%06X (%d bytes available)" %
          (cave_foff, tramp_size))

    return (init_str_foff, cave_foff)


def build_patches(data, site, devmpu_info=None):
    """
    Build patch entries: list of (file_offset, original_4bytes, patched_4bytes, desc).

    Three patch groups:
      A) Global: inside the protection function, NOP the SMMU programming BL
         so ALL callers skip actual SMMU hardware configuration.
      B) VCP handler: replace 5 instructions ending at the BL to skip the
         protection call entirely and jump to the zero+succeed path.
      C) DEVMPU reset: redirect DEVMPU init to a trampoline that calls
         devmpu_reset (clears all APC) before enabling DEVMPU channels.
    """
    code_base = MTK_IMG_HDR_SIZE
    patches = []

    if site.is_patched:
        raise RuntimeError(
            "Cannot auto-restore: original BL target address is lost.\n"
            "  Use the original unpatched tee.img to restore.")

    # --- Group A: Global SMMU programming bypass ---
    if site.prot_prog_bl_off is not None:
        MOVZ_W0_0 = 0x52800000
        foff = site.prot_prog_bl_off
        orig_bytes = data[foff:foff + 4]
        patches.append((foff, orig_bytes, struct.pack('<I', MOVZ_W0_0),
                         "MOVZ W0, #0 (skip SMMU programming, report success)"))

    # --- Group B: VCP handler skip ---
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

    # --- Group C: DEVMPU reset trampoline ---
    if devmpu_info is not None:
        init_str_foff, cave_foff = devmpu_info
        init_str_code = init_str_foff - code_base
        cave_code = cave_foff - code_base

        bl_word = encode_bl(init_str_code, cave_code)
        patches.append((init_str_foff,
                         struct.pack('<I', DEVMPU_ENABLE_STR),
                         struct.pack('<I', bl_word),
                         "BL 0x%06X (redirect to devmpu_reset trampoline)" % cave_code))

        for i, (insn_word, insn_desc) in enumerate(TRAMPOLINE_INSNS):
            foff = cave_foff + i * 4
            patches.append((foff,
                             b'\x00\x00\x00\x00',
                             struct.pack('<I', insn_word),
                             insn_desc))

    return patches


def verify_state(data, patches):
    """
    Returns:
      'original'  -- all original bytes match
      'patched'   -- all patched bytes match
      'unknown'   -- mixed or neither
    """
    orig_match = all(data[off:off+len(orig)] == orig for off, orig, patch, _ in patches)
    patch_match = all(data[off:off+len(patch)] == patch for off, orig, patch, _ in patches)
    if orig_match:
        return 'original'
    if patch_match:
        return 'patched'
    return 'unknown'


def apply_patches(data, patches):
    buf = bytearray(data)
    for foff, orig, patch, desc in patches:
        n = len(orig)
        actual = bytes(buf[foff:foff + n])
        if actual != orig:
            raise RuntimeError(
                "Byte mismatch at 0x%06X: expected %s, got %s" %
                (foff, orig.hex(), actual.hex()))
        buf[foff:foff + n] = patch
    return bytes(buf)


def restore_patches(data, patches):
    buf = bytearray(data)
    for foff, orig, patch, desc in patches:
        n = len(patch)
        actual = bytes(buf[foff:foff + n])
        if actual != patch:
            raise RuntimeError(
                "Cannot restore at 0x%06X: expected %s, got %s" %
                (foff, patch.hex(), actual.hex()))
        buf[foff:foff + n] = orig
    return bytes(buf)


def main():
    parser = argparse.ArgumentParser(
        description="Patch MTK ATF (tee.img) to skip VCP SMMU protection and reset DEVMPU",
        epilog="""
This patch allows VCP/APU to function when GenieZone is disabled.
Without GZ, the SMMU protection page table has no valid entries,
causing VCP DMA translation faults. The patch skips the protection
setup so VCP uses only the kernel's IOMMU (which is properly configured).
Additionally, the DEVMPU is reset during ATF init to clear preloader
APC restrictions that block domain 7 (VCP/APU) from PROT_SHARED memory.

IMPORTANT: Do NOT use --patch-protpgd when this ATF patch is applied.
           The protpgd mblock allocation is no longer needed.
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

    print("[*] Searching for DEVMPU init function...")
    devmpu_info = find_devmpu_reset_patch(data)

    if site.is_patched:
        print()
        if args.restore:
            print("[!] Auto-restore is not supported -- the original BL target cannot be recovered.")
            print("    To restore, re-flash the original (unpatched) tee.img.")
            return 1
        print("[*] Patch already applied. Nothing to do.")
        print("    To restore, re-flash the original (unpatched) tee.img.")
        return 0

    print("[*] Building patch...")
    try:
        patches = build_patches(data, site, devmpu_info)
    except RuntimeError as e:
        print("[!] %s" % e)
        return 1

    state = verify_state(data, patches)

    print()
    has_global = site.prot_prog_bl_off is not None
    has_devmpu = devmpu_info is not None
    n_layers = 1 + int(has_global) + int(has_devmpu)
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
        if has_devmpu and i == layer3_start:
            print("  --- Layer 3: DEVMPU reset (trampoline + code cave) ---")
        actual = data[foff:foff + len(orig)]
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
                print("[*] Dry run -- not writing.")
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
        print("[*] Dry run -- patch verification passed, not writing.")
        print()
        print("  Effect when applied:")
        print("    Layer 1 (global): SMMU programming function always reports success")
        print("      -> no SMMU hardware configured with empty protpgd for ANY subsystem")
        print("      -> covers iommu_secure init, cmdq, display, and VCP IOMMU banks")
        print("    Layer 2 (VCP handler): vcp_smc_vcp_init skips protection call")
        print("      -> zeros SMMU protection registers")
        print("      -> jumps to existing zero+succeed path")
        print("      -> VCP init returns success without processing protpgd pointer")
        if has_devmpu:
            print("    Layer 3 (DEVMPU reset): devmpu_reset injected into DEVMPU init")
            print("      -> writes 7 then 1 to DEVMPU control registers (0x10351104/0x10355104)")
            print("      -> clears ALL preloader DEVMPU APC restrictions")
            print("      -> region boundaries reprogrammed normally (no APC = no restrictions)")
            print("      -> VCP/APU (domain 7) gets unrestricted access to PROT_SHARED")
            print("      -> prevents 12K+ DEVMPU violation IRQ storm and HWT crash")
        print()
        print("  All devices use only the kernel's M4U IOMMU (no secure SMMU/DEVMPU protection).")
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
