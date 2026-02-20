#!/usr/bin/env python3
"""
Deep analysis with CORRECT file offset mappings.
Text section: file_offset = vaddr - 0x400000
Data section: file_offset = vaddr - 0x401000
"""
import struct

BINARY = r"c:\Users\ADMIN\Desktop\Kep-moving\My_World\CTF\2026\0xfun\for\RE\Liminal\liminal"

with open(BINARY, "rb") as f:
    data = f.read()

def v2f_text(vaddr):
    """Text section mapping"""
    return vaddr - 0x400000

def v2f_data(vaddr):
    """Data section mapping"""
    return vaddr - 0x401000

# === 1. Disassemble the speculative path (0x4016b4 onwards) ===
print("=== Speculative execution path (F0, starting at 0x4016b4) ===")
try:
    from capstone import *
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    start_vaddr = 0x4016b4
    end_vaddr = 0x4017a1  # next function
    start_foff = v2f_text(start_vaddr)
    end_foff = v2f_text(end_vaddr)
    code = data[start_foff:end_foff]

    for insn in md.disasm(code, start_vaddr):
        print(f"  0x{insn.address:06x}: {insn.mnemonic:<12s} {insn.op_str}")
        if insn.mnemonic == 'ret':
            break
except ImportError:
    print("  capstone not available")

# === 2. Dump raw bytes from speculative load area ===
print("\n=== Raw bytes from 0x4016c7 to 0x401720 ===")
for offset in range(0, 0x60, 16):
    vaddr = 0x4016c7 + offset
    foff = v2f_text(vaddr)
    hex_bytes = " ".join(f"{data[foff+j]:02x}" for j in range(16))
    print(f"  0x{vaddr:06x}: {hex_bytes}")

# === 3. Find r8/r9 for ALL 64 bit functions ===
print("\n=== R8/R9 offsets for all 64 bit functions ===")

# Scan for LEA patterns in text section
func_range_start = v2f_text(0x401681)
func_range_end = v2f_text(0x405600)

# LEA R8, [RSI] = 4C 8D 06 (3 bytes)
# LEA R8, [RSI + disp8] = 4C 8D 46 xx (4 bytes)
# LEA R8, [RSI + disp32] = 4C 8D 86 xx xx xx xx (7 bytes)
# LEA R9, [RSI + disp8] = 4C 8D 4E xx (4 bytes)
# LEA R9, [RSI + disp32] = 4C 8D 8E xx xx xx xx (7 bytes)

r8_entries = []
r9_entries = []

for foff in range(func_range_start, func_range_end):
    vaddr = foff + 0x400000  # text mapping
    if data[foff:foff+2] == bytes([0x4C, 0x8D]):
        modrm = data[foff+2] if foff+2 < len(data) else 0
        # ModR/M byte: mod=00, reg=R8(000) or R9(001), r/m=RSI(110)
        # For LEA R8, [RSI]: modrm = 0x06 (mod=00, reg=0, rm=6)
        # For LEA R8, [RSI+disp32]: modrm = 0x86 (mod=10, reg=0, rm=6)
        # For LEA R8, [RSI+disp8]: modrm = 0x46 (mod=01, reg=0, rm=6)
        # For LEA R9, [RSI+disp32]: modrm = 0x8E (mod=10, reg=1, rm=6)
        # For LEA R9, [RSI+disp8]: modrm = 0x4E (mod=01, reg=1, rm=6)
        # For LEA R9, [RSI]: modrm = 0x0E (mod=00, reg=1, rm=6)

        if modrm == 0x06:  # LEA R8, [RSI]
            r8_entries.append((vaddr, 0))
        elif modrm == 0x46:  # LEA R8, [RSI + disp8]
            disp = struct.unpack_from("<b", data, foff + 3)[0]
            r8_entries.append((vaddr, disp))
        elif modrm == 0x86:  # LEA R8, [RSI + disp32]
            disp = struct.unpack_from("<i", data, foff + 3)[0]
            r8_entries.append((vaddr, disp))
        elif modrm == 0x0E:  # LEA R9, [RSI]
            r9_entries.append((vaddr, 0))
        elif modrm == 0x4E:  # LEA R9, [RSI + disp8]
            disp = struct.unpack_from("<b", data, foff + 3)[0]
            r9_entries.append((vaddr, disp))
        elif modrm == 0x8E:  # LEA R9, [RSI + disp32]
            disp = struct.unpack_from("<i", data, foff + 3)[0]
            r9_entries.append((vaddr, disp))

print(f"Found {len(r8_entries)} LEA R8 and {len(r9_entries)} LEA R9 instructions")

# Pair them up (r8 always comes before r9 in each function)
assert len(r8_entries) == len(r9_entries), f"Mismatch: {len(r8_entries)} vs {len(r9_entries)}"

print(f"\n{'Func':>4} {'r8_addr':>10} {'r8_off':>10} {'r9_off':>10} {'gap':>10}")
for i in range(len(r8_entries)):
    r8_addr, r8_off = r8_entries[i]
    r9_addr, r9_off = r9_entries[i]
    gap = r9_off - r8_off
    print(f"  {i:2d}   0x{r8_addr:06x}   0x{r8_off:05x}   0x{r9_off:05x}   0x{gap:05x}")

# === 4. Check: which functions' r8 or r9 match 0x100 or 0x340? ===
print("\n=== Functions where r8 or r9 matches 0x100 or 0x340 ===")
for i in range(len(r8_entries)):
    _, r8_off = r8_entries[i]
    _, r9_off = r9_entries[i]
    if r8_off in (0x100, 0x340):
        print(f"  F{i}: r8 = rsi + 0x{r8_off:05x} MATCHES!")
    if r9_off in (0x100, 0x340):
        print(f"  F{i}: r9 = rsi + 0x{r9_off:05x} MATCHES!")

# === 5. For each function, determine proximity ===
print("\n=== Proximity analysis ===")
print("For each function, which probe (r8 or r9) is closer to each spec address?")
for i in range(min(len(r8_entries), 10)):  # first 10
    _, r8_off = r8_entries[i]
    _, r9_off = r9_entries[i]
    for spec_off in [0x100, 0x340]:
        d_r8 = abs(spec_off - r8_off)
        d_r9 = abs(spec_off - r9_off)
        closer = "r8" if d_r8 < d_r9 else ("r9" if d_r9 < d_r8 else "tie")
        print(f"  F{i}: spec=0x{spec_off:04x}  d(r8)=0x{d_r8:05x}  d(r9)=0x{d_r9:05x}  closer={closer}")
