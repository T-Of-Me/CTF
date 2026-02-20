#!/usr/bin/env python3
"""
Deep analysis of the Liminal binary:
1. Check bytes at probe addresses (rsi+0x100 and rsi+0x340)
2. Disassemble code between speculative load and timing measurement
3. Check all 64 functions' r8/r9 offsets
"""
import struct

BINARY = r"c:\Users\ADMIN\Desktop\Kep-moving\My_World\CTF\2026\0xfun\for\RE\Liminal\liminal"

with open(BINARY, "rb") as f:
    data = f.read()

# vaddr to file offset: file_offset = vaddr - 0x401000
def v2f(vaddr):
    return vaddr - 0x401000

# === 1. Check bytes at probe addresses ===
print("=== Probe array contents ===")
rsi_vaddr = 0x40B000
for offset in [0x000, 0x100, 0x200, 0x240, 0x300, 0x340, 0x400]:
    addr = rsi_vaddr + offset
    foff = v2f(addr)
    if foff < len(data):
        val = data[foff]
        print(f"  [rsi+0x{offset:04x}] = 0x{addr:06x} (foff=0x{foff:05x}) = 0x{val:02x}")

print("\nFirst 32 bytes at rsi+0x100:")
foff = v2f(0x40B100)
print("  " + " ".join(f"{data[foff+i]:02x}" for i in range(32)))

print("\nFirst 32 bytes at rsi+0x340:")
foff = v2f(0x40B340)
print("  " + " ".join(f"{data[foff+i]:02x}" for i in range(32)))

# === 2. Disassemble code between speculative load and timing ===
# For F0: speculative load at vaddr 0x4016c7, timing at ~0x401740
# Let's dump the raw bytes from 0x4016c7 to 0x401790
print("\n\n=== Raw bytes from 0x4016c7 to 0x401790 ===")
start = v2f(0x4016c7)
end = v2f(0x401790)
for i in range(0, end - start, 16):
    addr = 0x4016c7 + i
    hex_bytes = " ".join(f"{data[start+i+j]:02x}" for j in range(min(16, end-start-i)))
    ascii_repr = "".join(chr(data[start+i+j]) if 32 <= data[start+i+j] < 127 else "." for j in range(min(16, end-start-i)))
    print(f"  0x{addr:06x}: {hex_bytes:<48s} {ascii_repr}")

# === 3. Try to identify the speculative second load ===
# Look for patterns like: movzx, shl, mov [mem+rax*N] after the first speculative load
print("\n\n=== Disassembling with capstone (0x4016c7-0x401790) ===")
try:
    from capstone import *
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    code = data[start:end]
    for insn in md.disasm(code, 0x4016c7):
        print(f"  0x{insn.address:06x}: {insn.mnemonic:<10s} {insn.op_str}")
except ImportError:
    print("  capstone not available, using raw bytes above")

# === 4. Check r8/r9 offsets for all 64 functions ===
# Each function has: lea r8, [rsi + disp] and lea r9, [rsi + disp]
# LEA R8, [RSI + disp32] = 4C 8D 86 xx xx xx xx (if disp32) or 4C 8D 06 (if no disp, i.e. [rsi])
# LEA R9, [RSI + disp32] = 4C 8D 8E xx xx xx xx
print("\n\n=== R8/R9 offsets for all 64 bit functions ===")

# First, find all function start addresses
# Functions start at 0x401681 and subsequent ones
# Let me find them by looking for the push rbx/rcx/... pattern
# Or just scan for lea r8 and lea r9 patterns in the range

# LEA R8, [RSI]: 4C 8D 06
# LEA R8, [RSI + disp32]: 4C 8D 86 xx xx xx xx
# LEA R9, [RSI + disp32]: 4C 8D 8E xx xx xx xx

func_range_start = v2f(0x401681)
func_range_end = v2f(0x405600)

r8_offsets = []
r9_offsets = []

for foff in range(func_range_start, func_range_end):
    # LEA R8, [RSI] = 4C 8D 06
    if data[foff:foff+3] == bytes([0x4C, 0x8D, 0x06]):
        r8_offsets.append((foff - func_range_start + 0x401681, 0))
    # LEA R8, [RSI + disp32] = 4C 8D 86 xx xx xx xx
    elif data[foff:foff+3] == bytes([0x4C, 0x8D, 0x86]):
        disp = struct.unpack_from("<i", data, foff + 3)[0]
        r8_offsets.append((foff - func_range_start + 0x401681, disp))
    # LEA R9, [RSI + disp32] = 4C 8D 8E xx xx xx xx
    elif data[foff:foff+3] == bytes([0x4C, 0x8D, 0x8E]):
        disp = struct.unpack_from("<i", data, foff + 3)[0]
        r9_offsets.append((foff - func_range_start + 0x401681, disp))

print(f"Found {len(r8_offsets)} LEA R8 instructions, {len(r9_offsets)} LEA R9 instructions")
print(f"\nR8 offsets from RSI:")
for i, (addr, off) in enumerate(r8_offsets):
    print(f"  [{i:2d}] at 0x{addr:06x}: r8 = rsi + 0x{off:05x}")

print(f"\nR9 offsets from RSI:")
for i, (addr, off) in enumerate(r9_offsets):
    print(f"  [{i:2d}] at 0x{addr:06x}: r9 = rsi + 0x{off:05x}")

# === 5. Check: do speculative access addresses match ANY function's r8/r9? ===
print("\n\n=== Checking if spec addresses match any r8/r9 ===")
spec_addrs = {0x100, 0x340}
for i, (_, off) in enumerate(r8_offsets):
    if off in spec_addrs:
        print(f"  R8[{i}] offset 0x{off:05x} matches speculative address!")
for i, (_, off) in enumerate(r9_offsets):
    if off in spec_addrs:
        print(f"  R9[{i}] offset 0x{off:05x} matches speculative address!")
