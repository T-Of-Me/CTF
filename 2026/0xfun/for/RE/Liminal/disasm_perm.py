#!/usr/bin/env python3
"""Disassemble the permutation function at 0x405af9."""
import struct

BINARY = r"c:\Users\ADMIN\Desktop\Kep-moving\My_World\CTF\2026\0xfun\for\RE\Liminal\liminal"

with open(BINARY, "rb") as f:
    data = f.read()

def v2f_text(vaddr):
    return vaddr - 0x400000

try:
    from capstone import *
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    start_vaddr = 0x405af9
    start_foff = v2f_text(start_vaddr)
    code = data[start_foff:start_foff + 0x60]

    print("=== Permutation function (0x405af9) ===")
    for insn in md.disasm(code, start_vaddr):
        print(f"  0x{insn.address:06x}: {insn.mnemonic:<12s} {insn.op_str}")
        if insn.mnemonic == 'ret':
            break

except ImportError:
    print("capstone not available")

# Also verify the perm table content
print("\n=== Perm table at 0x42F280 ===")
perm_foff = 0x2E280  # data segment mapping
# Read as bytes
perm_bytes = list(data[perm_foff:perm_foff + 64])
print(f"As bytes: {perm_bytes}")

# Check if it could be dwords (4 bytes each)
perm_dwords = []
for i in range(64):
    perm_dwords.append(struct.unpack_from("<I", data, perm_foff + i * 4)[0])
print(f"\nAs dwords (first 16): {perm_dwords[:16]}")

# Check if it could be qwords
perm_qwords = []
for i in range(64):
    perm_qwords.append(struct.unpack_from("<Q", data, perm_foff + i * 8)[0])
print(f"\nAs qwords (first 8): {[hex(q) for q in perm_qwords[:8]]}")

# What's at perm_foff - 0x40 (just before)?
print(f"\nLast 8 bytes of table area before perm: {[hex(data[perm_foff - 8 + i]) for i in range(8)]}")
# What's right after the 64-byte perm table?
print(f"8 bytes after perm table: {[hex(data[perm_foff + 64 + i]) for i in range(8)]}")

# Verify perm is a valid permutation of 0-63
if sorted(perm_bytes) == list(range(64)):
    print("\nPerm table (as bytes) IS a valid permutation of 0-63")
else:
    print("\nPerm table (as bytes) is NOT a valid permutation of 0-63")
    print(f"Missing: {set(range(64)) - set(perm_bytes)}")
    print(f"Duplicated: {[x for x in perm_bytes if perm_bytes.count(x) > 1]}")
