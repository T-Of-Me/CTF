#!/usr/bin/env python3
"""Disassemble calibration function at 0x406298 and main function."""
import struct

BINARY = r"c:\Users\ADMIN\Desktop\Kep-moving\My_World\CTF\2026\0xfun\for\RE\Liminal\liminal"

with open(BINARY, "rb") as f:
    data = f.read()

def v2f_text(vaddr):
    return vaddr - 0x400000

try:
    from capstone import *
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    # Calibration function
    start_vaddr = 0x406298
    start_foff = v2f_text(start_vaddr)
    code = data[start_foff:start_foff + 0x200]

    print("=== Calibration function (0x406298) ===")
    for insn in md.disasm(code, start_vaddr):
        print(f"  0x{insn.address:06x}: {insn.mnemonic:<12s} {insn.op_str}")
        if insn.mnemonic == 'ret':
            break

    # Main function
    start_vaddr = 0x4010c0
    start_foff = v2f_text(start_vaddr)
    code = data[start_foff:start_foff + 0x300]

    print("\n=== Main function (0x4010c0) ===")
    for insn in md.disasm(code, start_vaddr):
        print(f"  0x{insn.address:06x}: {insn.mnemonic:<12s} {insn.op_str}")
        if insn.mnemonic == 'ret' or insn.mnemonic == 'hlt':
            break

except ImportError:
    print("capstone not available")
