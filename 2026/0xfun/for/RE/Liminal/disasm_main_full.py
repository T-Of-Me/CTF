#!/usr/bin/env python3
"""Disassemble the FULL main function including the normal execution path."""
import struct

BINARY = r"c:\Users\ADMIN\Desktop\Kep-moving\My_World\CTF\2026\0xfun\for\RE\Liminal\liminal"

with open(BINARY, "rb") as f:
    data = f.read()

def v2f_text(vaddr):
    return vaddr - 0x400000

try:
    from capstone import *
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    # Main function from 0x401126 (the normal path when argc==2)
    start_vaddr = 0x401126
    end_vaddr = 0x401440  # just before the speculation gadget
    start_foff = v2f_text(start_vaddr)
    end_foff = v2f_text(end_vaddr)
    code = data[start_foff:end_foff]

    print("=== Main function, normal path (0x401126) ===")
    for insn in md.disasm(code, start_vaddr):
        marker = ""
        if insn.mnemonic == "call":
            marker = f"  <--- CALL"
        print(f"  0x{insn.address:06x}: {insn.mnemonic:<12s} {insn.op_str}{marker}")
        if insn.mnemonic == "ret" or insn.mnemonic == "hlt":
            break

except ImportError:
    print("capstone not available")
