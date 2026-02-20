#!/usr/bin/env python3
"""Disassemble the init_array function at 0x401430 and fini_array at 0x401400."""
import struct

BINARY = r"c:\Users\ADMIN\Desktop\Kep-moving\My_World\CTF\2026\0xfun\for\RE\Liminal\liminal"

with open(BINARY, "rb") as f:
    data = f.read()

def v2f_text(vaddr):
    return vaddr - 0x400000

try:
    from capstone import *
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    # Init function at 0x401430
    start_vaddr = 0x401400
    start_foff = v2f_text(start_vaddr)
    code = data[start_foff:start_foff + 0x80]

    print("=== Functions at 0x401400-0x401480 ===")
    for insn in md.disasm(code, start_vaddr):
        marker = ""
        if insn.address == 0x401430:
            marker = "  <--- INIT_ARRAY entry point"
        if insn.address == 0x401400:
            marker = "  <--- FINI_ARRAY entry point"
        print(f"  0x{insn.address:06x}: {insn.mnemonic:<12s} {insn.op_str}{marker}")

    # Also check the .init section
    print("\n=== .init section (0x401000) ===")
    code = data[v2f_text(0x401000):v2f_text(0x401000) + 0x1b]
    for insn in md.disasm(code, 0x401000):
        print(f"  0x{insn.address:06x}: {insn.mnemonic:<12s} {insn.op_str}")

    # Let me also check what's right before the main function and right after
    # to find any hidden initializer
    print("\n=== Code at 0x4010a0-0x4010c0 (before main) ===")
    code = data[v2f_text(0x4010a0):v2f_text(0x4010c0)]
    for insn in md.disasm(code, 0x4010a0):
        print(f"  0x{insn.address:06x}: {insn.mnemonic:<12s} {insn.op_str}")

except ImportError:
    print("capstone not available")
