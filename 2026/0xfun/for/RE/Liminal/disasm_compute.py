#!/usr/bin/env python3
"""Disassemble the compute function at 0x405b37 to verify round structure."""
import struct

BINARY = r"c:\Users\ADMIN\Desktop\Kep-moving\My_World\CTF\2026\0xfun\for\RE\Liminal\liminal"

with open(BINARY, "rb") as f:
    data = f.read()

def v2f_text(vaddr):
    return vaddr - 0x400000

try:
    from capstone import *
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    # Disassemble compute function (0x405b37)
    # It probably extends to the calibration function or similar
    start_vaddr = 0x405b37
    end_vaddr = 0x406300  # generous end
    start_foff = v2f_text(start_vaddr)
    end_foff = v2f_text(end_vaddr)
    code = data[start_foff:end_foff]

    print("=== Compute function (0x405b37) ===")
    xor_count = 0
    call_count = 0
    for insn in md.disasm(code, start_vaddr):
        # Mark interesting instructions
        marker = ""
        if insn.mnemonic == "xor" and "r14" in insn.op_str and "[" in insn.op_str:
            xor_count += 1
            marker = f"  <--- KEY XOR #{xor_count}"
        elif insn.mnemonic == "call":
            call_count += 1
            marker = f"  <--- CALL #{call_count}"
        elif insn.mnemonic == "ret":
            marker = "  <--- END"

        print(f"  0x{insn.address:06x}: {insn.mnemonic:<12s} {insn.op_str}{marker}")

        if insn.mnemonic == "ret":
            break

    print(f"\nTotal key XORs: {xor_count}")
    print(f"Total calls: {call_count}")

except ImportError:
    print("capstone not available, doing raw byte scan")

    # Scan for XOR patterns
    start_foff = v2f_text(0x405b37)
    end_foff = v2f_text(0x406300)

    # Look for xor r14, [r15+disp]
    # 4D 33 77 XX (xor r14, [r15+disp8]) or 4D 33 B7 XX XX XX XX (xor r14, [r15+disp32])
    print("Scanning for XOR r14, [r15+disp] instructions...")
    for foff in range(start_foff, end_foff):
        vaddr = foff + 0x400000
        if data[foff:foff+3] == bytes([0x4D, 0x33, 0x77]):
            disp = struct.unpack_from("<b", data, foff+3)[0]
            print(f"  0x{vaddr:06x}: xor r14, [r15+0x{disp:02x}]")
        elif data[foff:foff+3] == bytes([0x4D, 0x33, 0xB7]):
            disp = struct.unpack_from("<i", data, foff+3)[0]
            print(f"  0x{vaddr:06x}: xor r14, [r15+0x{disp:x}]")
        elif data[foff:foff+3] == bytes([0x4D, 0x33, 0x37]):
            print(f"  0x{vaddr:06x}: xor r14, [r15]")
