#!/usr/bin/env python3
"""
Verify table addresses for all 64 bit-level functions.
Each bit function has a `lea rcx, [rip + disp]` instruction that loads the table address.
We need to find this instruction in each function and extract the table address.
"""
import struct

BINARY = r"c:\Users\ADMIN\Desktop\Kep-moving\My_World\CTF\2026\0xfun\for\RE\Liminal\liminal"

with open(BINARY, "rb") as f:
    data = f.read()

# The bit functions start at vaddr 0x401681
# We know the first one is at 0x401681 and uses table at 0x40F280
# Let's scan for all lea rcx, [rip + disp] instructions (opcode: 48 8d 0d XX XX XX XX)
# in the range of bit functions (0x401681 to ~0x405600)

# vaddr to file offset for .text section
# .text is typically loaded at vaddr = file_offset (for non-PIE)
# Actually, we need to check. For this binary, .text is in the first LOAD segment.
# From context: the first LOAD segment maps file offset 0 to vaddr 0x400000
text_base_vaddr = 0x400000
text_base_foff = 0

def vaddr_to_foff_text(vaddr):
    return vaddr - text_base_vaddr + text_base_foff

# Scan for LEA RCX, [RIP+disp32] = 48 8D 0D xx xx xx xx
# in the bit function range
start_vaddr = 0x401681
end_vaddr = 0x405600

start_foff = vaddr_to_foff_text(start_vaddr)
end_foff = vaddr_to_foff_text(end_vaddr)

print("Scanning for LEA RCX, [RIP+disp32] in bit functions...")
lea_rcx_pattern = bytes([0x48, 0x8D, 0x0D])

table_addrs = []
for offset in range(start_foff, end_foff):
    if data[offset:offset+3] == lea_rcx_pattern:
        disp = struct.unpack_from("<i", data, offset + 3)[0]
        # RIP-relative: target = vaddr_of_next_instruction + disp
        next_ip_vaddr = (offset - text_base_foff + text_base_vaddr) + 7
        target_vaddr = next_ip_vaddr + disp
        # Only consider targets in the table range (0x40F000 - 0x430000)
        if 0x40F000 <= target_vaddr <= 0x430000:
            func_vaddr = offset - text_base_foff + text_base_vaddr
            table_addrs.append((func_vaddr, target_vaddr))

print(f"\nFound {len(table_addrs)} LEA RCX instructions pointing to table range:")
for i, (func_va, table_va) in enumerate(table_addrs):
    table_idx = (table_va - 0x40F280) // 0x800
    print(f"  [{i:2d}] func_vaddr=0x{func_va:06x}  table_vaddr=0x{table_va:06x}  table_idx={table_idx}")

# Also check the byte-level S-box functions to see which bit functions they call
# S-box functions: 0x4056a1, 0x40572c, 0x4057b7, 0x405842, 0x4058cd, 0x405958, 0x4059e3, 0x405a6e
sbox_addrs = [0x4056a1, 0x40572c, 0x4057b7, 0x405842, 0x4058cd, 0x405958, 0x4059e3, 0x405a6e]

print("\n\nScanning byte-level S-box functions for CALL instructions...")

# Scan for CALL rel32 = E8 xx xx xx xx
for sbox_idx, sbox_addr in enumerate(sbox_addrs):
    sbox_foff = vaddr_to_foff_text(sbox_addr)
    # Each S-box function is roughly 0x8B bytes (0x40572c - 0x4056a1 = 0x8B)
    sbox_end = sbox_foff + 0x100  # scan a bit more

    calls = []
    for offset in range(sbox_foff, min(sbox_end, len(data) - 5)):
        if data[offset] == 0xE8:
            disp = struct.unpack_from("<i", data, offset + 1)[0]
            target = (offset - text_base_foff + text_base_vaddr) + 5 + disp
            # Only consider calls to bit functions (0x401600 - 0x405600)
            if 0x401600 <= target <= 0x405600:
                calls.append(target)

    print(f"\n  S-box {sbox_idx} (0x{sbox_addr:06x}) calls:")
    for j, target in enumerate(calls):
        # Find which table this bit function uses
        matching = [t for (f, t) in table_addrs if abs(f - target) < 0x30]
        table_info = ""
        if matching:
            t = matching[0]
            table_idx = (t - 0x40F280) // 0x800
            table_info = f" -> table_idx={table_idx}"
        print(f"    bit {j}: 0x{target:06x}{table_info}")
