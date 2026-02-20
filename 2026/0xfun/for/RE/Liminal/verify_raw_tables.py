#!/usr/bin/env python3
"""
Verify raw table data and test alternative interpretations.
"""
import struct

BINARY = r"c:\Users\ADMIN\Desktop\Kep-moving\My_World\CTF\2026\0xfun\for\RE\Liminal\liminal"

with open(BINARY, "rb") as f:
    data = f.read()

# Table 0 at file offset 0xE280 (vaddr 0x40F280)
# 256 qword entries
table0_offset = 0xE280

print("=== First 16 entries of Table 0 (raw qwords) ===")
for i in range(16):
    val = struct.unpack_from("<Q", data, table0_offset + i * 8)[0]
    print(f"  table0[{i:3d}] = 0x{val:016x}")

print("\n=== Last 16 entries of Table 0 ===")
for i in range(240, 256):
    val = struct.unpack_from("<Q", data, table0_offset + i * 8)[0]
    print(f"  table0[{i:3d}] = 0x{val:016x}")

# Check table 1 (next table)
table1_offset = 0xE280 + 256 * 8
print(f"\n=== First 8 entries of Table 1 (offset 0x{table1_offset:x}) ===")
for i in range(8):
    val = struct.unpack_from("<Q", data, table1_offset + i * 8)[0]
    print(f"  table1[{i:3d}] = 0x{val:016x}")

# Count unique values across ALL tables
all_vals = set()
for t in range(64):
    base = 0xE280 + t * 256 * 8
    for i in range(256):
        val = struct.unpack_from("<Q", data, base + i * 8)[0]
        all_vals.add(val)

print(f"\n=== Unique values across ALL 64 tables: {sorted(hex(v) for v in all_vals)} ===")

# What if the entries are 4 bytes, not 8?
print("\n=== Reinterpret Table 0 as DWORDS (512 entries, 4 bytes each) ===")
unique_dwords = set()
for i in range(512):
    val = struct.unpack_from("<I", data, table0_offset + i * 4)[0]
    unique_dwords.add(val)
print(f"Unique dword values: {sorted(hex(v) for v in unique_dwords)}")

# What if entries are 2 bytes?
print("\n=== Reinterpret as WORDS (1024 entries, 2 bytes each) ===")
unique_words = set()
for i in range(1024):
    val = struct.unpack_from("<H", data, table0_offset + i * 2)[0]
    unique_words.add(val)
print(f"Unique word values: {sorted(hex(v) for v in unique_words)}")

# Let me also check what's BEFORE the tables - is there possibly a header or different data?
print(f"\n=== 64 bytes before Table 0 (offset 0x{table0_offset - 64:x}) ===")
for i in range(0, 64, 8):
    val = struct.unpack_from("<Q", data, table0_offset - 64 + i)[0]
    print(f"  [0x{table0_offset-64+i:05x}] = 0x{val:016x}")

# Verify table 0 S-box interpretation
# For mapping A (0x100 -> 0, 0x340 -> 1):
sbox0_A = []
for input_byte in range(256):
    output = 0
    for bit in range(8):
        table_idx = bit  # S-box 0, bit `bit`
        tbl_offset = 0xE280 + table_idx * 256 * 8
        val = struct.unpack_from("<Q", data, tbl_offset + input_byte * 8)[0]
        if val == 0x340:
            output |= (1 << bit)
    sbox0_A.append(output)

print(f"\n=== S-box 0 (mapping A: 0x100->0, 0x340->1) ===")
print(f"First 16: {[hex(x) for x in sbox0_A[:16]]}")
print(f"Bijective: {len(set(sbox0_A)) == 256}")

# For mapping B (0x100 -> 1, 0x340 -> 0):
sbox0_B = []
for input_byte in range(256):
    output = 0
    for bit in range(8):
        table_idx = bit
        tbl_offset = 0xE280 + table_idx * 256 * 8
        val = struct.unpack_from("<Q", data, tbl_offset + input_byte * 8)[0]
        if val == 0x100:
            output |= (1 << bit)
    sbox0_B.append(output)

print(f"\n=== S-box 0 (mapping B: 0x100->1, 0x340->0) ===")
print(f"First 16: {[hex(x) for x in sbox0_B[:16]]}")
print(f"Bijective: {len(set(sbox0_B)) == 256}")

# Test encrypt(0) with mapping A
keys = []
for i in range(8):
    k = struct.unpack_from("<Q", data, 0x2E2C0 + i * 8)[0]
    keys.append(k)

perm = list(data[0x2E280:0x2E280+64])

def build_all_sboxes(mapping_100_to):
    sboxes = []
    for sbox_idx in range(8):
        sbox = []
        for input_byte in range(256):
            output_byte = 0
            for bit_idx in range(8):
                table_idx = sbox_idx * 8 + bit_idx
                tbl_offset = 0xE280 + table_idx * 256 * 8
                val = struct.unpack_from("<Q", data, tbl_offset + input_byte * 8)[0]
                if val == 0x100:
                    bit_val = mapping_100_to
                else:
                    bit_val = 1 - mapping_100_to
                output_byte |= (bit_val << bit_idx)
            sbox.append(output_byte)
        sboxes.append(sbox)
    return sboxes

def apply_sbox(state, sboxes):
    result = 0
    for i in range(8):
        byte_val = (state >> (i * 8)) & 0xFF
        result |= sboxes[i][byte_val] << (i * 8)
    return result

def apply_perm(state, p):
    result = 0
    for i in range(64):
        if state & (1 << p[i]):
            result |= (1 << i)
    return result

def encrypt(plaintext, sboxes, p):
    state = plaintext ^ keys[0]
    for i in range(7):
        state = apply_sbox(state, sboxes)
        state = apply_perm(state, p)
        state ^= keys[i + 1]
    state = apply_sbox(state, sboxes)
    return state

# Test with some known values
print("\n=== Testing encryption ===")
for mapping_name, mapping in [("A (0x100->0)", 0), ("B (0x100->1)", 1)]:
    sboxes = build_all_sboxes(mapping)
    for test_input in [0, 1, 0xdeadbeefcafebabe]:
        result = encrypt(test_input, sboxes, perm)
        print(f"  {mapping_name}: encrypt(0x{test_input:016x}) = 0x{result:016x}")
