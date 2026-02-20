#!/usr/bin/env python3
"""
Comprehensive solver for the Liminal CTF challenge.
Extracts SPN cipher components from the binary and tries all combinations.
"""
import struct

BINARY = r"c:\Users\ADMIN\Desktop\Kep-moving\My_World\CTF\2026\0xfun\for\RE\Liminal\liminal"
TARGET = 0x4C494D494E414C21  # "LIMINAL!" in ASCII

with open(BINARY, "rb") as f:
    data = f.read()

# === Extract round keys ===
# Keys at vaddr 0x42F2C0, file offset 0x2E2C0
key_offset = 0x2E2C0
keys = []
for i in range(8):
    k = struct.unpack_from("<Q", data, key_offset + i * 8)[0]
    keys.append(k)
    print(f"key[{i}] = 0x{k:016x}")

# === Extract permutation ===
# Perm table at vaddr 0x42F280, file offset 0x2E280
perm_offset = 0x2E280
perm = list(data[perm_offset:perm_offset + 64])
print(f"\nperm = {perm}")

# Compute inverse permutation
inv_perm = [0] * 64
for i in range(64):
    inv_perm[perm[i]] = i
print(f"inv_perm = {inv_perm}")

# === Extract S-box tables ===
# 64 tables starting at vaddr 0x40F280, file offset 0xE280
# Each table: 256 qwords (2048 bytes)
# Table i corresponds to bit function i
# S-box j (byte j) uses bit functions j*8 through j*8+7
# Bit function j*8+k gives bit k of S-box j output

table_base_offset = 0xE280
NUM_TABLES = 64
TABLE_SIZE = 256

# Read all 64 tables
all_tables = []
for t in range(NUM_TABLES):
    table = []
    offset = table_base_offset + t * TABLE_SIZE * 8
    for e in range(TABLE_SIZE):
        val = struct.unpack_from("<Q", data, offset + e * 8)[0]
        table.append(val)
    # Verify only 0x100 and 0x340
    unique = set(table)
    if unique != {0x100, 0x340}:
        print(f"WARNING: Table {t} has unexpected values: {unique}")
    all_tables.append(table)

print(f"\nExtracted {len(all_tables)} tables")
print(f"Table 0 has {sum(1 for v in all_tables[0] if v == 0x100)} entries of 0x100, "
      f"{sum(1 for v in all_tables[0] if v == 0x340)} entries of 0x340")

# === Build S-boxes for both mappings ===
def build_sboxes(mapping_100_to):
    """Build 8 S-boxes. mapping_100_to: the bit value when table entry is 0x100"""
    sboxes = []
    for sbox_idx in range(8):
        sbox = []
        for input_byte in range(256):
            output_byte = 0
            for bit_idx in range(8):
                table_idx = sbox_idx * 8 + bit_idx
                entry = all_tables[table_idx][input_byte]
                if entry == 0x100:
                    bit_val = mapping_100_to
                else:  # 0x340
                    bit_val = 1 - mapping_100_to
                output_byte |= (bit_val << bit_idx)
            sbox.append(output_byte)
        sboxes.append(sbox)
    return sboxes

def invert_sbox(sbox):
    """Compute inverse of a 256-element S-box"""
    inv = [0] * 256
    for i in range(256):
        inv[sbox[i]] = i
    return inv

def verify_bijective(sboxes, name):
    """Check that all S-boxes are bijective (permutations of 0-255)"""
    for i, sbox in enumerate(sboxes):
        if len(set(sbox)) != 256:
            print(f"WARNING: {name} S-box {i} is NOT bijective!")
            return False
    return True

# Build S-boxes for both mappings
sboxes_A = build_sboxes(0)  # 0x100 -> 0, 0x340 -> 1
sboxes_B = build_sboxes(1)  # 0x100 -> 1, 0x340 -> 0

print(f"\nMapping A (0x100->0, 0x340->1): bijective = {verify_bijective(sboxes_A, 'A')}")
print(f"Mapping B (0x100->1, 0x340->0): bijective = {verify_bijective(sboxes_B, 'B')}")

# === SPN operations ===
def apply_sbox(state, sboxes):
    """Apply 8 S-boxes to 8 bytes of state"""
    result = 0
    for i in range(8):
        byte_val = (state >> (i * 8)) & 0xFF
        result |= sboxes[i][byte_val] << (i * 8)
    return result

def apply_inv_sbox(state, sboxes):
    """Apply inverse S-boxes"""
    inv_sboxes = [invert_sbox(s) for s in sboxes]
    return apply_sbox(state, inv_sboxes)

def apply_perm(state, p):
    """Apply bit permutation: output[i] = input[p[i]]"""
    result = 0
    for i in range(64):
        if state & (1 << p[i]):
            result |= (1 << i)
    return result

def apply_inv_perm(state, p):
    """Apply inverse permutation"""
    # inv_p such that inv_p[p[i]] = i
    inv_p = [0] * 64
    for i in range(64):
        inv_p[p[i]] = i
    return apply_perm(state, inv_p)

# === Encryption (for verification) ===
def encrypt(plaintext, sboxes, p):
    """
    Forward SPN encryption:
    state = input ^ key[0]
    for i in range(7):
        state = sbox(state)
        state = perm(state)
        state ^= key[i+1]
    state = sbox(state)  # final sbox, no perm
    """
    state = plaintext ^ keys[0]
    for i in range(7):
        state = apply_sbox(state, sboxes)
        state = apply_perm(state, p)
        state ^= keys[i + 1]
    state = apply_sbox(state, sboxes)
    return state

# === Decryption ===
def decrypt(ciphertext, sboxes, p):
    """
    Inverse SPN decryption:
    state = inv_sbox(ciphertext)
    state ^= key[7]
    for i in range(6, -1, -1):
        state = inv_perm(state)
        state = inv_sbox(state)
        state ^= key[i]
    """
    inv_sboxes = [invert_sbox(s) for s in sboxes]
    state = apply_sbox(ciphertext, inv_sboxes)
    state ^= keys[7]
    for i in range(6, -1, -1):
        state = apply_inv_perm(state, p)
        state = apply_sbox(state, inv_sboxes)
        state ^= keys[i]
    return state

# === Try all combinations ===
print("\n" + "=" * 60)
print("Trying all combinations to decrypt 0x4C494D494E414C21")
print("=" * 60)

results = []

for mapping_name, sboxes in [("0x100->0", sboxes_A), ("0x100->1", sboxes_B)]:
    for perm_name, p in [("orig_perm", perm), ("inv_perm", inv_perm)]:
        plaintext = decrypt(TARGET, sboxes, p)
        # Verify by encrypting back
        check = encrypt(plaintext, sboxes, p)
        match = "MATCH" if check == TARGET else f"MISMATCH (got 0x{check:016x})"

        result_str = f"0x{plaintext:016x}"
        flag = f"0xfun{{{result_str}}}"
        print(f"\n{mapping_name} + {perm_name}:")
        print(f"  plaintext = {result_str}")
        print(f"  flag = {flag}")
        print(f"  verify: {match}")
        results.append((mapping_name, perm_name, plaintext, flag, check == TARGET))

# Also try with alternative SPN structure:
# What if the structure is:
# state = input
# for i in range(8):
#     state ^= key[i]
#     state = sbox(state)
#     if i < 7: state = perm(state)
# (This is what the summary describes)

print("\n" + "=" * 60)
print("Alternative: trying different SPN structure")
print("(XOR before sbox in same round)")
print("=" * 60)

def encrypt_v2(plaintext, sboxes, p):
    """
    Alternative structure:
    for i in range(8):
        state ^= key[i]
        state = sbox(state)
        if i < 7: state = perm(state)
    """
    state = plaintext
    for i in range(8):
        state ^= keys[i]
        state = apply_sbox(state, sboxes)
        if i < 7:
            state = apply_perm(state, p)
    return state

def decrypt_v2(ciphertext, sboxes, p):
    """Inverse of encrypt_v2"""
    inv_sboxes = [invert_sbox(s) for s in sboxes]
    state = ciphertext
    for i in range(7, -1, -1):
        if i < 7:
            state = apply_inv_perm(state, p)
        state = apply_sbox(state, inv_sboxes)
        state ^= keys[i]
    return state

for mapping_name, sboxes in [("0x100->0", sboxes_A), ("0x100->1", sboxes_B)]:
    for perm_name, p in [("orig_perm", perm), ("inv_perm", inv_perm)]:
        plaintext = decrypt_v2(TARGET, sboxes, p)
        check = encrypt_v2(plaintext, sboxes, p)
        match = "MATCH" if check == TARGET else f"MISMATCH (got 0x{check:016x})"

        result_str = f"0x{plaintext:016x}"
        flag = f"0xfun{{{result_str}}}"
        print(f"\n{mapping_name} + {perm_name}:")
        print(f"  plaintext = {result_str}")
        print(f"  flag = {flag}")
        print(f"  verify: {match}")

# Also try: what if there's a 9th key (key[8]) or the last round also has permutation?
# Try with perm on ALL rounds
print("\n" + "=" * 60)
print("Alternative: perm on ALL 8 rounds (including last)")
print("=" * 60)

def encrypt_v3(plaintext, sboxes, p):
    state = plaintext ^ keys[0]
    for i in range(7):
        state = apply_sbox(state, sboxes)
        state = apply_perm(state, p)
        state ^= keys[i + 1]
    state = apply_sbox(state, sboxes)
    state = apply_perm(state, p)  # perm on last round too
    return state

def decrypt_v3(ciphertext, sboxes, p):
    inv_sboxes = [invert_sbox(s) for s in sboxes]
    state = apply_inv_perm(ciphertext, p)  # undo last perm
    state = apply_sbox(state, inv_sboxes)
    state ^= keys[7]
    for i in range(6, -1, -1):
        state = apply_inv_perm(state, p)
        state = apply_sbox(state, inv_sboxes)
        state ^= keys[i]
    return state

for mapping_name, sboxes in [("0x100->0", sboxes_A), ("0x100->1", sboxes_B)]:
    for perm_name, p in [("orig_perm", perm), ("inv_perm", inv_perm)]:
        plaintext = decrypt_v3(TARGET, sboxes, p)
        check = encrypt_v3(plaintext, sboxes, p)
        match = "MATCH" if check == TARGET else f"MISMATCH (got 0x{check:016x})"

        result_str = f"0x{plaintext:016x}"
        flag = f"0xfun{{{result_str}}}"
        print(f"\n{mapping_name} + {perm_name}:")
        print(f"  plaintext = {result_str}")
        print(f"  flag = {flag}")
        print(f"  verify: {match}")

print("\n\nAll candidate flags:")
print("=" * 60)
