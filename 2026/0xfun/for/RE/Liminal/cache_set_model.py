#!/usr/bin/env python3
"""
Try per-bit mappings based on L1D cache set collision theory.
For each bit function, determine if its r8/r9 probe addresses share
cache sets with the speculative access addresses (rsi+0x100, rsi+0x340).
"""
import struct

BINARY = r"c:\Users\ADMIN\Desktop\Kep-moving\My_World\CTF\2026\0xfun\for\RE\Liminal\liminal"
TARGET = 0x4C494D494E414C21

with open(BINARY, "rb") as f:
    data = f.read()

keys = [struct.unpack_from("<Q", data, 0x2E2C0 + i*8)[0] for i in range(8)]
perm = list(data[0x2E280:0x2E280+64])

# Extract tables
all_tables = []
for t in range(64):
    table = []
    offset = 0xE280 + t * 256 * 8
    for e in range(256):
        val = struct.unpack_from("<Q", data, offset + e * 8)[0]
        table.append(val)
    all_tables.append(table)

def build_sboxes_per_bit(bit_mappings):
    """Build S-boxes with per-bit mappings. bit_mappings[i] = 0 or 1 for each of 64 bit functions."""
    sboxes = []
    for sbox_idx in range(8):
        sbox = []
        for input_byte in range(256):
            output_byte = 0
            for bit_idx in range(8):
                func_idx = sbox_idx * 8 + bit_idx
                mapping = bit_mappings[func_idx]
                entry = all_tables[func_idx][input_byte]
                if entry == 0x100:
                    bit_val = mapping
                else:
                    bit_val = 1 - mapping
                output_byte |= (bit_val << bit_idx)
            sbox.append(output_byte)
        sboxes.append(sbox)
    return sboxes

def invert_sbox(sbox):
    inv = [0] * 256
    for i in range(256):
        inv[sbox[i]] = i
    return inv

def apply_sbox(state, sboxes):
    result = 0
    for i in range(8):
        result |= sboxes[i][(state >> (i*8)) & 0xFF] << (i*8)
    return result

def apply_perm(state, p):
    result = 0
    for i in range(64):
        if state & (1 << p[i]):
            result |= (1 << i)
    return result

def apply_inv_perm(state, p):
    inv_p = [0] * 64
    for i in range(64):
        inv_p[p[i]] = i
    return apply_perm(state, inv_p)

def decrypt(ciphertext, sboxes, p):
    inv_sboxes = [invert_sbox(s) for s in sboxes]
    state = apply_sbox(ciphertext, inv_sboxes)
    state ^= keys[7]
    for i in range(6, -1, -1):
        state = apply_inv_perm(state, p)
        state = apply_sbox(state, inv_sboxes)
        state ^= keys[i]
    return state

def encrypt(plaintext, sboxes, p):
    state = plaintext ^ keys[0]
    for i in range(7):
        state = apply_sbox(state, sboxes)
        state = apply_perm(state, p)
        state ^= keys[i + 1]
    state = apply_sbox(state, sboxes)
    return state

def is_printable(val):
    for i in range(8):
        b = (val >> (i*8)) & 0xFF
        if b < 0x20 or b > 0x7e:
            return False
    return True

def to_str(val):
    s = ""
    for i in range(7, -1, -1):
        b = (val >> (i*8)) & 0xFF
        s += chr(b) if 0x20 <= b <= 0x7e else f"\\x{b:02x}"
    return s

# Compute cache set indices for each function
# spec addresses: rsi+0x100 (set 4) and rsi+0x340 (set 13) for 64-set L1D
spec_sets = {4, 13}  # sets used by speculative accesses

print("=== Cache set analysis ===")
print("L1D: 64 sets, 8-way, 64B lines")
print(f"spec_0x100 set = {(0x100 >> 6) & 0x3F}")
print(f"spec_0x340 set = {(0x340 >> 6) & 0x3F}")

# For various cache geometries (number of sets), find which functions collide
for num_sets in [16, 32, 64, 128, 256]:
    set_mask = num_sets - 1

    spec_100_set = (0x100 >> 6) & set_mask
    spec_340_set = (0x340 >> 6) & set_mask

    colliding_funcs = set()
    for i in range(64):
        r8_set = ((i * 0x480) >> 6) & set_mask
        r9_set = ((i * 0x480 + 0x240) >> 6) & set_mask

        # Check if r8 or r9 set matches either speculative access set
        if r8_set == spec_100_set or r8_set == spec_340_set or \
           r9_set == spec_100_set or r9_set == spec_340_set:
            colliding_funcs.add(i)

    if colliding_funcs:
        print(f"\n  {num_sets} sets: colliding functions = {sorted(colliding_funcs)}")

        # Try model: colliding functions use mapping A, others use mapping B (and vice versa)
        for flip_desc, flip in [("collide=A, rest=B", True), ("collide=B, rest=A", False)]:
            bit_mappings = []
            for i in range(64):
                if i in colliding_funcs:
                    bit_mappings.append(0 if flip else 1)  # mapping A=0x100→0 or B=0x100→1
                else:
                    bit_mappings.append(1 if flip else 0)

            sboxes = build_sboxes_per_bit(bit_mappings)
            # Check bijectivity
            bijective = all(len(set(s)) == 256 for s in sboxes)
            if not bijective:
                continue

            plaintext = decrypt(TARGET, sboxes, perm)
            check = encrypt(plaintext, sboxes, perm)
            ascii_str = to_str(plaintext) if is_printable(plaintext) else ""

            marker = " ASCII!" if is_printable(plaintext) else ""
            match = "OK" if check == TARGET else "FAIL"
            print(f"    {flip_desc}: 0x{plaintext:016x} [{match}]{marker} {ascii_str}")

# Also try: mapping based on r8_set matching EXACTLY spec_0x100_set (set 4)
# and r9_set matching EXACTLY spec_0x340_set (set 13)
print("\n\n=== Exact cache set match model ===")
for num_sets in [64]:
    set_mask = num_sets - 1
    spec_100_set = (0x100 >> 6) & set_mask  # 4
    spec_340_set = (0x340 >> 6) & set_mask  # 13

    exact_match_funcs = set()
    for i in range(64):
        r8_set = ((i * 0x480) >> 6) & set_mask
        r9_set = ((i * 0x480 + 0x240) >> 6) & set_mask
        if r8_set == spec_100_set and r9_set == spec_340_set:
            exact_match_funcs.add(i)

    print(f"  {num_sets} sets: exact match funcs = {sorted(exact_match_funcs)}")

    # Model: exact match → 0x100 warms r8 set → r8 slightly faster → al=0
    #         (mapping A for exact match, mapping B for others)
    for flip_desc, flip in [("exact=A, rest=B", True), ("exact=B, rest=A", False)]:
        bit_mappings = [0 if flip else 1 if i in exact_match_funcs else 1 if flip else 0
                        for i in range(64)]
        # Simpler:
        bit_mappings = []
        for i in range(64):
            if i in exact_match_funcs:
                bit_mappings.append(0 if flip else 1)
            else:
                bit_mappings.append(1 if flip else 0)

        sboxes = build_sboxes_per_bit(bit_mappings)
        bijective = all(len(set(s)) == 256 for s in sboxes)
        if not bijective:
            print(f"    {flip_desc}: NOT BIJECTIVE")
            continue

        plaintext = decrypt(TARGET, sboxes, perm)
        check = encrypt(plaintext, sboxes, perm)
        ascii_str = to_str(plaintext) if is_printable(plaintext) else ""
        marker = " ASCII!" if is_printable(plaintext) else ""
        print(f"    {flip_desc}: 0x{plaintext:016x} [{check==TARGET and 'OK' or 'FAIL'}]{marker} {ascii_str}")

# Also try: per-bit mapping based on r8_set XOR spec_100_set parity
print("\n\n=== Parity-based models ===")
for num_sets in [64]:
    set_mask = num_sets - 1
    for model_name, model_func in [
        ("r8_set % 2", lambda i: ((i * 0x480 >> 6) & set_mask) % 2),
        ("r8_set % 4 < 2", lambda i: 1 if ((i * 0x480 >> 6) & set_mask) % 4 < 2 else 0),
        ("i % 2", lambda i: i % 2),
        ("i // 8 % 2", lambda i: (i // 8) % 2),
        ("(i*18+4) % 64 < 32", lambda i: 1 if (i * 18 + 4) % 64 < 32 else 0),
    ]:
        bit_mappings = [model_func(i) for i in range(64)]
        sboxes = build_sboxes_per_bit(bit_mappings)
        bijective = all(len(set(s)) == 256 for s in sboxes)
        if not bijective:
            continue
        plaintext = decrypt(TARGET, sboxes, perm)
        check = encrypt(plaintext, sboxes, perm)
        ascii_str = to_str(plaintext) if is_printable(plaintext) else ""
        marker = " ASCII!" if is_printable(plaintext) else ""
        print(f"  {model_name}: 0x{plaintext:016x} [{check==TARGET and 'OK' or 'FAIL'}]{marker} {ascii_str}")
