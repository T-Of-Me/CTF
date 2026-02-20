#!/usr/bin/env python3
"""
Try all 256 per-byte S-box mapping combinations.
For each of 8 S-boxes, the mapping can be A (0x100→0) or B (0x100→1).
"""
import struct
import itertools

BINARY = r"c:\Users\ADMIN\Desktop\Kep-moving\My_World\CTF\2026\0xfun\for\RE\Liminal\liminal"
TARGET = 0x4C494D494E414C21

with open(BINARY, "rb") as f:
    data = f.read()

# Extract keys
keys = []
for i in range(8):
    k = struct.unpack_from("<Q", data, 0x2E2C0 + i * 8)[0]
    keys.append(k)

# Extract perm
perm = list(data[0x2E280:0x2E280 + 64])

# Extract all 64 tables
all_tables = []
for t in range(64):
    table = []
    offset = 0xE280 + t * 256 * 8
    for e in range(256):
        val = struct.unpack_from("<Q", data, offset + e * 8)[0]
        table.append(val)
    all_tables.append(table)

# Build S-box for a specific byte with a specific mapping
def build_sbox_for_byte(sbox_idx, mapping_100_to):
    sbox = []
    for input_byte in range(256):
        output_byte = 0
        for bit_idx in range(8):
            table_idx = sbox_idx * 8 + bit_idx
            entry = all_tables[table_idx][input_byte]
            if entry == 0x100:
                bit_val = mapping_100_to
            else:
                bit_val = 1 - mapping_100_to
            output_byte |= (bit_val << bit_idx)
        sbox.append(output_byte)
    return sbox

def invert_sbox(sbox):
    inv = [0] * 256
    for i in range(256):
        inv[sbox[i]] = i
    return inv

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

def is_printable_ascii(val):
    """Check if all 8 bytes are printable ASCII"""
    for i in range(8):
        b = (val >> (i * 8)) & 0xFF
        if b < 0x20 or b > 0x7e:
            return False
    return True

def to_string(val):
    """Convert qword to string (big-endian byte order)"""
    s = ""
    for i in range(7, -1, -1):
        b = (val >> (i * 8)) & 0xFF
        if 0x20 <= b <= 0x7e:
            s += chr(b)
        else:
            s += f"\\x{b:02x}"
    return s

# Precompute S-boxes for both mappings for each byte
sboxes_per_byte = {}
for sbox_idx in range(8):
    sboxes_per_byte[(sbox_idx, 0)] = build_sbox_for_byte(sbox_idx, 0)  # mapping A
    sboxes_per_byte[(sbox_idx, 1)] = build_sbox_for_byte(sbox_idx, 1)  # mapping B

# Try all 256 combinations
print(f"Trying all 256 per-byte mapping combinations...")
print(f"Target: 0x{TARGET:016x} = \"{to_string(TARGET)}\"")
print()

results = []
for combo in range(256):
    # combo is a bitmask: bit i = mapping for S-box i (0=A, 1=B)
    sboxes = []
    for sbox_idx in range(8):
        mapping = (combo >> sbox_idx) & 1
        sboxes.append(sboxes_per_byte[(sbox_idx, mapping)])

    plaintext = decrypt(TARGET, sboxes, perm)

    # Verify
    check = encrypt(plaintext, sboxes, perm)
    if check != TARGET:
        continue  # shouldn't happen

    is_ascii = is_printable_ascii(plaintext)
    string_rep = to_string(plaintext)

    if is_ascii:
        mapping_str = "".join(str((combo >> i) & 1) for i in range(8))
        print(f"  combo={combo:3d} (mapping={mapping_str}): 0x{plaintext:016x} = \"{string_rep}\" <-- ASCII!")
        results.append((combo, plaintext, string_rep))

print(f"\n\nTotal ASCII results: {len(results)}")

# Also try per-BIT mapping (but only within constraints)
# Each bit function independently maps 0x100 to 0 or 1
# With 64 bits, 2^64 is too many. But if we know some structure...

# Let me also check: for the per-byte results, what does the flag look like?
if results:
    print("\n\nCandidate flags:")
    for combo, plaintext, string_rep in results:
        print(f"  0xfun{{0x{plaintext:016x}}}  (\"{string_rep}\")")
else:
    print("\nNo ASCII results found. Trying other patterns...")

    # Check for results where most bytes are ASCII (allowing 1-2 non-printable)
    print("\nResults with 6+ printable bytes:")
    for combo in range(256):
        sboxes = []
        for sbox_idx in range(8):
            mapping = (combo >> sbox_idx) & 1
            sboxes.append(sboxes_per_byte[(sbox_idx, mapping)])

        plaintext = decrypt(TARGET, sboxes, perm)

        printable_count = 0
        for i in range(8):
            b = (plaintext >> (i * 8)) & 0xFF
            if 0x20 <= b <= 0x7e:
                printable_count += 1

        if printable_count >= 6:
            mapping_str = "".join(str((combo >> i) & 1) for i in range(8))
            string_rep = to_string(plaintext)
            print(f"  combo={combo:3d} (mapping={mapping_str}): 0x{plaintext:016x} = \"{string_rep}\" ({printable_count}/8 printable)")
