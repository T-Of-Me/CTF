#!/usr/bin/env python3
"""Search binary for embedded test values and try alternative targets."""
import struct

BINARY = r"c:\Users\ADMIN\Desktop\Kep-moving\My_World\CTF\2026\0xfun\for\RE\Liminal\liminal"
TARGET = 0x4C494D494E414C21
TARGET_SWAPPED = 0x214C414E494D494C  # byte-swapped

with open(BINARY, "rb") as f:
    data = f.read()

# Search for target value in binary
target_bytes_le = struct.pack("<Q", TARGET)
target_bytes_be = struct.pack(">Q", TARGET)

print("=== Searching for target 0x4C494D494E414C21 in binary ===")
for i in range(len(data) - 7):
    if data[i:i+8] == target_bytes_le:
        print(f"  Found (LE) at file offset 0x{i:x}")
    if data[i:i+8] == target_bytes_be:
        print(f"  Found (BE) at file offset 0x{i:x}")

# Search for "LIMINAL!" as ASCII
liminal = b"LIMINAL!"
for i in range(len(data) - 7):
    if data[i:i+8] == liminal:
        print(f"  Found 'LIMINAL!' at file offset 0x{i:x}")

# Try byte-swapped target
print("\n=== Trying byte-swapped target 0x214C414E494D494C ===")

keys = [struct.unpack_from("<Q", data, 0x2E2C0 + i*8)[0] for i in range(8)]
perm = list(data[0x2E280:0x2E280+64])

all_tables = []
for t in range(64):
    table = []
    offset = 0xE280 + t * 256 * 8
    for e in range(256):
        val = struct.unpack_from("<Q", data, offset + e * 8)[0]
        table.append(val)
    all_tables.append(table)

def build_sboxes(mapping):
    sboxes = []
    for sbox_idx in range(8):
        sbox = []
        for input_byte in range(256):
            output_byte = 0
            for bit_idx in range(8):
                entry = all_tables[sbox_idx*8+bit_idx][input_byte]
                bit_val = mapping if entry == 0x100 else 1 - mapping
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

def encrypt(pt, sboxes, p):
    state = pt ^ keys[0]
    for i in range(7):
        state = apply_sbox(state, sboxes)
        state = apply_perm(state, p)
        state ^= keys[i + 1]
    state = apply_sbox(state, sboxes)
    return state

for name, target in [("original", TARGET), ("byte-swapped", TARGET_SWAPPED)]:
    print(f"\nTarget: {name} = 0x{target:016x}")
    for mname, m in [("0x100->0", 0), ("0x100->1", 1)]:
        sboxes = build_sboxes(m)
        pt = decrypt(target, sboxes, perm)
        ct = encrypt(pt, sboxes, perm)
        ok = "OK" if ct == target else "FAIL"
        print(f"  {mname}: plaintext = 0x{pt:016x} [{ok}]")

# Also try: what if the cipher is applied in REVERSE?
# i.e., what if the binary DECRYPTS instead of encrypts?
# Then the "input that produces" means: decrypt(input) = target
# So input = encrypt(target)
print("\n=== What if compute() is decryption? input = encrypt(target) ===")
for mname, m in [("0x100->0", 0), ("0x100->1", 1)]:
    sboxes = build_sboxes(m)
    result = encrypt(TARGET, sboxes, perm)
    check = decrypt(result, sboxes, perm)
    ok = "OK" if check == TARGET else "FAIL"
    print(f"  {mname}: input = 0x{result:016x} [{ok}]")

# Try: what if key order is reversed?
print("\n=== Reversed key order ===")
keys_rev = keys[::-1]
def decrypt_rev(ciphertext, sboxes, p):
    inv_sboxes = [invert_sbox(s) for s in sboxes]
    state = apply_sbox(ciphertext, inv_sboxes)
    state ^= keys_rev[7]
    for i in range(6, -1, -1):
        state = apply_inv_perm(state, p)
        state = apply_sbox(state, inv_sboxes)
        state ^= keys_rev[i]
    return state

for mname, m in [("0x100->0", 0), ("0x100->1", 1)]:
    sboxes = build_sboxes(m)
    pt = decrypt_rev(TARGET, sboxes, perm)
    # Verify by encrypting with reversed keys
    state = pt ^ keys_rev[0]
    for i in range(7):
        state = apply_sbox(state, sboxes)
        state = apply_perm(state, perm)
        state ^= keys_rev[i + 1]
    state = apply_sbox(state, sboxes)
    ok = "OK" if state == TARGET else "FAIL"
    print(f"  {mname}: plaintext = 0x{pt:016x} [{ok}]")

# Per-byte brute force with byte-swapped target
print("\n=== Per-byte brute force with byte-swapped target ===")
def build_sbox_byte(sbox_idx, mapping):
    sbox = []
    for input_byte in range(256):
        output_byte = 0
        for bit_idx in range(8):
            entry = all_tables[sbox_idx*8+bit_idx][input_byte]
            bit_val = mapping if entry == 0x100 else 1 - mapping
            output_byte |= (bit_val << bit_idx)
        sbox.append(output_byte)
    return sbox

sboxes_cache = {}
for sbox_idx in range(8):
    for m in [0, 1]:
        sboxes_cache[(sbox_idx, m)] = build_sbox_byte(sbox_idx, m)

for target_name, target_val in [("byte-swapped", TARGET_SWAPPED)]:
    ascii_results = []
    for combo in range(256):
        sboxes = [sboxes_cache[(i, (combo >> i) & 1)] for i in range(8)]
        pt = decrypt(target_val, sboxes, perm)
        is_ascii = all(0x20 <= (pt >> (i*8)) & 0xFF <= 0x7e for i in range(8))
        if is_ascii:
            s = "".join(chr((pt >> (i*8)) & 0xFF) for i in range(7, -1, -1))
            print(f"  combo={combo:3d}: 0x{pt:016x} = \"{s}\" ASCII!")
            ascii_results.append((combo, pt, s))

    if not ascii_results:
        print(f"  No ASCII results for {target_name}")
