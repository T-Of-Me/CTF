#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# permpress solver (Python)
# Ý tưởng: tìm fixed point của f(s) = HASH( shuffle(N, s) ), rồi in perm.
#
# Không cần thư viện ngoài. Có thể chỉnh:
#  - ROUNDS: 8 / 12 / 20 (ChaCha)
#  - HASH_MODE: "fnv1a_len" hoặc "fnv1a_raw"
#  - N: độ dài permutation
#
# Cách dùng:
#   python3 permpress_solver.py 64 --rounds 12 --hash fnv1a_len
#
# Nếu chưa “ăn”:
#   - Thử N khác (32/64/128/256)
#   - Đổi --rounds 8/20
#   - Đổi --hash fnv1a_raw
#   - Tăng --iters / --restarts

import argparse
import struct
from typing import List, Optional, Tuple

# -----------------------------
# SplitMix64 (giống seed_from_u64 -> 32 bytes)
# -----------------------------
def splitmix64(x: int) -> int:
    x &= 0xFFFFFFFFFFFFFFFF
    x = (x + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    z = x
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9 & 0xFFFFFFFFFFFFFFFF
    z = (z ^ (z >> 27)) * 0x94D049BB133111EB & 0xFFFFFFFFFFFFFFFF
    z ^= (z >> 31)
    return z & 0xFFFFFFFFFFFFFFFF

def seed_u64_to_32bytes(seed: int) -> bytes:
    # tạo 4 u64 (32 bytes) bằng SplitMix64
    s = seed & 0xFFFFFFFFFFFFFFFF
    out = bytearray()
    for _ in range(4):
        s = (s + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        out += struct.pack("<Q", splitmix64(s))
    return bytes(out)  # 32 bytes

# -----------------------------
# ChaCha core (rounds = 8/12/20). Tạo stream 64-byte block như chuẩn.
# -----------------------------
def rotl32(v: int, n: int) -> int:
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))

def chacha_block(key32: bytes, counter: int, nonce12: bytes, rounds: int) -> bytes:
    # key32: 32 bytes
    # counter: 64-bit (nhưng ở đây dùng 32-bit thấp cho block counter, đủ lớn)
    # nonce12: 12 bytes
    assert len(key32) == 32
    assert len(nonce12) == 12

    def u32le(b): return list(struct.unpack("<16I", b))

    constants = b"expand 32-byte k"
    state = [
        struct.unpack("<I", constants[0:4])[0],
        struct.unpack("<I", constants[4:8])[0],
        struct.unpack("<I", constants[8:12])[0],
        struct.unpack("<I", constants[12:16])[0],
    ] + list(struct.unpack("<8I", key32)) + [
        counter & 0xFFFFFFFF,
        (counter >> 32) & 0xFFFFFFFF,
    ] + list(struct.unpack("<3I", nonce12))

    working = state[:]

    def quarter(a, b, c, d):
        working[a] = (working[a] + working[b]) & 0xFFFFFFFF
        working[d] = rotl32(working[d] ^ working[a], 16)
        working[c] = (working[c] + working[d]) & 0xFFFFFFFF
        working[b] = rotl32(working[b] ^ working[c], 12)
        working[a] = (working[a] + working[b]) & 0xFFFFFFFF
        working[d] = rotl32(working[d] ^ working[a], 8)
        working[c] = (working[c] + working[d]) & 0xFFFFFFFF
        working[b] = rotl32(working[b] ^ working[c], 7)

    # rounds: even number (8,12,20)
    for _ in range(rounds // 2):
        # column rounds
        quarter(0, 4, 8, 12)
        quarter(1, 5, 9, 13)
        quarter(2, 6, 10, 14)
        quarter(3, 7, 11, 15)
        # diagonal rounds
        quarter(0, 5, 10, 15)
        quarter(1, 6, 11, 12)
        quarter(2, 7, 8, 13)
        quarter(3, 4, 9, 14)

    out = [(working[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack("<16I", *out)

class ChaChaRng:
    def __init__(self, seed_u64: int, rounds: int = 12):
        self.rounds = rounds
        self.key = seed_u64_to_32bytes(seed_u64)     # 32-byte key từ u64
        self.nonce = b"\x00" * 12                    # nonce 96-bit = 0
        self.counter = 0
        self.buf = b""
        self.pos = 0

    def refill(self):
        self.buf = chacha_block(self.key, self.counter, self.nonce, self.rounds)
        self.counter = (self.counter + 1) & 0xFFFFFFFFFFFFFFFF
        self.pos = 0

    def next_u32(self) -> int:
        if self.pos >= len(self.buf):
            self.refill()
        val = struct.unpack_from("<I", self.buf, self.pos)[0]
        self.pos += 4
        return val

    def next_u64(self) -> int:
        lo = self.next_u32()
        hi = self.next_u32()
        return (hi << 32) | lo

    def uniform_u64(self, upper: int) -> int:
        """Trả về số trong [0, upper) không lệch (rejection sampling)."""
        assert upper > 0
        # lấy 64-bit rồi mod, tránh bias bằng “zone”
        zone = (1 << 64) - ((1 << 64) % upper)
        while True:
            x = self.next_u64()
            if x < zone:
                return x % upper

# -----------------------------
# FNV-1a 64-bit
# -----------------------------
def fnv1a64(data: bytes) -> int:
    h = 0xcbf29ce484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h

def serialize_vec_i32_rust_style(vec: List[int], with_len_prefix=True) -> bytes:
    out = bytearray()
    if with_len_prefix:
        # usize 8-byte LE (giả định 64-bit target)
        out += struct.pack("<Q", len(vec))
    for x in vec:
        out += struct.pack("<i", int(x))  # i32 LE
    return bytes(out)

def hash_vec_i32(vec: List[int], mode: str = "fnv1a_len") -> int:
    if mode == "fnv1a_len":
        return fnv1a64(serialize_vec_i32_rust_style(vec, with_len_prefix=True))
    elif mode == "fnv1a_raw":
        return fnv1a64(serialize_vec_i32_rust_style(vec, with_len_prefix=False))
    else:
        raise ValueError("Unknown hash mode")

# Nếu cần FxHash thật (rustc_hash::FxHasher), bạn có thể cài `pyfxhash` hoặc tự viết hasher.
# Ở đây đa số CTF tương tự xài FNV-1a nên mình để 2 biến thể trên trước.

# -----------------------------
# Shuffle (Fisher-Yates) dùng rng.uniform_u64
# -----------------------------
def shuffle_from_seed(n: int, seed: int, rounds: int) -> List[int]:
    rng = ChaChaRng(seed, rounds=rounds)
    v = list(range(n))
    # Fisher-Yates (rand 0.8: j ∈ [0, i])
    for i in range(n - 1, 0, -1):
        j = rng.uniform_u64(i + 1)
        v[i], v[int(j)] = v[int(j)], v[i]
    return v

# -----------------------------
# Tìm fixed point: s == HASH(shuffle(n, s))
# -----------------------------
GOLD = 0x9E3779B97F4A7C15
C2   = 0x94D049BB133111EB

def find_fixed_point(n: int,
                     rounds: int = 12,
                     hash_mode: str = "fnv1a_len",
                     max_iters_per_restart: int = 1_000_00,  # 1e5
                     max_restarts: int = 256) -> Optional[Tuple[int, List[int]]]:
    s0 = GOLD
    for r in range(max_restarts):
        s = s0 ^ ((r * C2) & 0xFFFFFFFFFFFFFFFF)
        for _ in range(max_iters_per_restart):
            p = shuffle_from_seed(n, s, rounds)
            h = hash_vec_i32(p, mode=hash_mode)
            if h == s:
                return s, p
            s = h
    return None

# -----------------------------
# CLI
# -----------------------------
def main():
    ap = argparse.ArgumentParser(description="permpress fixed-point solver (Python)")
    ap.add_argument("N", type=int, help="độ dài permutation (ví dụ 64)")
    ap.add_argument("--rounds", type=int, default=12, choices=[8, 12, 20],
                    help="số vòng ChaCha (8/12/20), mặc định 12")
    ap.add_argument("--hash", type=str, default="fnv1a_len",
                    choices=["fnv1a_len", "fnv1a_raw"],
                    help="kiểu hash trên vector i32 (mặc định fnv1a_len)")
    ap.add_argument("--iters", type=int, default=200_000,
                    help="số vòng lặp mỗi restart (mặc định 200k)")
    ap.add_argument("--restarts", type=int, default=256,
                    help="số lần restart (mặc định 256)")
    args = ap.parse_args()

    res = find_fixed_point(args.N, rounds=args.rounds, hash_mode=args.hash,
                           max_iters_per_restart=args.iters,
                           max_restarts=args.restarts)
    if not res:
        print("[-] Không tìm thấy fixed point trong budget. Thử tăng --iters/--restarts, đổi --rounds / --hash / N.")
        return
    seed, perm = res
    print(f"[+] Found fixed seed: 0x{seed:016x}")
    # In ra permutation một dòng cách nhau bởi space (dán vào nc)
    print(" ".join(str(x) for x in perm))

if __name__ == "__main__":
    main()
