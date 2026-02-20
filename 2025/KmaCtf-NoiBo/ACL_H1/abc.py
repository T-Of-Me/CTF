#!/usr/bin/env python3
import socket
import sys

HOST = "chal.sunshinectf.games"
PORT = 25403

KNOWN_PREFIX = b"Greetings, Earthlings."  # given in the challenge

BLOCK = 16

def recv_until(sock, marker: bytes):
    buf = b""
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("Connection closed before marker")
        buf += chunk
    return buf

def recv_hex_line(sock):
    # Read a full line and strip; must be hex
    line = b""
    while True:
        ch = sock.recv(1)
        if not ch:
            raise RuntimeError("Connection closed while reading ciphertext line")
        line += ch
        if ch == b"\n":
            break
    line = line.strip()
    # Be lenient: filter to hex chars
    if any(c not in b"0123456789abcdefABCDEF" for c in line):
        # Not hex? Keep reading until we find a hex-looking line
        return None
    try:
        return bytes.fromhex(line.decode())
    except Exception as e:
        return None

def block_count(n_bytes):
    return (n_bytes + BLOCK - 1) // BLOCK

def solve_from_two(ct0: bytes, ct1: bytes, known_prefix: bytes) -> bytes:
    assert len(ct0) == len(ct1), "Ciphertexts must be same length"
    L = len(ct0)
    if len(known_prefix) < BLOCK:
        raise ValueError("Known prefix must cover at least one full 16-byte block")

    # Prepare mutable plaintext buffer, seeded with known prefix
    M = bytearray(L)
    M[:len(known_prefix)] = known_prefix

    # Work block-by-block
    N = block_count(L)

    # Start at the first block index that is *not* fully known from the prefix
    start_b = (len(known_prefix) + BLOCK - 1) // BLOCK
    if start_b == 0:
        start_b = 1  # we need M[block 0] known to derive KS[1]

    for b in range(start_b, N):
        # keystream for block b equals ct1 block (b-1) XOR plaintext block (b-1)
        bprev = b - 1

        c1prev = ct1[bprev*BLOCK : min(L, (bprev+1)*BLOCK)]
        mprev  = M   [bprev*BLOCK : min(L, (bprev+1)*BLOCK)]
        ks_b   = bytes(x ^ y for x, y in zip(c1prev, mprev))

        c0b = ct0[b*BLOCK : min(L, (b+1)*BLOCK)]
        mb  = bytes(x ^ y for x, y in zip(c0b, ks_b))
        M[b*BLOCK : b*BLOCK + len(mb)] = mb

    return bytes(M)

def main():
    # Connect
    with socket.create_connection((HOST, PORT), timeout=15) as sock:
        # Wait for the transmission marker
        recv_until(sock, b"== BEGINNING TRANSMISSION ==")

        # The service prints a blank line and then ciphertext lines; grab two valid hex lines
        ct_lines = []
        while len(ct_lines) < 2:
            maybe = recv_hex_line(sock)
            if maybe:
                ct_lines.append(maybe)

    ct0, ct1 = ct_lines
    plaintext = solve_from_two(ct0, ct1, KNOWN_PREFIX)

    # Print as UTF-8 if possible; fall back to repr for safety
    try:
        text = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        text = plaintext.decode("latin1")

    print("\n=== RECOVERED MESSAGE ===\n")
    print(text)
    print("\n=========================\n")

    # If a flag is present, try to locate it.
    import re
    m = re.search(r"sun\{[^}]*\}", text)
    if m:
        print("Flag:", m.group(0))

if __name__ == "__main__":
    main()
