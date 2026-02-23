#!/usr/bin/env python3
"""
Super DES exploit - BITSCTF 2026

Vulnerability: DES semi-weak key pairs.
For pair (A=01FE01FE01FE01FE, B=FE01FE01FE01FE01):
  E_A(x) = D_B(x)  and  E_B(x) = D_A(x)
  => E_B(E_A(x)) = D_A(E_A(x)) = x  (cancellation!)

Using k2=B, k3=A so E_k2(E_k3(x)) = x:

  v2 oracle:  D_k1(E_k2(E_k3(pt))) = D_k1(pt)
  v1 oracle:  E_k1(E_k2(E_k3(pt))) = E_k1(pt)

Two-step attack:
  Step 1: option 3 + flag  => X = D_k1(pad(flag))
  Step 2: option 2 + X     => E_k1(X) = E_k1(D_k1(pad(flag))) = pad(flag)
  Step 3: unpad => flag
"""

from pwn import *
from Crypto.Util.Padding import unpad

HOST = '20.193.149.152'
PORT = 1340

# Semi-weak pair: E_B(E_A(x)) = x
# k2=B, k3=A  =>  E_k2(E_k3(x)) = x
K2 = b'FE01FE01FE01FE01'
K3 = b'01FE01FE01FE01FE'


def get_ct(conn, option, option_, custom_pt_hex=None):
    conn.sendlineafter(b'enter k2 hex bytes >', K2)
    conn.sendlineafter(b'enter k3 hex bytes >', K3)
    conn.sendlineafter(b'enter option >', str(option).encode())
    conn.sendlineafter(b'enter option >', str(option_).encode())
    if option_ == 2:
        conn.sendlineafter(b'enter hex bytes >', custom_pt_hex)
    conn.recvuntil(b'ciphertext : ')
    return bytes.fromhex(conn.recvline().strip().decode())


conn = remote(HOST, PORT)

# Step 1: D_k1(pad(flag)) via option 3 (v2) + encrypt flag
log.info('Step 1: getting D_k1(pad(flag))')
X = get_ct(conn, 3, 1)
N = len(X) // 8
log.info(f'X = {X.hex()}  ({N} blocks)')

# Step 2: E_k1(X) = pad(flag) via option 2 (v1) + custom text X
log.info('Step 2: getting E_k1(D_k1(pad(flag))) = pad(flag)')
result = get_ct(conn, 2, 2, X.hex().encode())
log.info(f'result = {result.hex()}')

# First N*8 bytes = pad(flag); last 8 bytes are E_k1 of extra padding block
padded_flag = result[:N * 8]
flag = unpad(padded_flag, 8)

log.success(f'FLAG: {flag.decode()}')

conn.close()
