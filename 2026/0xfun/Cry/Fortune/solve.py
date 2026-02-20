#!/usr/bin/env python3
import socket
import time
import struct

M = 2**64
A = 2862933555777941757
C = 3037000493

def recover_low_bits(g1, g2):
    """Brute force lower 32 bits of state1 given two consecutive glimpses.
    Uses numpy for vectorized computation."""
    try:
        import numpy as np
        MASK64 = np.uint64(0xFFFFFFFFFFFFFFFF)
        a64 = np.uint64(A)
        c64 = np.uint64(C)
        g1_shifted = np.uint64(g1) << np.uint64(32)

        # Process in chunks to avoid memory issues
        chunk_size = 2**24  # 16M at a time
        for start in range(0, 2**32, chunk_size):
            end = min(start + chunk_size, 2**32)
            x = np.arange(start, end, dtype=np.uint64)
            state1 = g1_shifted + x
            state2 = a64 * state1 + c64  # wraps naturally as uint64
            upper = state2 >> np.uint64(32)
            matches = np.where(upper == np.uint64(g2))[0]
            if len(matches) > 0:
                return int(x[matches[0]])
        return None
    except ImportError:
        # Fallback: pure python brute force
        base = g1 << 32
        for x in range(2**32):
            state1 = (base + x) % M
            state2 = (A * state1 + C) % M
            if (state2 >> 32) == g2:
                return x
        return None

def lcg_next(state):
    return (A * state + C) % M

# Connect and get glimpses
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('chall.0xfun.org', 63638))
sock.settimeout(60)  # generous timeout

def recv_until(marker):
    data = b''
    while marker not in data:
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data

# Receive until the prompt
data = recv_until(b': ')
text = data.decode(errors='replace')
print("SERVER:", text)

lines = text.strip().split('\n')
glimpses = []
for line in lines:
    line = line.strip()
    if line.isdigit():
        glimpses.append(int(line))

print(f"Glimpses: {glimpses}")
assert len(glimpses) >= 2, f"Expected at least 2 glimpses, got {len(glimpses)}"

# Recover lower 32 bits of state after first glimpse
print("Brute-forcing lower 32 bits...")
t0 = time.time()
low = recover_low_bits(glimpses[0], glimpses[1])
print(f"Found low bits: {low} in {time.time()-t0:.1f}s")

# Reconstruct full state after first glimpse
state = (glimpses[0] << 32) | low
print(f"State after glimpse 1: {state}")

# Verify against remaining glimpses
for i in range(1, len(glimpses)):
    state = lcg_next(state)
    g = state >> 32
    print(f"Verify glimpse {i+1}: predicted={g}, actual={glimpses[i]}, {'OK' if g == glimpses[i] else 'FAIL'}")

# Now predict next 5 full 64-bit states
predictions = []
for i in range(5):
    state = lcg_next(state)
    predictions.append(state)
    print(f"Prediction {i+1}: {state}")

# Send answer
answer = ' '.join(str(p) for p in predictions)
print(f"Sending: {answer}")
sock.send((answer + '\n').encode())

time.sleep(2)
resp = b''
try:
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        resp += chunk
except socket.timeout:
    pass

print("RESPONSE:", resp.decode(errors='replace'))
sock.close()
