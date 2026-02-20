#!/usr/bin/env python3
from z3 import *
import socket

M = 2**64
A = 2862933555777941757
C = 3037000493
A_JUMP = pow(A, 100000, M)
C_JUMP = 8391006422427229792

# Effective multiplier/increment between glimpses:
# glimpse does next() which is A*s+C, then jump() does A_JUMP*s+C_JUMP
# So from state before glimpse1's next() to state before glimpse2's next():
#   after next(): s1 = A*s0 + C
#   after jump(): s2 = A_JUMP*s1 + C_JUMP
#   next glimpse's next(): s3 = A*s2 + C
# So s3 = A*(A_JUMP*(A*s0+C) + C_JUMP) + C = A*A_JUMP*A*s0 + A*A_JUMP*C + A*C_JUMP + C
# But we observe the output of next(), not the state before.
# Let's track the states that produce the glimpses:
# s1 = A*s0 + C  -> g1 = s1 >> 32
# jump: s1' = A_JUMP*s1 + C_JUMP
# s2 = A*s1' + C -> g2 = s2 >> 32
# jump: s2' = A_JUMP*s2 + C_JUMP
# s3 = A*s2' + C -> g3 = s3 >> 32
#
# s2 = A*(A_JUMP*s1 + C_JUMP) + C = (A*A_JUMP)*s1 + (A*C_JUMP + C)
# s3 = (A*A_JUMP)*s2 + (A*C_JUMP + C)

B = (A * A_JUMP) % M
D = (A * C_JUMP + C) % M

def solve_state(g1, g2, g3):
    x1 = BitVec('x1', 64)

    s1 = (BitVecVal(g1, 64) << 32) | x1
    s2 = B * s1 + D  # mod 2^64 automatic with BitVec
    s3 = B * s2 + D

    solver = Solver()
    solver.add(ULT(x1, BitVecVal(2**32, 64)))
    solver.add(LShR(s2, 32) == BitVecVal(g2, 64))
    solver.add(LShR(s3, 32) == BitVecVal(g3, 64))

    if solver.check() == sat:
        model = solver.model()
        x1_val = model[x1].as_long()
        s1_val = (g1 << 32) | x1_val
        return s1_val
    else:
        print("UNSAT!")
        return None

def predict_next(state):
    # From last glimpse state s3, we need to:
    # jump: s3' = A_JUMP*s3 + C_JUMP
    # next: s4 = A*s3' + C
    # glimpse = s4 >> 32
    s3_prime = (A_JUMP * state + C_JUMP) % M
    s4 = (A * s3_prime + C) % M
    return s4 >> 32, s4

def recvline(s):
    buf = b""
    while not buf.endswith(b"\n"):
        buf += s.recv(1)
    return buf.strip()

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('chall.0xfun.org', 54161))
    f = s.makefile('rb')

    # Read all initial data to understand server format
    import time
    s.settimeout(5)
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            print(f"[raw] {chunk}")
    except socket.timeout:
        pass

    print(f"\n=== All received data ===")
    print(data.decode(errors='replace'))

    # Try to parse glimpses from the data
    lines = data.decode(errors='replace').strip().split('\n')
    print(f"Lines: {lines}")

    # Look for numbers
    numbers = []
    for line in lines:
        line = line.strip()
        try:
            n = int(line)
            numbers.append(n)
        except:
            pass

    print(f"Found numbers: {numbers}")

    if len(numbers) >= 3:
        g1, g2, g3 = numbers[0], numbers[1], numbers[2]
    else:
        print("Not enough numbers found!")
        # Send the remaining data lines for debugging
        s.close()
        return

    print(f"g1 = {g1}")
    print(f"g2 = {g2}")
    print(f"g3 = {g3}")

    # Solve for state
    s1 = solve_state(g1, g2, g3)
    if s1 is None:
        print("Failed to solve!")
        s.close()
        return

    print(f"Recovered s1 = {s1}")

    # Compute s2, s3
    s2_val = (B * s1 + D) % M
    s3_val = (B * s2_val + D) % M

    # Verify
    assert s1 >> 32 == g1
    assert s2_val >> 32 == g2
    assert s3_val >> 32 == g3
    print("Verification passed!")

    # Predict next glimpse
    prediction, s4 = predict_next(s3_val)
    print(f"Prediction: {prediction}")

    s.sendall((str(prediction) + '\n').encode())

    # Read response
    s.settimeout(10)
    try:
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
    except socket.timeout:
        pass

    print(f"\nServer response:\n{response.decode(errors='replace')}")
    s.close()

if __name__ == "__main__":
    main()
