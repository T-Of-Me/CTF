#!/usr/bin/env python3
"""
Truncated LCG solver using LLL + enumeration.
"""
import random
import time
from fractions import Fraction
from itertools import product

M = 2**64
A = 2862933555777941757
C = 3037000493
A_JUMP = pow(A, 100000, M)
C_JUMP = 8391006422427229792

B_eff = (A * A_JUMP) % M
D_eff = (A * C_JUMP + C) % M
B2 = (B_eff * B_eff) % M

def lll_reduce(basis, delta=0.99):
    n = len(basis)
    m = len(basis[0])
    B = [[Fraction(basis[i][j]) for j in range(m)] for i in range(n)]

    def dot(u, v):
        return sum(u[k]*v[k] for k in range(m))

    def gs():
        ortho = [list(row) for row in B]
        mu = [[Fraction(0)]*n for _ in range(n)]
        for i in range(n):
            for j in range(i):
                d = dot(ortho[j], ortho[j])
                if d == 0:
                    mu[i][j] = Fraction(0)
                else:
                    mu[i][j] = dot(B[i], ortho[j]) / d
                for k in range(m):
                    ortho[i][k] -= mu[i][j] * ortho[j][k]
        return ortho, mu

    k = 1
    while k < n:
        ortho, mu = gs()
        for j in range(k-1, -1, -1):
            if abs(mu[k][j]) > Fraction(1, 2):
                r = round(mu[k][j])
                for l in range(m):
                    B[k][l] -= r * B[j][l]
                ortho, mu = gs()
        d_k = dot(ortho[k], ortho[k])
        d_k1 = dot(ortho[k-1], ortho[k-1])
        if d_k >= (Fraction(delta) - mu[k][k-1]**2) * d_k1:
            k += 1
        else:
            B[k], B[k-1] = B[k-1], B[k]
            k = max(k-1, 1)

    return [[int(B[i][j]) for j in range(m)] for i in range(n)]


def solve_truncated_lcg(g1, g2, g3):
    t1 = g1 << 32
    t2 = g2 << 32
    t3 = g3 << 32

    K1 = (B_eff * t1 + D_eff - t2) % M
    K2 = (B_eff * t2 + D_eff - t3) % M
    K12 = (B_eff * K1 + K2) % M

    basis = [
        [M,     0,    0,  0],
        [0,     M,    0,  0],
        [B_eff, B2,   1,  0],
        [K1,    K12,  0,  1],
    ]

    reduced = lll_reduce(basis)

    # Enumerate small linear combinations of reduced basis vectors
    # The solution vector has last component = ±1
    # Try combinations with small coefficients
    R = 3  # range of coefficients to try
    for coeffs in product(range(-R, R+1), repeat=4):
        if all(c == 0 for c in coeffs):
            continue

        v = [0, 0, 0, 0]
        for i in range(4):
            for j in range(4):
                v[j] += coeffs[i] * reduced[i][j]

        c = v[3]
        if c != 1 and c != -1:
            continue

        if c == -1:
            v = [-x for x in v]

        x2_c, x3_c, x1_c, _ = v

        if not (0 <= x1_c < 2**32):
            continue
        if not (0 <= x2_c < 2**32):
            continue

        check_x2 = (B_eff * x1_c + K1) % M
        if check_x2 != x2_c:
            continue

        check_x3 = (B_eff * x2_c + K2) % M
        if 0 <= check_x3 < 2**32:
            return x1_c

    return None


# ============ TEST ============
successes = 0
trials = 20
for trial in range(trials):
    seed = random.randint(1, M - 1)

    class FTR:
        def __init__(self, seed):
            self.state = seed
        def next(self):
            self.state = (A * self.state + C) % M
            return self.state
        def jump(self):
            self.state = (A_JUMP * self.state + C_JUMP) % M
        def glimpse(self):
            return self.next() >> 32

    ft = FTR(seed)
    g1 = ft.glimpse(); s1_actual = ft.state
    ft.jump()
    g2 = ft.glimpse()
    ft.jump()
    g3 = ft.glimpse(); s3_actual = ft.state

    t0 = time.time()
    x1 = solve_truncated_lcg(g1, g2, g3)
    dt = time.time() - t0

    if x1 is not None:
        s1_recovered = (g1 << 32) | x1
        ok = s1_recovered == s1_actual

        s2_r = (B_eff * s1_recovered + D_eff) % M
        s3_r = (B_eff * s2_r + D_eff) % M
        ft.jump()
        g4_actual = ft.glimpse()
        s3p = (A_JUMP * s3_r + C_JUMP) % M
        s4 = (A * s3p + C) % M
        pred_ok = (s4 >> 32) == g4_actual

        if ok and pred_ok:
            successes += 1
            print(f"Trial {trial+1}: OK ({dt:.2f}s)")
        else:
            print(f"Trial {trial+1}: WRONG ANSWER ({dt:.2f}s)")
    else:
        print(f"Trial {trial+1}: FAILED ({dt:.2f}s)")

print(f"\n{successes}/{trials} successful")
