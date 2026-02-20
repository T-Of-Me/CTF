from pwn import *

context.log_level = 'info'

OFFSET = 0xD3ADC0DE
E = 0x10001

def solve_from_one_valid(p):
    p.recvuntil(b"--- Test #")
    p.recvline()

    p.recvuntil(b"n = ")
    n = int(p.recvline().strip())
    log.info(f"n = {n}")

    p.recvuntil(b"You can ask 7 questions:")

    valid_entries = []  # list of (sum_li, sum_ri, enc_li, enc_ri)

    for i in range(7):
        base_li = 50 + i * 10
        base_ri = 200 + i * 10
        li = [base_li + j for j in range(4)]
        ri = [base_ri + j for j in range(4)]
        payload = ' '.join(str(x) for x in (li + ri))
        log.info(f"Query {i+1}: li={li}, ri={ri}")
        p.sendline(payload.encode())

        resp = p.recvline(timeout=5)
        if not resp:
            log.info("No response or blank for this query")
            continue
        line = resp.decode(errors='ignore').strip()
        parts = line.split()
        if len(parts) >= 2:
            enc_li = int(parts[0])
            enc_ri = int(parts[1])
            sum_li = sum(li)
            sum_ri = sum(ri)
            valid_entries.append((sum_li, sum_ri, enc_li, enc_ri))
            log.success(f"Got non-zero response for query {i+1}")
        else:
            log.info(f"Zero or blank for query {i+1}")

    if not valid_entries:
        log.error("No valid entries at all — can't solve this round")
        return None

    # Brute-force secret
    for s in range(2048):
        off = s + OFFSET
        ok = True
        for (sum_li, sum_ri, enc_li, enc_ri) in valid_entries:
            if pow(off * sum_li % n, E, n) != enc_li:
                ok = False
                break
            if pow(off * sum_ri % n, E, n) != enc_ri:
                ok = False
                break
        if ok:
            log.success(f"Found secret = {s}")
            return s

    log.error("Secret not found from valid entries")
    return None

def main():
    p = remote("0.cloud.chals.io", 32957)
    try:
        secret = solve_from_one_valid(p)
        if secret is not None:
            print("Secret:", secret)
            p.sendline(str(secret).encode())
            resp = p.recvline(timeout=5)
            print("Response to guess:", resp.decode(errors='ignore').strip() if resp else "<no response>")
            flag = p.recvall(timeout=5).decode(errors='ignore')
            print("Flag:", flag)
        else:
            print("Could not solve this round.")
    finally:
        p.close()

if __name__ == "__main__":
    main()
