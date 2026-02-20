#!/usr/bin/env python3
import os
import threading
from pathlib import Path
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request
from playwright.sync_api import sync_playwright


BOT_SECRET_FILE = Path("/shared/bot/token.txt")


def create_app():
    app = Flask(__name__)
    app.config["TARGET_BASE"] = os.environ.get("TARGET_BASE", "http://web:5000")
    app.config["BOT_HEADLESS"] = os.environ.get("BOT_HEADLESS", "1") not in {"0", "false", "False"}

    @app.route("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.route("/visit", methods=["POST"])
    def visit():
        token = load_bot_token()
        if request.headers.get("X-Bot-Auth") != token:
            return jsonify({"error": "forbidden"}), 403

        body = request.get_json(silent=True) or {}
        url = (body.get("url") or "").strip()
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return jsonify({"error": "invalid url"}), 400

        worker = threading.Thread(
            target=_visit_worker,
            kwargs={
                "target_base": app.config["TARGET_BASE"],
                "url": url,
                "headless": app.config["BOT_HEADLESS"],
                "bot_token": token,
            },
            daemon=True,
        )
        worker.start()
        return jsonify({"status": "queued"})

    return app


def load_bot_token() -> str:
    if BOT_SECRET_FILE.exists():
        val = BOT_SECRET_FILE.read_text(encoding="utf-8", errors="ignore").strip()
        if val:
            return val
    return os.environ.get("BOT_TOKEN", "bot-sync-9a1d")


def seed_admin_session(target_base: str, bot_token: str):
    sess = requests.Session()
    resp = sess.post(
        f"{target_base}/internal/bot/session",
        headers={"X-Bot-Auth": bot_token},
        timeout=10,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"bot session seed failed: {resp.status_code}")
    return sess.cookies.get_dict()


def run_visit(target_base: str, url: str, headless: bool, bot_token: str):
    cookies = seed_admin_session(target_base=target_base, bot_token=bot_token)

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=headless,
            args=[
                "--no-sandbox",
                "--disable-popup-blocking",
                "--enable-features=BackForwardCache",
                "--disable-features=SameSiteByDefaultCookies,CookiesWithoutSameSiteMustBeSecure",
            ],
        )
        context = browser.new_context()
        cookie_list = []
        for key, value in cookies.items():
            cookie_list.append({"name": key, "value": value, "url": target_base})
        if cookie_list:
            context.add_cookies(cookie_list)

        page = context.new_page()
        page.goto(f"{target_base}/", wait_until="domcontentloaded", timeout=15000)
        page.goto(url, wait_until="domcontentloaded", timeout=15000)
        page.wait_for_timeout(18000)
        browser.close()


def _visit_worker(target_base: str, url: str, headless: bool, bot_token: str):
    try:
        run_visit(target_base=target_base, url=url, headless=headless, bot_token=bot_token)
    except Exception as exc:
        print(f"[bot] visit failed: {exc}")


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7000, debug=False)
