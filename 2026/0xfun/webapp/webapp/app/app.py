#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

import requests
from flask import Flask, flash, g, jsonify, redirect, render_template, request, session, url_for
from lxml import etree


APP_ROOT = Path("/var/app")
INSTANCE_DIR = APP_ROOT / "instance"
DB_PATH = INSTANCE_DIR / "perimeter.db"
UPLOAD_DIR = Path("/var/app/uploads")
REVIEW_MATERIAL_DIR = APP_ROOT / "review-materials"
KEYS_DIR = APP_ROOT / "keys"
SHARED_LOOT_DIR = Path("/shared/loot")
BOT_SECRET_FILE = Path("/shared/bot/token.txt")
SESSION_SECRET_FILE = INSTANCE_DIR / "session_secret.txt"
BOOTSTRAP_TICKET_FILE = INSTANCE_DIR / "bootstrap_ticket.txt"
SSO_VERIFY_KEY_FILE = INSTANCE_DIR / "sso_verify_key.txt"

DEFAULT_INTERNAL_AUTH = "internal-sync-4a6b"
DEFAULT_INTERNAL_SINK = "http://internal:9000/internal/import"

SSO_RESEARCHER_USERNAME = "nora.v"
SSO_EMAIL_SUFFIX = "@drift.com"
SSO_KID = "partner-main"
SSO_ISSUER = "https://sso.partner.local"
SSO_AUDIENCE = "perimeter-drift-web"
SSO_PUBLIC_N = "u5opYFk7j2wvkYx4fLJ-U6f6poC35MZppL8XrNHElY5x4jkCzV2xN53nO22_r3H6myA42hM0WjvQx8yA8hJQ4w"
SSO_PUBLIC_E = "AQAB"
BOOTSTRAP_PROGRAM_TITLE = "Bootstrap Session Runbook"

VALID_WORKSPACE_KEYS = set()
SSO_JWKS_CACHE = {}

PROGRAM_SEEDS = [
    {
        "title": "Disclosure Partner Calendar",
        "keywords": ["vendor", "calendar", "rotation", "quarter"],
        "preview": "Coordination calendar for partner programs and disclosure timelines.",
    },
    {
        "title": "Triage Escalation Matrix",
        "keywords": ["soc", "escalation", "ops", "pager", "review"],
        "preview": "Routing matrix for researcher submissions and reviewer validation lanes.",
    },
    {
        "title": "Research Workspace Loader",
        "keywords": ["ops-loader", "loader", "import", "modular"],
        "preview": "Legacy workspace module references used by report validation tooling.",
    },
    {
        "title": "Privileged Role Sync Bundle",
        "keywords": ["admin", "roles", "bundle", "bootstrap"],
        "preview": "Privileged UI bundle notes for emergency triage and recovery workflows.",
    },
    {
        "title": "Program: Northwind Commerce",
        "keywords": ["northwind", "ecommerce", "api", "web"],
        "preview": "E-commerce storefront program scope covering web checkout, partner APIs, and fraud controls.",
    },
    {
        "title": "Program: Atlas Payments",
        "keywords": ["atlas", "payments", "fintech", "webhook", "api"],
        "preview": "Payments processing program covering onboarding, payouts, webhooks, and reporting surfaces.",
    },
    {
        "title": "Program: Specter Mobile",
        "keywords": ["specter", "mobile", "android", "ios", "client"],
        "preview": "Mobile client program scope including transport security, session handling, and device storage.",
    },
    {
        "title": "Program: Redline CDN",
        "keywords": ["redline", "cdn", "edge", "http", "cache"],
        "preview": "Edge caching program covering cache key derivation, request normalization, and origin shielding.",
    },
    {
        "title": "Program: Orpheus SaaS",
        "keywords": ["orpheus", "saas", "oidc", "sso", "auth"],
        "preview": "SaaS platform program scope covering sign-in flows, tenant isolation, and identity integrations.",
    },
    {
        "title": "Internal: Disclosure Comms Template",
        "keywords": ["comms", "template", "email", "coordinated"],
        "preview": "Standard communications templates used for coordinated disclosure updates and acknowledgements.",
    },
    {
        "title": "Internal: Proof of Concept Guidelines",
        "keywords": ["poc", "template", "repro", "impact"],
        "preview": "Guidance for minimal proof-of-concept submissions, safe reproduction, and impact statements.",
    },
]

VULN_TYPES = [
    "IDOR",
    "Broken Access Control",
    "XSS",
    "CSRF",
    "SSRF",
    "XXE",
    "Deserialization",
    "RCE",
    "Sandbox Escape",
    "Authentication Bypass",
    "SQLi",
    "LFI/RFI",
    "Other",
]

LOCAL_USERS = [
    {
        "username": "isaac.r",
        "role": "reviewer",
        "display_name": "Isaac Rowe",
        "email": "isaac.rowe@drift.com",
        "password_env": "REVIEWER_PASSWORD",
        "default_password": "",
    },
    {
        "username": "olivia.m",
        "role": "admin",
        "display_name": "Olivia Marsh",
        "email": "olivia.marsh@drift.com",
        "password_env": "ADMIN_PASSWORD",
        "default_password": "",
    },
]

SSO_RESEARCHER_USER = {
    "username": SSO_RESEARCHER_USERNAME,
    "role": "researcher",
    "display_name": "Nora Vale",
    "email": "nora.vale@drift.com",
}

DEFAULT_BIO = ""


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("APP_SECRET") or load_or_create_secret(SESSION_SECRET_FILE)
    app.config["SESSION_COOKIE_SAMESITE"] = None
    app.config["SESSION_COOKIE_SECURE"] = False
    app.config["BOOTSTRAP_TICKET"] = os.environ.get("BOOTSTRAP_TICKET") or load_or_create_bootstrap_ticket(
        BOOTSTRAP_TICKET_FILE
    )
    app.config["INTERNAL_AUTH"] = os.environ.get("INTERNAL_AUTH", DEFAULT_INTERNAL_AUTH)
    app.config["INTERNAL_SINK"] = os.environ.get("INTERNAL_SINK", DEFAULT_INTERNAL_SINK)
    app.config["BOT_URL"] = os.environ.get("BOT_URL", "http://bot:7000/visit")
    app.config["BOT_TOKEN"] = load_or_create_secret(BOT_SECRET_FILE)
    app.config["SSO_ISSUER"] = os.environ.get("SSO_ISSUER", SSO_ISSUER)
    app.config["SSO_AUDIENCE"] = os.environ.get("SSO_AUDIENCE", SSO_AUDIENCE)
    app.config["SSO_VERIFY_KEY"] = os.environ.get("SSO_VERIFY_KEY") or load_or_create_secret(SSO_VERIFY_KEY_FILE)
    try:
        app.config["SSO_JWKS_CACHE_TTL"] = int(os.environ.get("SSO_JWKS_CACHE_TTL", "180"))
    except Exception:
        app.config["SSO_JWKS_CACHE_TTL"] = 180

    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    REVIEW_MATERIAL_DIR.mkdir(parents=True, exist_ok=True)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    SHARED_LOOT_DIR.mkdir(parents=True, exist_ok=True)
    ensure_reviewer_key()

    @app.teardown_appcontext
    def close_db(_error):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.after_request
    def add_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-src 'self'; "
            "object-src 'none'; "
            "base-uri 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.context_processor
    def inject_user():
        return {"current_user": get_current_user()}

    @app.route("/healthz")
    def healthz():
        return jsonify({"status": "ok"})

    @app.route("/.well-known/openid-configuration", methods=["GET"])
    def openid_configuration():
        root = request.host_url.rstrip("/")
        return jsonify(
            {
                "issuer": app.config["SSO_ISSUER"],
                "jwks_uri": f"{root}/sso/jwks.json",
                "response_types_supported": ["id_token"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "client_id": app.config["SSO_AUDIENCE"],
            }
        )

    @app.route("/sso/jwks.json", methods=["GET"])
    def sso_jwks():
        return jsonify(
            {
                "keys": [
                    {
                        "kid": SSO_KID,
                        "kty": "RSA",
                        "alg": "RS256",
                        "use": "sig",
                        "n": SSO_PUBLIC_N,
                        "e": SSO_PUBLIC_E,
                    }
                ]
            }
        )

    @app.route("/sso/start", methods=["GET"])
    def sso_start():
        redirect_uri = url_for("sso_callback", _external=True)
        target = (
            f"{app.config['SSO_ISSUER']}/authorize"
            f"?client_id={app.config['SSO_AUDIENCE']}"
            f"&response_type=id_token"
            f"&redirect_uri={redirect_uri}"
        )
        return redirect(target)

    @app.route("/sso/callback", methods=["GET"])
    def sso_callback():
        raw = request.args.get("id_token", "").strip()
        if not raw:
            return "Authentication response missing token.", 400

        claims = verify_sso_id_token(raw, app.config)
        if not claims:
            return "Authentication token validation failed.", 403

        if claims.get("iss") != app.config["SSO_ISSUER"]:
            return "Authentication provider mismatch.", 403
        if claims.get("aud") != app.config["SSO_AUDIENCE"]:
            return "Application audience mismatch.", 403

        now = int(time.time())
        exp = int(claims.get("exp", 0) or 0)
        if exp and exp < now:
            return "Authentication token expired.", 403

        email = str(claims.get("email", "")).strip().lower()
        if not email.endswith(SSO_EMAIL_SUFFIX):
            return "Account is not authorized for this tenant.", 403

        db = get_db()
        user = db.execute(
            "SELECT id, username, role, display_name, email, auth_source FROM users WHERE username = ?",
            (SSO_RESEARCHER_USERNAME,),
        ).fetchone()

        if user and user["auth_source"] == "sso" and user["role"] != "researcher":
            db.execute("UPDATE users SET role = 'researcher' WHERE id = ?", (user["id"],))
            db.commit()
            user = db.execute(
                "SELECT id, username, role, display_name, email, auth_source FROM users WHERE username = ?",
                (SSO_RESEARCHER_USERNAME,),
            ).fetchone()

        if user and user["auth_source"] != "sso":
            return "This account must use internal sign-in.", 403

        if not user:
            display_name = str(claims.get("name") or "Contract Researcher").strip()[:80] or "Contract Researcher"
            cur = db.execute(
                "INSERT INTO users(username, password, role, display_name, email, auth_source, sso_sub) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    SSO_RESEARCHER_USERNAME,
                    secrets.token_urlsafe(20),
                    "researcher",
                    display_name,
                    email,
                    "sso",
                    f"{claims.get('iss', '')}|{claims.get('sub', '')}",
                ),
            )
            db.execute("INSERT INTO profiles(user_id, bio) VALUES (?, ?)", (cur.lastrowid, DEFAULT_BIO))
            db.commit()
            user = db.execute(
                "SELECT id, username, role, display_name, email, auth_source FROM users WHERE id = ?",
                (cur.lastrowid,),
            ).fetchone()

        set_session_from_user(user)
        return redirect(url_for("dashboard"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            db = get_db()
            user = db.execute(
                "SELECT id, username, role, display_name, email, auth_source FROM users "
                "WHERE username = ? AND password = ? AND auth_source = 'local'",
                (username, password),
            ).fetchone()
            if user:
                set_session_from_user(user)
                return redirect(url_for("dashboard"))
            flash("Sign-in failed. Please verify your credentials.", "error")
        return render_template("login.html")

    @app.route("/logout", methods=["GET"])
    def logout():
        preserved_until = int(session.get("ephemeral_admin_until", 0) or 0)
        session.clear()
        if preserved_until and int(time.time()) < preserved_until:
            session["ephemeral_admin_until"] = preserved_until
        if request.args.get("return") == "back":
            return (
                "<!doctype html><html><body style='background:#080808;color:#ddd;font-family:monospace'>"
                "<p>Session closed. Returning to previous view...</p>"
                "<script>setTimeout(() => history.back(), 500);</script>"
                "</body></html>"
            )
        flash("You have been signed out.", "info")
        return redirect(url_for("login"))

    @app.route("/", methods=["GET"])
    def landing():
        if session.get("uid"):
            user = get_current_user()
            if user:
                return redirect(url_for("dashboard"))
        return render_template("landing.html")

    @app.route("/dashboard", methods=["GET"])
    @login_required
    def dashboard():
        db = get_db()
        role = session.get("role", "")
        uid = session.get("uid")
        if role in {"reviewer", "admin"}:
            reports = db.execute(
                "SELECT r.id, r.title, r.vuln_type, r.created_at, "
                "u.display_name AS reporter_name, u.username AS reporter_username "
                "FROM reports r JOIN users u ON u.id = r.reporter_id "
                "ORDER BY r.id DESC LIMIT 6"
            ).fetchall()
        else:
            reports = db.execute(
                "SELECT r.id, r.title, r.vuln_type, r.created_at, "
                "u.display_name AS reporter_name, u.username AS reporter_username "
                "FROM reports r JOIN users u ON u.id = r.reporter_id "
                "WHERE r.reporter_id = ? ORDER BY r.id DESC LIMIT 6",
                (uid,),
            ).fetchall()
        programs = db.execute(
            "SELECT id, title, preview FROM programs ORDER BY id ASC LIMIT 6"
        ).fetchall()
        return render_template("dashboard.html", docs=programs, reports=reports)

    @app.route("/review/material/upload", methods=["POST"])
    @login_required
    def review_material_upload():
        file_obj = request.files.get("file")
        if not file_obj or not file_obj.filename:
            return jsonify({"error": "No file was provided."}), 400
        filename = Path(file_obj.filename).name
        if not filename:
            return jsonify({"error": "Filename is invalid."}), 400
        target = REVIEW_MATERIAL_DIR / filename
        if target.exists():
            target = REVIEW_MATERIAL_DIR / f"{target.stem}-{secrets.token_hex(3)}{target.suffix}"
        file_obj.save(target)
        return jsonify({"status": "stored", "filename": target.name})

    @app.route("/review/escalate", methods=["POST"])
    @login_required
    def review_escalate():
        raw = request.form.get("grant", "").strip()
        claims = verify_reviewer_grant(raw)
        if not claims:
            return "Authorization token is invalid.", 403
        if claims.get("scope") != "report:submit":
            return "Authorization scope is insufficient.", 403
        session["role"] = "reviewer"
        flash("Reviewer clearance enabled for this session.", "info")
        return redirect(url_for("dashboard"))

    @app.route("/report", methods=["POST"])
    @login_required
    def report():
        if session.get("role") not in {"reviewer", "admin"}:
            return "reviewer role required", 403

        target = request.form.get("url", "").strip()
        parsed = urlparse(target)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            flash("Please provide a valid URL.", "error")
            return redirect(url_for("dashboard"))

        try:
            resp = requests.post(
                app.config["BOT_URL"],
                json={"url": target},
                headers={"X-Bot-Auth": app.config["BOT_TOKEN"]},
                timeout=20,
            )
            if resp.status_code == 200:
                flash("Validation request has been queued.", "info")
            else:
                flash("Validation service rejected the request.", "error")
        except Exception:
            flash("Validation service is unavailable.", "error")

        return redirect(url_for("dashboard"))

    @app.route("/api/me", methods=["GET"])
    @login_required
    def me():
        user = get_current_user()
        return jsonify(
            {
                "username": user["username"],
                "display_name": user["display_name"],
                "email": user["email"],
                "role": user["role"],
            }
        )

    @app.route("/search", methods=["GET"])
    @login_required
    def search():
        return render_template("search.html", query=request.args.get("q", ""))

    @app.route("/api/search", methods=["GET"])
    @login_required
    def api_search():
        q = request.args.get("q", "").strip().lower()
        if not q:
            return jsonify([])
        like = f"%{q}%"
        db = get_db()
        if session.get("role") == "admin":
            rows = db.execute(
                "SELECT id, title FROM programs "
                "WHERE lower(title) LIKE ? OR lower(keywords) LIKE ? "
                "ORDER BY id ASC LIMIT 8",
                (like, like),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT id, title FROM programs "
                "WHERE (lower(title) LIKE ? OR lower(keywords) LIKE ?) "
                "AND lower(title) != lower(?) "
                "ORDER BY id ASC LIMIT 8",
                (like, like, BOOTSTRAP_PROGRAM_TITLE),
            ).fetchall()
        return jsonify([{"id": r["id"], "title": r["title"]} for r in rows])

    @app.route("/preview/<int:item_id>", methods=["GET"])
    @login_required
    def preview(item_id):
        db = get_db()
        doc = db.execute(
            "SELECT id, title, preview FROM programs WHERE id = ?",
            (item_id,),
        ).fetchone()
        if not doc:
            return "Not found", 404
        return render_template("preview.html", doc=doc)

    @app.route("/reports", methods=["GET"])
    @login_required
    def reports_index():
        db = get_db()
        role = session.get("role", "")
        uid = session.get("uid")
        if role in {"reviewer", "admin"}:
            rows = db.execute(
                "SELECT r.id, r.title, r.vuln_type, r.created_at, "
                "u.display_name AS reporter_name, u.username AS reporter_username "
                "FROM reports r JOIN users u ON u.id = r.reporter_id "
                "ORDER BY r.id DESC"
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT r.id, r.title, r.vuln_type, r.created_at, "
                "u.display_name AS reporter_name, u.username AS reporter_username "
                "FROM reports r JOIN users u ON u.id = r.reporter_id "
                "WHERE r.reporter_id = ? ORDER BY r.id DESC",
                (uid,),
            ).fetchall()
        return render_template("reports.html", reports=rows)

    @app.route("/reports/new", methods=["GET", "POST"])
    @login_required
    def report_new():
        user = get_current_user()
        if user["role"] != "researcher":
            flash("Report submission is restricted to researchers.", "error")
            return redirect(url_for("reports_index"))
        if request.method == "POST":
            title = (request.form.get("title") or "").strip()
            vuln_type = (request.form.get("vuln_type") or "").strip()
            report_blob = request.form.get("report") or request.form.get("body") or ""

            if not title or not vuln_type or not report_blob:
                flash("Please complete all report fields.", "error")
                return redirect(url_for("report_new"))

            if vuln_type not in VULN_TYPES:
                flash("Please select a valid vulnerability type.", "error")
                return redirect(url_for("report_new"))

            if len(title) > 120:
                title = title[:120]
            if len(vuln_type) > 48:
                vuln_type = vuln_type[:48]

            target = ""
            db = get_db()
            cur = db.execute(
                "INSERT INTO reports(reporter_id, title, vuln_type, target, body_html, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (user["id"], title, vuln_type, target, report_blob[:7000], int(time.time())),
            )
            db.commit()
            return redirect(url_for("report_view", report_id=cur.lastrowid))

        return render_template("report_new.html", vuln_types=VULN_TYPES)

    @app.route("/reports/<int:report_id>", methods=["GET"])
    @login_required
    def report_view(report_id):
        user = get_current_user()
        db = get_db()
        row = db.execute(
            "SELECT r.id, r.reporter_id, r.title, r.vuln_type, r.body_html, r.created_at, "
            "u.display_name AS reporter_name, u.username AS reporter_username, u.email AS reporter_email "
            "FROM reports r JOIN users u ON u.id = r.reporter_id WHERE r.id = ?",
            (report_id,),
        ).fetchone()
        if not row:
            return "Not found", 404

        role = session.get("role", "")
        if role not in {"reviewer", "admin"} and int(row["reporter_id"]) != int(user["id"]):
            return "Access denied.", 403

        state_json = json.dumps({"debug": False, "module": "ops/loader"})
        return render_template("report_view.html", report=row, state_json=state_json)

    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    def profile():
        user = get_current_user()
        db = get_db()
        viewed = user
        target_username = request.args.get("u", "").strip()
        if target_username:
            maybe = db.execute(
                "SELECT id, username, role, display_name FROM users WHERE username = ?",
                (target_username,),
            ).fetchone()
            if maybe:
                viewed = maybe
        editable = viewed["id"] == user["id"]

        if request.method == "POST":
            if not editable:
                return "Access denied.", 403
            bio = request.form.get("bio", "")
            db.execute("UPDATE profiles SET bio = ? WHERE user_id = ?", (bio[:7000], user["id"]))
            db.commit()
            flash("Profile changes saved.", "info")
            return redirect(url_for("profile", **request.args.to_dict()))

        row = db.execute("SELECT bio FROM profiles WHERE user_id = ?", (viewed["id"],)).fetchone()
        bio = row["bio"] if row else ""
        return render_template(
            "profile.html",
            bio=bio,
            viewed_user=viewed,
            editable=editable,
        )

    @app.route("/auth/bootstrap", methods=["GET"])
    @login_required
    def auth_bootstrap():
        if session.get("role") != "admin":
            return "Access denied.", 403
        ticket = request.args.get("ticket", "")
        if ticket != app.config["BOOTSTRAP_TICKET"]:
            return "Access token is invalid.", 403
        session["ephemeral_admin_until"] = int(time.time()) + 25
        return redirect(url_for("admin"))

    @app.route("/internal/bot/session", methods=["POST"])
    def internal_bot_session():
        if request.headers.get("X-Bot-Auth") != app.config["BOT_TOKEN"]:
            return jsonify({"error": "forbidden"}), 403
        db = get_db()
        admin_user = db.execute(
            "SELECT id, username, role, display_name, email, auth_source "
            "FROM users WHERE role = 'admin' AND auth_source = 'local' LIMIT 1"
        ).fetchone()
        if not admin_user:
            return jsonify({"error": "Required administrative account is unavailable."}), 500
        set_session_from_user(admin_user)
        return jsonify({"status": "ok"})

    @app.route("/admin", methods=["GET"])
    @admin_required
    def admin():
        if request.args.get("bounce") == "1":
            until = int(session.get("ephemeral_admin_until", 0) or 0)
            if int(time.time()) >= until:
                return "Access denied.", 403
        workspace_key = secrets.token_urlsafe(18)
        VALID_WORKSPACE_KEYS.add(workspace_key)
        return render_template("admin.html", workspace_key=workspace_key, internal_sink=app.config["INTERNAL_SINK"])

    @app.route("/admin/upload", methods=["POST"])
    def admin_upload():
        if not workspace_key_valid(request):
            return jsonify({"error": "UI authorization key is missing."}), 403
        f = request.files.get("file")
        if not f or not f.filename:
            return jsonify({"error": "No file was provided."}), 400
        filename = Path(f.filename).name
        stored = UPLOAD_DIR / filename
        f.save(stored)
        return jsonify({"status": "stored", "path": str(stored)})

    @app.route("/admin/xml/import", methods=["POST"])
    def admin_xml_import():
        if not workspace_key_valid(request):
            return jsonify({"error": "UI authorization key is missing."}), 403
        xml_blob = request.form.get("xml", "")
        if not xml_blob:
            xml_blob = request.get_data(as_text=True)
        parser = etree.XMLParser(resolve_entities=False, load_dtd=False)
        try:
            tree = etree.fromstring(xml_blob.encode(), parser)

            pre_text = "".join(tree.itertext()).strip()
            if pre_text:
                return jsonify({"error": "Inline payloads are not supported. Upload an artifact and reference it via XInclude."}), 400

            includes = tree.findall(".//{http://www.w3.org/2001/XInclude}include")
            if not includes:
                return jsonify({"error": "Import payload must reference an uploaded artifact."}), 400

            upload_root = UPLOAD_DIR.resolve()
            for inc in includes:
                href = str(inc.get("href", "") or "").strip()
                parsed_href = urlparse(href)
                if parsed_href.scheme != "file":
                    return jsonify({"error": "Import payload must reference an uploaded artifact."}), 400
                include_path = Path(parsed_href.path).resolve()
                if include_path != upload_root and upload_root not in include_path.parents:
                    return jsonify({"error": "Import payload must reference an uploaded artifact."}), 400

            etree.XInclude()(tree)
            sink = tree.get("sink", app.config["INTERNAL_SINK"])
            blob_text = "".join(tree.itertext()).strip()
            payload = base64.b64decode(blob_text)
            requests.post(
                sink,
                data=payload,
                headers={"X-Internal-Auth": app.config["INTERNAL_AUTH"]},
                timeout=4,
            )
            return jsonify({"status": "queued", "sink": sink})
        except Exception:
            return jsonify({"status": "queued", "sink": "unknown"})

    @app.route("/recovery/latest", methods=["GET"])
    def recovery_latest():
        target = SHARED_LOOT_DIR / "flag.txt"
        if target.exists():
            return target.read_text(encoding="utf-8", errors="ignore")
        return "No records available."

    return app


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


def get_current_user():
    uid = session.get("uid")
    if not uid:
        return None
    db = get_db()
    row = db.execute(
        "SELECT id, username, role, display_name, email FROM users WHERE id = ?",
        (uid,),
    ).fetchone()
    if not row:
        return None

    user = dict(row)
    effective_role = session.get("role")
    if effective_role:
        user["role"] = effective_role
    return user


def set_session_from_user(user):
    session.clear()
    session["uid"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    session["display_name"] = user["display_name"]
    if "email" in user.keys():
        session["email"] = user["email"]


def login_required(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        if not session.get("uid"):
            return redirect(url_for("login"))
        return handler(*args, **kwargs)

    return wrapped


def admin_required(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        until = session.get("ephemeral_admin_until", 0)
        if int(time.time()) < int(until):
            return handler(*args, **kwargs)
        if not session.get("uid"):
            return redirect(url_for("login"))
        role = session.get("role", "")
        if role == "admin":
            return handler(*args, **kwargs)
        return "Access denied.", 403

    return wrapped


def workspace_key_valid(req):
    key = req.headers.get("X-Workspace-Key") or req.form.get("workspace_key")
    return bool(key and key in VALID_WORKSPACE_KEYS)


def init_db():
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS profiles;
        DROP TABLE IF EXISTS reports;
        DROP TABLE IF EXISTS programs;

        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            display_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            auth_source TEXT NOT NULL,
            sso_sub TEXT
        );

        CREATE TABLE profiles (
            user_id INTEGER PRIMARY KEY,
            bio TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );


        CREATE TABLE programs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            keywords TEXT NOT NULL,
            preview TEXT NOT NULL
        );

        CREATE TABLE reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            vuln_type TEXT NOT NULL,
            target TEXT NOT NULL,
            body_html TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (reporter_id) REFERENCES users(id)
        );
        """
    )
    for user in LOCAL_USERS:
        password = os.environ.get(user["password_env"], user["default_password"])
        if not password:
            password = secrets.token_urlsafe(24)
        cur = db.execute(
            "INSERT INTO users(username, password, role, display_name, email, auth_source, sso_sub) "
            "VALUES (?, ?, ?, ?, ?, ?, NULL)",
            (
                user["username"],
                password,
                user["role"],
                user["display_name"],
                user["email"],
                "local",
            ),
        )
        db.execute("INSERT INTO profiles(user_id, bio) VALUES (?, ?)", (cur.lastrowid, DEFAULT_BIO))

    researcher = SSO_RESEARCHER_USER
    cur = db.execute(
        "INSERT INTO users(username, password, role, display_name, email, auth_source, sso_sub) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            researcher["username"],
            "SSO_ONLY_ACCOUNT",
            researcher["role"],
            researcher["display_name"],
            researcher["email"],
            "sso",
            f"{SSO_ISSUER}|seeded-{researcher['username']}",
        ),
    )
    db.execute("INSERT INTO profiles(user_id, bio) VALUES (?, ?)", (cur.lastrowid, DEFAULT_BIO))

    for program in PROGRAM_SEEDS:
        db.execute(
            "INSERT INTO programs(title, keywords, preview) VALUES (?, ?, ?)",
            (program["title"], " ".join(program["keywords"]), program["preview"]),
        )
    db.execute(
        "INSERT INTO programs(title, keywords, preview) VALUES (?, ?, ?)",
        (
            BOOTSTRAP_PROGRAM_TITLE,
            f"ticket bootstrap bt-prefix {app.config['BOOTSTRAP_TICKET']}",
            "Protected session transition token reference used by privileged role sync tooling.",
        ),
    )

    db.commit()
    db.close()


def load_or_create_secret(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        value = path.read_text(encoding="utf-8", errors="ignore").strip()
        if value:
            return value
    value = secrets.token_urlsafe(28)
    path.write_text(value, encoding="utf-8")
    return value


def load_or_create_bootstrap_ticket(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        value = path.read_text(encoding="utf-8", errors="ignore").strip()
        if value:
            return value
    value = f"bt-{secrets.token_hex(2)}"
    path.write_text(value, encoding="utf-8")
    return value


def ensure_reviewer_key():
    key_file = KEYS_DIR / "reviewer.pem"
    if key_file.exists():
        return
    key_file.write_bytes(secrets.token_bytes(32))


def b64url_decode(raw: str) -> bytes:
    padding = "=" * ((4 - len(raw) % 4) % 4)
    return base64.urlsafe_b64decode((raw + padding).encode())


def parse_jwt_parts(raw: str):
    try:
        head_b64, body_b64, sig_b64 = raw.split(".", 2)
        header = json.loads(b64url_decode(head_b64).decode())
        payload = json.loads(b64url_decode(body_b64).decode())
        signature = b64url_decode(sig_b64)
        return header, payload, signature, f"{head_b64}.{body_b64}".encode()
    except Exception:
        return None, None, None, None


def verify_sso_id_token(raw: str, cfg):
    header, payload, signature, signing_input = parse_jwt_parts(raw)
    if not header or not payload:
        return None

    alg = str(header.get("alg", "RS256"))
    if alg != "RS256":
        return None

    kid = str(header.get("kid", "")).strip()
    if not kid:
        return None

    jku = str(header.get("jku", "")).strip()
    if jku:
        refresh_sso_jwks_cache(jku, int(cfg.get("SSO_JWKS_CACHE_TTL", 180) or 180))

    key_material = cached_sso_key_for_kid(kid)
    if not key_material and kid == SSO_KID:
        key_material = str(cfg.get("SSO_VERIFY_KEY", "") or "")
    if not key_material:
        return None

    expected = hmac.new(key_material.encode(), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, signature):
        return None
    return payload


def refresh_sso_jwks_cache(jku: str, ttl: int):
    parsed = urlparse(jku)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return

    try:
        response = requests.get(jku, timeout=2)
        response.raise_for_status()
        data = response.json()
    except Exception:
        return

    keys = data.get("keys") or []
    now = int(time.time())
    expiry = now + max(15, min(int(ttl or 180), 1200))
    for entry in keys:
        kid = str(entry.get("kid", "")).strip()
        material = str(entry.get("k", "")).strip()
        if kid and material:
            SSO_JWKS_CACHE[kid] = {"key": material, "exp": expiry}


def cached_sso_key_for_kid(kid: str):
    now = int(time.time())
    item = SSO_JWKS_CACHE.get(kid)
    if not item:
        return None
    if int(item.get("exp", 0) or 0) < now:
        SSO_JWKS_CACHE.pop(kid, None)
        return None
    key = str(item.get("key", "")).strip()
    if not key:
        return None
    return key


def verify_reviewer_grant(raw: str):
    header, payload, signature, signing_input = parse_jwt_parts(raw)
    if not header or not payload:
        return None

    kid = str(header.get("kid", "reviewer"))
    key_path = KEYS_DIR / f"{kid}.pem"
    try:
        key = key_path.read_bytes()
    except Exception:
        return None

    expected = hmac.new(key, signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, signature):
        return None
    return payload


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
