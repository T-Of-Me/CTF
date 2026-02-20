from flask import Flask, request, jsonify
import re

app = Flask(__name__)

def parse_auth_header(auth_header: str):
    """
    Parse Authorization header like:
      Digest username="admin", realm="...", nonce="...", uri="/auth", response="...", ...
    or Basic base64(...)
    Returns dict: {"type":"Digest", "raw":..., "params": {...}} or {"type":"Basic", "raw":..., "credentials": "..."}
    """
    if not auth_header:
        return None

    parts = auth_header.split(None, 1)
    if len(parts) == 0:
        return None
    auth_type = parts[0]
    rest = parts[1] if len(parts) > 1 else ""

    result = {"type": auth_type, "raw": auth_header}

    if auth_type.lower() == "basic":
        result["credentials"] = rest  # base64 payload, client: base64(user:pass)
        return result

    if auth_type.lower() == "digest":
        # find key="value" or key=value tokens (value may be quoted)
        pattern = re.compile(r'([\w\-]+)=("([^"]*)"|([^,\s]*))(?:,?\s*)')
        params = {}
        for m in pattern.finditer(rest):
            key = m.group(1)
            val = m.group(3) if m.group(3) is not None else m.group(4)
            params[key] = val
        result["params"] = params
        return result

    # fallback: return rest as raw params
    result["raw_params"] = rest
    return result

@app.route('/auth', methods=['GET', 'POST', 'PUT', 'DELETE'])
def auth_inspector():
    # Collect request-level info
    headers = dict(request.headers)
    raw_auth = headers.get('Authorization')  # may be None
    parsed = parse_auth_header(raw_auth)

    # Werkzeug's request.authorization may contain some fields (for Basic/Digest) — include if present
    werkzeug_auth = None
    if request.authorization:
        try:
            # convert to dict safely
            werkzeug_auth = {
                "type": request.authorization.type,
                "username": getattr(request.authorization, "username", None),
                "password": getattr(request.authorization, "password", None),
                # some implementations expose other attributes (nonce, response) — include if present
            }
        except Exception:
            werkzeug_auth = str(request.authorization)

    info = {
        "method": request.method,
        "remote_addr": request.remote_addr,
        "path": request.path,
        "args": request.args.to_dict(),
        "json": request.get_json(silent=True),
        "form": request.form.to_dict(),
        "headers": headers,
        "raw_authorization": raw_auth,
        "parsed_authorization": parsed,
        "werkzeug_request_authorization": werkzeug_auth
    }

    # Print to console for real-time inspection
    print("\n=== AUTH INSPECTOR ===")
    print(f"From: {request.remote_addr} {request.method} {request.path}")
    print("Authorization (raw):", raw_auth)
    print("Parsed:", parsed)
    print("Werkzeug request.authorization:", werkzeug_auth)
    print("All headers:")
    for k, v in headers.items():
        print(f"  {k}: {v}")
    print("======================\n")

    # Return JSON so client (or your /api/check) can see what it sent
    return jsonify(info), 200

# Optional helper endpoint to simulate client check (useful for local test)
import requests
from requests.auth import HTTPDigestAuth, HTTPBasicAuth

@app.route('/api/check', methods=['GET'])
def api_check_sim():
    # simple simulator that calls /auth on same host
    user, pw = 'admin', '12345'  # change to match your server's expected creds
    target = request.host_url.rstrip('/') + '/auth'
    try:
        # try digest first
        res = requests.get(target, auth=HTTPDigestAuth(user, pw), timeout=3)
        return jsonify({
            "target": target,
            "status_code": res.status_code,
            "returned_json": res.json() if res.headers.get('Content-Type','').startswith('application/json') else None,
            "response_headers": dict(res.headers)
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    # debug=True will auto-reload and show console prints
    app.run(host='0.0.0.0', port=5001, debug=True)
