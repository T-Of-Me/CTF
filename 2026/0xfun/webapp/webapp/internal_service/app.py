#!/usr/bin/env python3
import pickle

from flask import Flask, request


def create_app():
    app = Flask(__name__)
    app.config["INTERNAL_AUTH"] = "internal-sync-4a6b"

    @app.route("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.route("/internal/import", methods=["POST"])
    def internal_import():
        if request.headers.get("X-Internal-Auth") != app.config["INTERNAL_AUTH"]:
            return "forbidden", 403
        data = request.get_data()
        obj = pickle.loads(data)
        _process(obj)
        return "ok"

    return app


def _process(_obj):
    return None


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000, debug=False)
