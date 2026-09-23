"""Config-gated demo API used to exercise the FuzzRex orchestrator.

Security-relevant switches live in config.json so joint config x API
fuzzing has observable differential behavior to hunt for.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from flask import Flask, jsonify

CONFIG_PATH = Path(os.environ.get("CONFIG_PATH", "/app/config.json"))
app = Flask(__name__)


def load_config() -> dict:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.get("/api/info")
def info():
    config = load_config()
    payload = {"service": "demo-api", "greeting": config.get("greeting", "hi")}
    if config.get("debug"):
        # Intentional: debug mode leaks internals.
        payload["debug"] = {
            "cwd": os.getcwd(),
            "config": config,
            "stack": "Traceback (most recent call last): ...",
        }
    return jsonify(payload)


@app.get("/api/admin")
def admin():
    config = load_config()
    if config.get("require_auth"):
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"role": "admin", "action": "list_users"})


@app.get("/api/greeting")
def greeting():
    return jsonify({"greeting": load_config().get("greeting", "hi")})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
