"""FORGE Demo Service — Hardened minimal Flask microservice deployed behind FORGE security gates."""

from __future__ import annotations

import os
from datetime import datetime, timezone

from flask import Flask, jsonify

app = Flask(__name__)

RELEASE_VERSION = os.environ.get("FORGE_RELEASE_VERSION", "2.0.0")
ARTIFACT_SHA256 = os.environ.get("FORGE_ARTIFACT_SHA256", "unset")


@app.route("/")
def home():
    return jsonify(
        {
            "service": "forge-demo-app",
            "version": RELEASE_VERSION,
            "artifact_sha256": ARTIFACT_SHA256,
            "message": "FORGE gate-verified service running as non-root user",
            "status": "operational",
        }
    )


@app.route("/version")
def version():
    return jsonify(
        {
            "service": "forge-demo-app",
            "version": RELEASE_VERSION,
            "artifact_sha256": ARTIFACT_SHA256,
        }
    )


@app.route("/health")
def health():
    if os.environ.get("FORGE_FORCE_UNHEALTHY", "0") == "1":
        return jsonify({"status": "unhealthy", "version": RELEASE_VERSION}), 503
    return jsonify(
        {
            "status": "healthy",
            "service": "forge-demo-app",
            "version": RELEASE_VERSION,
            "artifact_sha256": ARTIFACT_SHA256,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


if __name__ == "__main__":
    port = int(os.environ.get("FORGE_PORT", "5000"))
    app.run(host="127.0.0.1", port=port)
