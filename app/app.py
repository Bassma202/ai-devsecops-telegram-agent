"""FORGE Demo Service — Hardened minimal Flask microservice deployed behind FORGE security gates."""

from datetime import datetime, timezone
from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/")
def home():
    return jsonify(
        {
            "service": "forge-demo-app",
            "message": "FORGE gate-verified service running as non-root user",
            "status": "operational",
        }
    )


@app.route("/health")
def health():
    return jsonify(
        {
            "status": "healthy",
            "service": "forge-demo-app",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
