from flask import Flask, jsonify
from datetime import datetime

app = Flask(__name__)


@app.route("/")
def home():
    return jsonify({
        "message": "DevSecOps Telegram-controlled app is running",
        "status": "success"
    })


@app.route("/health")
def health():
    return jsonify({
        "status": "healthy",
        "service": "ai-devsecops-telegram-agent",
        "timestamp": datetime.utcnow().isoformat()
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)