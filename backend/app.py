import json
import logging
import os
from datetime import datetime

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from backend.url_checker import analyze_url
from backend.email_parser import analyze_email
from backend.analyzer import get_demos

app = Flask(__name__, static_folder=None)
CORS(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["60 per minute"])

logging.basicConfig(
    filename=os.path.join(os.path.dirname(__file__), "..", "scan_log.json"),
    level=logging.INFO,
    format="%(message)s"
)

scan_stats = {"total": 0, "url_scans": 0, "email_scans": 0, "threats_found": 0}

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")


@app.route("/")
def serve_index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:path>")
def serve_static(path):
    return send_from_directory(FRONTEND_DIR, path)


@app.route("/api/analyze/url", methods=["POST"])
@limiter.limit("30 per minute")
def api_analyze_url():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' field"}), 400

    url = data["url"].strip()
    if not url or len(url) > 2048:
        return jsonify({"error": "Invalid URL"}), 400

    result = analyze_url(url)

    scan_stats["total"] += 1
    scan_stats["url_scans"] += 1
    if result["threat_level"] != "safe":
        scan_stats["threats_found"] += 1

    _log_scan("url", url, result)
    return jsonify(result)


@app.route("/api/analyze/email", methods=["POST"])
@limiter.limit("15 per minute")
def api_analyze_email():
    data = request.get_json()
    if not data or "email" not in data:
        return jsonify({"error": "Missing 'email' field"}), 400

    raw_email = data["email"].strip()
    if not raw_email or len(raw_email) > 100_000:
        return jsonify({"error": "Invalid email content"}), 400

    result = analyze_email(raw_email)

    scan_stats["total"] += 1
    scan_stats["email_scans"] += 1
    if result["threat_level"] != "safe":
        scan_stats["threats_found"] += 1

    _log_scan("email", "(email content)", result)
    return jsonify(result)


@app.route("/api/stats")
def api_stats():
    return jsonify(scan_stats)


@app.route("/api/demos")
def api_demos():
    return jsonify(get_demos())


def _log_scan(scan_type: str, target: str, result: dict):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "type": scan_type,
        "target": target[:200],
        "score": result["score"],
        "threat_level": result["threat_level"],
        "findings_count": len(result["findings"])
    }
    logging.info(json.dumps(entry))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
