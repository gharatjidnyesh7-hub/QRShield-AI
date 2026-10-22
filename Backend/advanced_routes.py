"""
QRShield AI - Advanced Security Analysis API (Flask Blueprint)
===============================================================
  POST /api/explain-url       {"url": "..."}
  POST /api/analyze-security  {"url": "..."}
  POST /api/analyze-message   {"channel": "sms|email", "subject": "", "body": "...", "sender": ""}
  GET  /api/advanced/status   which optional features are enabled

Every response is JSON. Success: HTTP 200 with the report fields. Failure:
{"error": "<safe message>", "code": "<machine_code>"} with a 4xx/5xx status.
Internal exception text is never returned to the client.

Environment variables (all optional):
  ADVANCED_RATE_LIMIT_PER_MIN   requests/min/client across advanced endpoints (default 20)
  TRUST_PROXY_HEADERS           "1" to key rate limits on X-Forwarded-For (set on Render)
  SECURITY_MAX_REDIRECTS        default 5
  SECURITY_HOP_TIMEOUT          seconds per request, default 5
  SECURITY_TOTAL_TIMEOUT        seconds for the whole analysis, default 15
  GOOGLE_SAFE_BROWSING_API_KEY  enables optional reputation lookup (see reputation.py)
"""

import os
import threading
import time
from collections import defaultdict, deque

from flask import Blueprint, jsonify, request

from feature_extraction import is_valid_url
from url_pipeline import classify_url
from explain import explain_url
from security_analyzer import SecurityAnalyzer, MAX_URL_LENGTH
from message_analyzer import analyze_message, MessageValidationError, MAX_BODY
import reputation

advanced_bp = Blueprint("advanced", __name__)

MAX_JSON_BYTES = 32 * 1024  # body size cap for the advanced endpoints

_analyzer = SecurityAnalyzer(
    max_redirects=int(os.environ.get("SECURITY_MAX_REDIRECTS", 5)),
    hop_timeout=float(os.environ.get("SECURITY_HOP_TIMEOUT", 5)),
    total_timeout=float(os.environ.get("SECURITY_TOTAL_TIMEOUT", 15)),
)

# ---- tiny in-memory sliding-window rate limiter (per process) ----
_hits = defaultdict(deque)
_hits_lock = threading.Lock()


def _client_key():
    if os.environ.get("TRUST_PROXY_HEADERS") == "1":
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[-1].strip()  # last hop = added by the trusted proxy
    return request.remote_addr or "unknown"


def _rate_limited():
    limit = int(os.environ.get("ADVANCED_RATE_LIMIT_PER_MIN", 20))
    now = time.monotonic()
    key = _client_key()
    with _hits_lock:
        q = _hits[key]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= limit:
            return True
        q.append(now)
        if len(_hits) > 5000:  # opportunistic cleanup
            for k in [k for k, v in _hits.items() if not v or now - v[-1] > 60]:
                _hits.pop(k, None)
    return False


def _err(message, code, status):
    return jsonify({"error": message, "code": code}), status


def _read_json():
    """Returns (data, error_response)."""
    if request.content_length is not None and request.content_length > MAX_JSON_BYTES:
        return None, _err("Request is too large.", "payload_too_large", 413)
    raw = request.get_data(cache=True, as_text=False)
    if len(raw) > MAX_JSON_BYTES:
        return None, _err("Request is too large.", "payload_too_large", 413)
    data = request.get_json(silent=True, force=True)
    if not isinstance(data, dict):
        return None, _err("Request body must be a JSON object.", "invalid_json", 400)
    return data, None


def _get_url(data):
    url = data.get("url")
    if not isinstance(url, str) or not url.strip():
        return None, _err("No URL provided.", "missing_url", 400)
    url = url.strip()
    if len(url) > MAX_URL_LENGTH:
        return None, _err("URL is too long to process.", "url_too_long", 400)
    return url, None


@advanced_bp.before_request
def _guard():
    if request.method == "OPTIONS":
        return None
    if request.path.startswith("/api/advanced/status"):
        return None
    if _rate_limited():
        return _err("Too many requests. Please wait a minute and try again.", "rate_limited", 429)
    return None


@advanced_bp.route("/api/advanced/status", methods=["GET"])
def status():
    return jsonify({
        "explain_url": True,
        "analyze_security": True,
        "analyze_message": True,
        "message_method": "rule_based",
        "reputation_lookup": reputation.is_enabled(),
        "domain_registration_lookup": False,
        "max_message_chars": MAX_BODY,
    })


@advanced_bp.route("/api/explain-url", methods=["POST", "OPTIONS"])
def explain_url_route():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    data, e = _read_json()
    if e:
        return e
    url, e = _get_url(data)
    if e:
        return e
    if not is_valid_url(url):
        return jsonify({"applicable": False,
                        "message": "This does not look like a website link, so URL analysis is not applicable."}), 200
    try:
        classification = classify_url(url)
        report = explain_url(url, classification)
        report["applicable"] = True
        return jsonify(report), 200
    except FileNotFoundError:
        return _err("The detection model is not available on the server.", "model_unavailable", 503)
    except Exception:
        return _err("Could not explain this URL.", "internal_error", 500)


@advanced_bp.route("/api/analyze-security", methods=["POST", "OPTIONS"])
def analyze_security_route():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    data, e = _read_json()
    if e:
        return e
    url, e = _get_url(data)
    if e:
        return e
    try:
        report = _analyzer.analyze(url)
        report["reputation"] = reputation.lookup(report.get("final_url") or url)
        report["applicable"] = True
        return jsonify(report), 200
    except Exception:
        return _err("Security analysis failed unexpectedly.", "internal_error", 500)


@advanced_bp.route("/api/analyze-message", methods=["POST", "OPTIONS"])
def analyze_message_route():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    data, e = _read_json()
    if e:
        return e
    try:
        report = analyze_message(
            data.get("channel", "sms"), data.get("subject"), data.get("body"), data.get("sender"))
        return jsonify(report), 200
    except MessageValidationError as ex:
        return _err(str(ex), "invalid_message", 400)
    except FileNotFoundError:
        return _err("The detection model is not available on the server.", "model_unavailable", 503)
    except Exception:
        return _err("Could not analyze this message.", "internal_error", 500)
