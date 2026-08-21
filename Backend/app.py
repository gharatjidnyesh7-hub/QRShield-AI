"""
QRShield AI - Flask Backend
=============================
REST API endpoints:

  GET  /api/health                 - liveness check
  POST /api/analyze-url            - body: {"url": "...", "source": "manual"}
  POST /api/scan-qr                - multipart file upload (QR image), decodes + analyzes
  GET  /api/history?limit=200      - scan history
  GET  /api/dashboard               - aggregated stats for dashboard charts

Security measures implemented:
  - All DB queries parameterized (no string-built SQL) -> SQL injection safe
  - File upload validated by extension AND actual image content (Pillow verify)
  - Upload size capped via MAX_CONTENT_LENGTH
  - Defensive URL parsing (feature_extraction never raises on malformed input)
  - CORS restricted to explicit methods/headers (manual, no flask_cors dependency
    available in this sandbox -- functionally equivalent)
"""

import os
import sys
import json
import time
import traceback
from io import BytesIO

import numpy as np
import joblib
import cv2
from PIL import Image
from flask import Flask, request, jsonify

sys.path.append(os.path.dirname(__file__))
from feature_extraction import (
    extract_features, features_to_vector, is_valid_url, explain_prediction
)

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "Database"))
from db_utils import init_db, insert_scan, get_history, get_dashboard_stats  # noqa: E402

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "Models", "model.pkl")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # 8 MB upload cap

_model = None


def get_model():
    global _model
    if _model is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                "model.pkl not found. Run: python Models/train_model.py first."
            )
        _model = joblib.load(MODEL_PATH)
    return _model


@app.after_request
def add_cors_headers(resp):
    # Manual CORS (flask_cors unavailable in this build sandbox) -- functionally
    # equivalent for local dev. Restrict origin via FRONTEND_ORIGIN env var in prod.
    resp.headers["Access-Control-Allow-Origin"] = os.environ.get("FRONTEND_ORIGIN", "*")
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "QRShield AI Backend"})


def _allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def _classify(url: str):
    """Run the full pipeline: feature extraction -> model prediction ->
    3-way SAFE/SUSPICIOUS/PHISHING classification with confidence and risk score."""
    feat = extract_features(url)
    vector = np.array([features_to_vector(feat)])
    model = get_model()

    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(vector)[0]
        phishing_proba = float(proba[1])
    else:
        pred = int(model.predict(vector)[0])
        phishing_proba = 0.9 if pred == 1 else 0.1

    risk_score = int(round(phishing_proba * 100))

    if phishing_proba < 0.35:
        label = "SAFE"
        confidence = round((1 - phishing_proba) * 100, 2)
    elif phishing_proba < 0.65:
        label = "SUSPICIOUS"
        confidence = round(max(phishing_proba, 1 - phishing_proba) * 100, 2)
    else:
        label = "PHISHING"
        confidence = round(phishing_proba * 100, 2)

    reasons = explain_prediction(feat, label)

    return {
        "prediction": label,
        "confidence": confidence,
        "risk_score": risk_score,
        "reasons": reasons,
        "features": feat,
    }


@app.route("/api/analyze-url", methods=["POST", "OPTIONS"])
def analyze_url():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    try:
        data = request.get_json(silent=True) or {}
        raw_url = (data.get("url") or "").strip()
        source = data.get("source", "manual")

        if not raw_url:
            return jsonify({"error": "No URL provided"}), 400

        if len(raw_url) > 2048:
            return jsonify({"error": "URL is too long to process"}), 400

        if not is_valid_url(raw_url):
            return jsonify({
                "applicable": False,
                "message": ("This QR code does not contain a website link. "
                            "Phishing analysis is not applicable.")
            }), 200

        t0 = time.time()
        result = _classify(raw_url)
        elapsed_ms = round((time.time() - t0) * 1000, 2)

        scan_id = insert_scan(
            url=raw_url,
            source=source,
            prediction=result["prediction"],
            confidence=result["confidence"],
            risk_score=result["risk_score"],
            reasons_json=json.dumps(result["reasons"]),
        )

        return jsonify({
            "applicable": True,
            "scan_id": scan_id,
            "url": raw_url,
            "prediction": result["prediction"],
            "confidence": result["confidence"],
            "risk_score": result["risk_score"],
            "reasons": result["reasons"],
            "prediction_time_ms": elapsed_ms,
        }), 200

    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 503
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Internal error analyzing URL", "detail": str(e)}), 500


@app.route("/api/scan-qr", methods=["POST", "OPTIONS"])
def scan_qr():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "Empty filename"}), 400
        if not _allowed_file(file.filename):
            return jsonify({"error": "Only PNG, JPG, JPEG files are allowed"}), 400

        raw_bytes = file.read()

        # Validate it is genuinely an image (defends against disguised uploads)
        try:
            img_check = Image.open(BytesIO(raw_bytes))
            img_check.verify()
        except Exception:
            return jsonify({"error": "Uploaded file is not a valid image"}), 400

        # Decode QR using OpenCV (re-open since verify() invalidates the object)
        pil_img = Image.open(BytesIO(raw_bytes)).convert("RGB")
        cv_img = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)

        detector = cv2.QRCodeDetector()
        data, points, _ = detector.detectAndDecode(cv_img)

        if not data:
            return jsonify({
                "decoded": False,
                "message": "No QR code detected in the uploaded image. Please upload a clearer image."
            }), 200

        if not is_valid_url(data):
            return jsonify({
                "decoded": True,
                "applicable": False,
                "raw_data": data,
                "message": ("This QR code contains text, contact information, Wi-Fi "
                            "credentials, or another unsupported format. Phishing "
                            "analysis only works for website URLs.")
            }), 200

        t0 = time.time()
        result = _classify(data)
        elapsed_ms = round((time.time() - t0) * 1000, 2)

        scan_id = insert_scan(
            url=data,
            source="upload",
            prediction=result["prediction"],
            confidence=result["confidence"],
            risk_score=result["risk_score"],
            reasons_json=json.dumps(result["reasons"]),
        )

        return jsonify({
            "decoded": True,
            "applicable": True,
            "scan_id": scan_id,
            "url": data,
            "prediction": result["prediction"],
            "confidence": result["confidence"],
            "risk_score": result["risk_score"],
            "reasons": result["reasons"],
            "prediction_time_ms": elapsed_ms,
        }), 200

    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 503
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Internal error processing QR image", "detail": str(e)}), 500


@app.route("/api/history", methods=["GET"])
def history():
    try:
        limit = request.args.get("limit", default=200, type=int)
        limit = max(1, min(limit, 1000))
        rows = get_history(limit=limit)
        for r in rows:
            try:
                r["reasons"] = json.loads(r["reasons"]) if r["reasons"] else []
            except Exception:
                r["reasons"] = []
        return jsonify({"history": rows}), 200
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Could not fetch history", "detail": str(e)}), 500


@app.route("/api/dashboard", methods=["GET"])
def dashboard():
    try:
        stats = get_dashboard_stats()
        for r in stats["recent_activity"]:
            try:
                r["reasons"] = json.loads(r["reasons"]) if r["reasons"] else []
            except Exception:
                r["reasons"] = []
        return jsonify(stats), 200
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "Could not fetch dashboard stats", "detail": str(e)}), 500


if __name__ == "__main__":
    init_db()
    print("QRShield AI backend starting on http://localhost:5000")
    print("Model path:", MODEL_PATH, "| exists:", os.path.exists(MODEL_PATH))
    app.run(host="0.0.0.0", port=5000, debug=True)
