"""
QRShield AI - Shared URL pipeline
==================================
Single place where the trained model is loaded and a URL is classified.
Used by app.py / QRshieldAI.py (existing endpoints) AND by the advanced
analysis endpoints (explain-url, analyze-message), so model-loading logic is
never duplicated and every feature agrees on the same prediction.

The model's input format is unchanged: the 13 features from
feature_extraction.FEATURE_ORDER, in that order.
"""

import os
import threading

import joblib
import numpy as np

from feature_extraction import extract_features, features_to_vector, explain_prediction

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "Models", "model.pkl")

_model = None
_lock = threading.Lock()


def get_model():
    global _model
    if _model is None:
        with _lock:
            if _model is None:
                if not os.path.exists(MODEL_PATH):
                    raise FileNotFoundError(
                        "model.pkl not found. Run: python Models/train_model.py first."
                    )
                _model = joblib.load(MODEL_PATH)
    return _model


def classify_url(url: str) -> dict:
    """feature extraction -> model -> SAFE / SUSPICIOUS / PHISHING.
    Behaviour is identical to the original app._classify()."""
    feat = extract_features(url)
    vector = np.array([features_to_vector(feat)])
    model = get_model()

    if hasattr(model, "predict_proba"):
        phishing_proba = float(model.predict_proba(vector)[0][1])
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

    return {
        "prediction": label,
        "confidence": confidence,
        "risk_score": risk_score,
        "reasons": explain_prediction(feat, label),
        "features": feat,
        "phishing_probability": phishing_proba,
    }
