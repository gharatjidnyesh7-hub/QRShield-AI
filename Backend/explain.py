"""
QRShield AI - Explainable AI (XAI)
===================================
Two clearly separated kinds of explanation are produced:

1. MODEL EXPLANATION (method "tree_path_contributions")
   For the RandomForest in Models/model.pkl, the exact local contribution of
   every input feature to P(phishing) is computed by walking each tree's
   decision path and attributing the change in node probability at every
   split to the feature used at that split (the "treeinterpreter"
   decomposition). Averaged over all trees:

       P(phishing) = bias + sum(feature contributions)

   This is an exact decomposition of THIS model's output for THIS input, not
   an approximation and not a heuristic. It is NOT SHAP (no extra dependency),
   although it answers the same question. The additivity is verified at
   runtime and the explanation is withheld if it does not hold.

   If the loaded model is not a supported tree ensemble, model contributions
   are reported as unavailable. Nothing is invented.

2. HEURISTIC INDICATORS
   Plain rule-of-thumb checks on the URL (long URL, IP host, @ symbol, ...).
   They are labelled "heuristic" and are independent of the model's output.
"""

import numpy as np

from feature_extraction import FEATURE_ORDER, features_to_vector
from url_pipeline import get_model

FEATURE_LABELS = {
    "url_length": "URL length",
    "domain_length": "Domain length",
    "has_https": "Uses HTTPS",
    "count_dots": "Number of dots",
    "count_digits": "Number of digits",
    "count_hyphens": "Number of hyphens",
    "count_special_chars": "Special characters",
    "subdomain_count": "Subdomain count",
    "has_ip": "IP address as host",
    "is_shortened": "URL shortener",
    "suspicious_keywords": "Suspicious keywords",
    "tld_suspicious": "Commonly-abused TLD",
    "has_at_symbol": "'@' symbol",
}

ADDITIVITY_TOLERANCE = 1e-6


def _tree_contributions(tree, x_row, n_features):
    """Per-feature contribution of a single fitted sklearn tree to P(class 1)."""
    t = tree.tree_
    values = t.value[:, 0, :]
    sums = values.sum(axis=1, keepdims=True)
    sums[sums == 0] = 1.0
    prob1 = (values / sums)[:, 1]  # normalised, robust to count/fraction storage

    contrib = np.zeros(n_features)
    node = 0
    bias = prob1[0]
    while t.children_left[node] != t.children_right[node]:  # not a leaf
        f = t.feature[node]
        nxt = (t.children_left[node]
               if x_row[f] <= t.threshold[node] else t.children_right[node])
        contrib[f] += prob1[nxt] - prob1[node]
        node = nxt
    return bias, contrib, prob1[node]


def model_contributions(feature_vector):
    """Returns dict with contributions, or {"available": False, "reason": ...}."""
    model = get_model()
    estimators = getattr(model, "estimators_", None)
    if estimators is None or not hasattr(model, "predict_proba"):
        return {"available": False,
                "reason": "The loaded model type does not expose per-tree "
                          "structure, so feature contributions cannot be computed."}
    classes = list(getattr(model, "classes_", []))
    if classes != [0, 1]:
        return {"available": False,
                "reason": "Unexpected model class labels; explanation withheld."}

    x = np.asarray(feature_vector, dtype=float)
    n = len(x)
    bias_sum, leaf_sum = 0.0, 0.0
    contrib_sum = np.zeros(n)
    try:
        for est in estimators:
            b, c, leaf = _tree_contributions(est, x, n)
            bias_sum += b
            contrib_sum += c
            leaf_sum += leaf
    except Exception:
        return {"available": False,
                "reason": "Model structure could not be interpreted; explanation withheld."}
    k = len(estimators)
    bias, contrib = bias_sum / k, contrib_sum / k
    reconstructed = bias + contrib.sum()
    actual = float(model.predict_proba(x.reshape(1, -1))[0][1])
    if abs(reconstructed - actual) > ADDITIVITY_TOLERANCE:
        return {"available": False,
                "reason": "Explanation failed its consistency check against the "
                          "model output and was withheld."}
    return {
        "available": True,
        "method": "tree_path_contributions",
        "method_description": (
            "Exact per-feature decomposition of the Random Forest's phishing "
            "probability along each tree's decision path, averaged over all trees. "
            "Not SHAP; same additive idea."),
        "base_probability": float(bias),
        "model_probability": actual,
        "contributions": [float(v) for v in contrib],
    }


def global_importance():
    model = get_model()
    imp = getattr(model, "feature_importances_", None)
    if imp is None:
        return None
    return {FEATURE_ORDER[i]: float(imp[i]) for i in range(len(FEATURE_ORDER))}


def heuristic_indicators(feat: dict):
    """Rule-of-thumb URL checks. Independent of the model; labelled as such."""
    ind = []

    def add(key, label, detail, severity):
        ind.append({"key": key, "label": label, "detail": detail,
                    "severity": severity, "source": "heuristic"})

    if feat["has_ip"]:
        add("ip_host", "IP address used as host",
            "Legitimate services almost always use a domain name.", "high")
    if feat["has_at_symbol"]:
        add("at_symbol", "Contains '@' symbol",
            "Text before '@' is ignored by browsers, which can disguise the real host.", "high")
    if feat["url_length"] > 75:
        add("long_url", "Unusually long URL",
            f"{feat['url_length']} characters (heuristic threshold: 75).", "medium")
    if feat["subdomain_count"] > 2:
        add("many_subdomains", "Many subdomains",
            f"{feat['subdomain_count']} subdomain levels can hide the real domain "
            "(e.g. brand.example.attacker.com).", "medium")
    if feat["is_shortened"]:
        add("shortener", "URL shortening service",
            "The real destination is hidden; see Website Security Analysis to "
            "inspect where it redirects.", "medium")
    if feat["tld_suspicious"]:
        add("tld", "Top-level domain often abused",
            "Some TLDs are heavily used by phishing campaigns. Many legitimate "
            "sites use them too, so this is only a weak signal.", "low")
    if feat["suspicious_keywords"] > 0:
        add("keywords", "Credential-related keywords in URL",
            f"{feat['suspicious_keywords']} keyword(s) such as 'login', 'verify', 'account'.", "low")
    if feat["count_special_chars"] > 5:
        add("special_chars", "Many special characters",
            f"{feat['count_special_chars']} characters such as ?, =, &, %.", "low")
    if feat["count_hyphens"] > 3:
        add("hyphens", "Many hyphens",
            f"{feat['count_hyphens']} hyphens; look-alike domains often chain words with hyphens.", "low")
    if not feat["has_https"]:
        add("no_https", "Not using HTTPS",
            "Traffic is unencrypted. This alone does not make a site malicious.", "low")
    return ind


def _risk_level(score):
    if score < 35:
        return "Low"
    if score < 65:
        return "Medium"
    return "High"


def recommendations(prediction, feat, indicators):
    keys = {i["key"] for i in indicators}
    recs = []
    if prediction == "PHISHING":
        recs.append("Do not open this link or enter any credentials, OTPs or payment details.")
        recs.append("If it came from a message or QR sticker, report it to the sender organisation "
                    "through a channel you already trust.")
    elif prediction == "SUSPICIOUS":
        recs.append("Treat this link with caution; avoid entering personal information until you "
                    "have verified it.")
        recs.append("Reach the organisation by typing its official address yourself instead of "
                    "following this link.")
    else:
        recs.append("The model rated this URL low-risk, but no model catches every phishing site. "
                    "Stay alert for unexpected login or payment prompts.")
    if "shortener" in keys:
        recs.append("Use the Website Security Analysis tab to see where the shortened link really leads.")
    if "ip_host" in keys or "at_symbol" in keys:
        recs.append("Be especially wary: raw IP hosts and '@' tricks are rarely used by legitimate services.")
    if "no_https" in keys:
        recs.append("Avoid submitting any information over a connection that is not HTTPS.")
    recs.append("If you already entered a password, change it on the real site and enable "
                "two-factor authentication.") if prediction != "SAFE" else None
    return [r for r in recs if r]


def explain_url(url: str, classification: dict) -> dict:
    """classification: output of url_pipeline.classify_url(url)."""
    feat = classification["features"]
    vec = features_to_vector(feat)
    mc = model_contributions(vec)
    importance = global_importance()

    features_out = []
    for i, name in enumerate(FEATURE_ORDER):
        row = {"name": name, "label": FEATURE_LABELS[name], "value": feat[name]}
        if mc.get("available"):
            row["contribution"] = round(mc["contributions"][i], 4)
        if importance:
            row["global_importance"] = round(importance[name], 4)
        features_out.append(row)

    model_expl = {"available": mc.get("available", False)}
    if mc.get("available"):
        ranked = sorted(features_out, key=lambda r: abs(r["contribution"]), reverse=True)
        top = [r for r in ranked if abs(r["contribution"]) >= 0.01][:5]
        model_expl.update({
            "method": mc["method"],
            "method_description": mc["method_description"],
            "base_probability": round(mc["base_probability"], 4),
            "model_probability": round(mc["model_probability"], 4),
            "top_factors": [{
                "name": r["name"], "label": r["label"], "value": r["value"],
                "contribution": r["contribution"],
                "direction": "raises risk" if r["contribution"] > 0 else "lowers risk",
            } for r in top],
            "note": ("Contributions are in probability points and sum with the base "
                     "probability to the model's phishing probability. Positive values "
                     "push toward PHISHING, negative toward SAFE."),
        })
    else:
        model_expl["reason"] = mc.get("reason")

    indicators = heuristic_indicators(feat)
    score = classification["risk_score"]
    return {
        "url": url,
        "prediction": {
            "label": classification["prediction"],
            "confidence": classification["confidence"],
            "source": "ml_model",
            "model": "RandomForest (Models/model.pkl)",
        },
        "risk": {
            "score": score,
            "level": _risk_level(score),
            "basis": "Model-estimated probability of phishing x 100. "
                     "Thresholds: <35 Low, 35-64 Medium, >=65 High.",
        },
        "model_explanation": model_expl,
        "features": features_out,
        "heuristic_indicators": indicators,
        "heuristic_note": ("Heuristic indicators are simple rules shown for context. "
                           "They are not the model's reasoning and do not change its score."),
        "recommendations": recommendations(classification["prediction"], feat, indicators),
        "training_data_note": ("The model was trained on a synthetic dataset (see Models/model_metadata.json); "
                               "treat its probabilities as indicative, not calibrated."),
    }
