"""
QRShield AI - URL Feature Extraction Module
=============================================
This module extracts lexical / structural features from a URL that are
predictive of phishing behaviour. It is used BOTH to build the training
dataset (Dataset/generate_dataset.py) and at prediction time
(Backend/app.py), so the exact same feature vector shape is guaranteed
between training and inference.

Feature list (13 core features + engineered extras):
  1. url_length            - total character length of the URL
  2. domain_length         - character length of the domain/host
  3. has_https             - 1 if scheme is https, else 0
  4. count_dots            - number of '.' characters
  5. count_digits          - number of digits in the URL
  6. count_hyphens         - number of '-' characters
  7. count_special_chars   - count of @, %, =, &, ?, #, etc.
  8. subdomain_count       - number of subdomain labels
  9. has_ip                - 1 if host is a raw IP address
 10. is_shortened          - 1 if a known URL shortener domain is used
 11. suspicious_keywords   - count of phishing-trigger words in the URL
 12. tld_suspicious        - 1 if TLD is in a commonly-abused list
 13. has_at_symbol         - 1 if '@' present (redirection trick)

All feature functions are pure and defensive: malformed URLs never raise,
they simply degrade to "worst case" feature values so the model still
returns a prediction instead of crashing the API.
"""

import re
import socket
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "bank", "account",
    "password", "signin", "confirm", "billing", "webscr", "ebayisapi"
]

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd",
    "buff.ly", "adf.ly", "bitly.com", "shorte.st", "cutt.ly", "rb.gy"
]

SUSPICIOUS_TLDS = [
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work", "info"
]

IP_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


def _safe_parse(url: str):
    """Parse a URL defensively; always returns a urlparse result, even
    for malformed input, by prefixing a scheme if one is missing."""
    url = (url or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    try:
        return urlparse(url)
    except Exception:
        return urlparse("http://invalid.invalid")


def is_valid_url(text: str) -> bool:
    """Determine whether a decoded QR payload actually looks like a
    website URL (vs. plain text, vCard, Wi-Fi config, etc.)."""
    if not text:
        return False
    text = text.strip()
    if text.upper().startswith(("WIFI:", "BEGIN:VCARD", "MECARD:", "TEL:", "SMSTO:", "MAILTO:")):
        return False
    parsed = _safe_parse(text)
    host = parsed.netloc.split(":")[0]
    if not host or "." not in host:
        return False
    # Must have at least one alnum label before a dot, and a plausible TLD
    if not re.match(r"^[a-zA-Z0-9.-]+$", host):
        return False
    return True


def extract_features(url: str) -> dict:
    """Extract the full feature dictionary for a single URL."""
    parsed = _safe_parse(url)
    host = parsed.netloc.split(":")[0] if parsed.netloc else ""
    full = url or ""

    url_length = len(full)
    domain_length = len(host)
    has_https = 1 if parsed.scheme == "https" else 0
    count_dots = full.count(".")
    count_digits = sum(c.isdigit() for c in full)
    count_hyphens = full.count("-")
    count_special_chars = sum(full.count(c) for c in ["@", "%", "=", "&", "?", "#", "!", "$", "^", "*"])
    subdomain_count = max(host.count(".") - 1, 0) if host else 0
    has_ip = 1 if IP_REGEX.match(host) else 0
    is_shortened = 1 if any(s in host for s in SHORTENER_DOMAINS) else 0
    suspicious_keywords = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in full.lower())
    tld = host.split(".")[-1].lower() if "." in host else ""
    tld_suspicious = 1 if tld in SUSPICIOUS_TLDS else 0
    has_at_symbol = 1 if "@" in full else 0

    return {
        "url_length": url_length,
        "domain_length": domain_length,
        "has_https": has_https,
        "count_dots": count_dots,
        "count_digits": count_digits,
        "count_hyphens": count_hyphens,
        "count_special_chars": count_special_chars,
        "subdomain_count": subdomain_count,
        "has_ip": has_ip,
        "is_shortened": is_shortened,
        "suspicious_keywords": suspicious_keywords,
        "tld_suspicious": tld_suspicious,
        "has_at_symbol": has_at_symbol,
    }


FEATURE_ORDER = [
    "url_length", "domain_length", "has_https", "count_dots", "count_digits",
    "count_hyphens", "count_special_chars", "subdomain_count", "has_ip",
    "is_shortened", "suspicious_keywords", "tld_suspicious", "has_at_symbol",
]


def features_to_vector(feat: dict):
    """Convert a feature dict into an ordered list matching FEATURE_ORDER
    (the exact column order the ML model was trained on)."""
    return [feat[k] for k in FEATURE_ORDER]


def explain_prediction(feat: dict, prediction: str) -> list:
    """Produce short, human-readable reasons for a prediction, mirroring
    the "Reason" section requested in the product spec."""
    reasons = []
    if prediction in ("PHISHING", "SUSPICIOUS"):
        if not feat["has_https"]:
            reasons.append("No HTTPS encryption")
        if feat["has_ip"]:
            reasons.append("Uses raw IP address instead of a domain name")
        if feat["url_length"] > 75:
            reasons.append("Unusually long URL")
        if feat["suspicious_keywords"] > 0:
            reasons.append("Contains suspicious keyword(s) such as 'login' or 'verify'")
        if feat["count_special_chars"] > 5:
            reasons.append("High number of special characters")
        if feat["is_shortened"]:
            reasons.append("Uses a URL shortening service")
        if feat["subdomain_count"] > 2:
            reasons.append("Excessive number of subdomains")
        if feat["tld_suspicious"]:
            reasons.append("Uses a top-level domain commonly abused for phishing")
        if feat["has_at_symbol"]:
            reasons.append("Contains '@' symbol (browser redirection trick)")
        if not reasons:
            reasons.append("Multiple minor risk signals combined")
    else:
        if feat["has_https"]:
            reasons.append("HTTPS enabled")
        if feat["url_length"] <= 75:
            reasons.append("Normal URL length")
        if feat["suspicious_keywords"] == 0:
            reasons.append("No suspicious keywords detected")
        if not feat["has_ip"]:
            reasons.append("Uses a proper domain name, not a raw IP")
        if not reasons:
            reasons.append("No significant risk indicators found")
    return reasons
