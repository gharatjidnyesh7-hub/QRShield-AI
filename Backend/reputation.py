"""
Optional external reputation lookup (Google Safe Browsing v4 "threatMatches:find").

DISABLED unless GOOGLE_SAFE_BROWSING_API_KEY is set. The application runs
identically without it. STATUS: the request/response handling is covered by unit
tests with a mocked HTTP layer only; it has NOT been exercised against the live
Google API in this build (no network access). Verify with your own key.

Notes: the free API is for non-commercial use and rate/quota limited (see Google's
documentation). A "no match" result does NOT mean a URL is safe.
Privacy: this sends the URL being checked to Google; leave the key unset if that
is unacceptable for your deployment.
"""

import json
import os
import urllib.request

ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"


def is_enabled():
    return bool(os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY"))


def _post(url, payload, timeout=5):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # fixed, trusted host
        return json.loads(r.read(65536).decode())


def lookup(url, post=_post):
    if not is_enabled():
        return {"enabled": False, "status": "Unavailable",
                "detail": "No external reputation service is configured."}
    key = os.environ["GOOGLE_SAFE_BROWSING_API_KEY"]
    payload = {
        "client": {"clientId": "qrshield-ai", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        data = post(ENDPOINT.format(key=key), payload)
    except Exception:
        return {"enabled": True, "status": "Unavailable",
                "detail": "The reputation service could not be reached."}
    matches = data.get("matches") if isinstance(data, dict) else None
    if matches:
        types = sorted({m.get("threatType", "UNKNOWN") for m in matches})
        return {"enabled": True, "status": "Failed", "provider": "Google Safe Browsing",
                "detail": "Listed by Google Safe Browsing: " + ", ".join(types).lower().replace("_", " ") + ".",
                "threat_types": types}
    return {"enabled": True, "status": "Passed", "provider": "Google Safe Browsing",
            "detail": "Not listed by Google Safe Browsing. This does not guarantee the site is safe."}
