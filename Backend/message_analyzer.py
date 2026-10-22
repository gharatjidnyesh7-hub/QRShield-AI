"""
QRShield AI - SMS & Email Phishing Message Analyzer
====================================================
IMPORTANT - what this is and is not
  * The message-level analysis is RULE-BASED. There is no trained text model
    in this project, so no machine-learning claim is made about message text
    and no accuracy figure exists for it.
  * The only ML involved is the project's existing URL model
    (Models/model.pkl), applied to links extracted from the message through
    url_pipeline.classify_url(). Those results are labelled "ml_model" and are
    kept separate from the rule findings.
  * Raw message text is never passed to the URL model.
  * Message content is analysed in memory and never stored or logged.

Design principle: single weak signals (e.g. the word "urgent") do not make a
message phishing. Risk comes from combinations: urgency + credential request,
payment demand + unfamiliar link, brand claim + mismatching link/sender, ...
"""

import re
import unicodedata
from urllib.parse import urlsplit

from feature_extraction import is_valid_url, SHORTENER_DOMAINS, IP_REGEX
from url_pipeline import classify_url
from security_analyzer import registrable_domain

MAX_BODY = 5000
MAX_SUBJECT = 300
MAX_SENDER = 254
MAX_URLS_ANALYZED = 10


class MessageValidationError(ValueError):
    pass


# ------------------------------------------------------------------ data
BRANDS = {
    # brand keyword -> legitimate registrable domains (small illustrative set)
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "a.co", "amzn.to", "amazonaws.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "google.co.in", "gmail.com", "goo.gl", "youtube.com", "googleapis.com", "googleusercontent.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "flipkart": {"flipkart.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"},
    "hdfc": {"hdfcbank.com"},
    "icici": {"icicibank.com"},
    "axis bank": {"axisbank.com"},
    "fedex": {"fedex.com"},
    "dhl": {"dhl.com"},
    "india post": {"indiapost.gov.in"},
    "dropbox": {"dropbox.com"},
    "linkedin": {"linkedin.com"},
}
FREEMAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "rediffmail.com",
            "proton.me", "protonmail.com", "aol.com", "icloud.com", "mail.com"}

_NEG = r"(?:do\s*not|don'?t|never|not)\s+(?:\w+\s+){0,2}?(?:share|disclose|give|tell|reveal|send)"

RE_URGENCY = re.compile(
    r"\b(urgent(?:ly)?|immediately|right\s+away|asap|act\s+now|within\s+\d+\s*(?:hours?|hrs?|minutes?|mins?)|"
    r"last\s+(?:chance|warning|notice)|final\s+(?:notice|warning|reminder)|expires?\s+(?:today|soon|tonight)|"
    r"(?:today|tonight)\s+only|before\s+it'?s\s+too\s+late)\b", re.I)
RE_THREAT = re.compile(
    r"\b(?:account|card|wallet|service|number|sim|kyc)\b[^.\n]{0,40}\b(?:(?:will\s+be\s+|has\s+been\s+|is\s+)?"
    r"(?:suspended|blocked|locked|closed|deactivated|terminated|restricted|disabled|limited|frozen)|expire[sd]?)\b|"
    r"\b(?:legal\s+action|arrest(?:ed)?|police\s+(?:case|complaint)|court\s+notice|penalty\s+will)\b", re.I)
RE_CRED_REQ = re.compile(
    r"\b(?:verify|confirm|update|validate|re-?enter|enter|provide|submit|share|send|reply\s+with|tell\s+us)\b"
    r"[^.\n]{0,50}\b(?:password|passcode|pin|cvv|cvc|otp|one[-\s]?time\s+(?:password|code|pin)|"
    r"card\s+(?:number|details)|net\s*banking|login\s+(?:details|credentials)|credentials|"
    r"security\s+code|ssn|social\s+security|aadhaar|aadhar|pan\s+(?:number|card)|bank\s+details|"
    r"account\s+(?:number|details))\b", re.I)
RE_LOGIN_PROMPT = re.compile(r"\b(?:log\s?in|sign\s?in)\s+(?:to|at|here|now)\b|\bverify\s+(?:your\s+)?(?:account|identity)\b", re.I)
RE_DEFENSIVE = re.compile(_NEG + r"[^\n]{0,40}\b(?:otp|password|pin|code|cvv)\b|"
                          r"\b(?:otp|password|pin|code|cvv)\b[^\n]{0,30}" + _NEG, re.I)
RE_PAYMENT = re.compile(
    r"\b(?:pay|payment|send|transfer|deposit)\b[^.\n]{0,40}\b(?:fee|fine|penalty|charge|processing|customs|"
    r"clearance|delivery\s+fee|tax|deposit|amount|balance\s+due)\b|"
    r"\b(?:gift\s*cards?|bitcoin|crypto(?:currency)?|wire\s+transfer|western\s+union|upi\s+(?:id|pin)|"
    r"google\s*play\s*card|itunes\s*card)\b|"
    r"\b(?:unpaid|outstanding)\s+(?:invoice|bill|toll|fine|balance)\b", re.I)
RE_PRIZE = re.compile(
    r"\b(?:you(?:'ve|\s+have)?\s+(?:won|been\s+selected)|lottery|lucky\s+winner|claim\s+(?:your\s+)?"
    r"(?:prize|reward|gift|refund|cashback)|free\s+(?:gift|iphone|voucher)|congratulations[^.\n]{0,30}(?:won|winner|selected))\b", re.I)
RE_CTA = re.compile(r"\b(?:click|tap|open|visit|follow|go\s+to)\b[^.\n]{0,25}\b(?:link|here|below|now)\b", re.I)
RE_GENERIC_GREETING = re.compile(r"\bdear\s+(?:customer|user|client|member|account\s+holder|valued\s+\w+)\b", re.I)

RE_URL = re.compile(
    r"(?:https?://[^\s<>\"'\)\]]+)|"
    r"(?:www\.[^\s<>\"'\)\]]+)|"
    r"(?:\b[a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9-]{1,63})*\.(?:com|net|org|in|co|io|info|xyz|top|club|online|site|link|click|"
    r"ly|gl|me|us|uk|ru|cn|tk|ml|ga|cf|gq|app|live|shop|store|work|icu|vip|bank|pw|cc)\b(?:/[^\s<>\"'\)\]]*)?)", re.I)
RE_EMAIL = re.compile(r"[\w.+-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+)", re.I)


# ------------------------------------------------------------------ helpers
def _normalise(text):
    text = unicodedata.normalize("NFKC", text)
    text = re.sub(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]", "", text)  # zero-width / bidi controls
    return text


def _mask(snippet):
    """Mask long digit runs so OTPs/card numbers echoed in evidence are not displayed."""
    return re.sub(r"\d{4,}", lambda m: "•" * len(m.group()), snippet)


def _evidence(m, text, width=70):
    s = text[max(0, m.start() - 10): m.end() + 10].strip().replace("\n", " ")
    return _mask(s[:width])


def extract_urls(text):
    found, seen = [], set()
    for m in RE_URL.finditer(text):
        u = m.group().rstrip(".,;:!?'\")]}>")
        # skip email addresses picked up as domains
        start = m.start()
        if start > 0 and text[start - 1] == "@":
            continue
        key = u.lower()
        if key not in seen:
            seen.add(key)
            found.append(u)
    return found


def _host_of(u):
    try:
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u):
            u = "http://" + u
        return (urlsplit(u).hostname or "").lower()
    except ValueError:
        return ""


def _brand_mentions(text):
    low = text.lower()
    return [b for b in BRANDS if re.search(r"\b" + re.escape(b) + r"\b", low)]


def _brand_in_host(brand, host):
    """Token-based check so short brand names (e.g. 'sbi') don't match inside unrelated words."""
    key = brand.replace(" ", "")
    tokens = [t for t in re.split(r"[.\-_]", host) if t]
    if any(t == key or t.startswith(key) or (len(key) >= 6 and key in t) for t in tokens):
        return True
    return len(key) >= 6 and key in host.replace("-", "").replace(".", "")


def _link_flags(url, brands):
    """Rule-based observations about one link (not ML)."""
    host = _host_of(url)
    flags = []
    if not host:
        return [{"id": "malformed", "label": "Link could not be parsed", "severity": "low", "points": 0}]
    reg = registrable_domain(host)
    if IP_REGEX.match(host):
        flags.append({"id": "ip_link", "label": "Link uses a raw IP address", "severity": "high", "points": 15})
    if any(host == d or host.endswith("." + d) for d in SHORTENER_DOMAINS):
        flags.append({"id": "shortener", "label": "Link uses a URL shortener (destination hidden)",
                      "severity": "medium", "points": 8})
    if "xn--" in host:
        flags.append({"id": "punycode", "label": "Internationalised (punycode) domain; may imitate a known brand",
                      "severity": "medium", "points": 10})
    if "@" in url.split("?")[0].split("//", 1)[-1].split("/")[0]:
        flags.append({"id": "at_link", "label": "Link contains '@' (can disguise the real host)",
                      "severity": "high", "points": 15})
    for b in brands:
        legit = BRANDS[b]
        if _brand_in_host(b, host) and reg not in legit:
            flags.append({"id": "brand_lookalike",
                          "label": f"Link contains the name '{b}' but is not on its known domain(s)",
                          "severity": "high", "points": 25})
            break
    else:
        if brands and reg and not any(reg in BRANDS[b] for b in brands):
            flags.append({"id": "brand_mismatch",
                          "label": f"Message mentions {', '.join(brands[:2])} but links to an unrelated domain",
                          "severity": "medium", "points": 15})
    return flags


def _sender_findings(sender, brands):
    out = []
    if not sender:
        return out
    m = RE_EMAIL.search(sender)
    domain = (m.group(1).lower() if m else (sender.strip().lower() if "." in sender and " " not in sender else ""))
    if not domain:
        return out  # e.g. SMS short-code or phone number: nothing to check
    reg = registrable_domain(domain)
    if brands:
        for b in brands:
            if reg in BRANDS[b]:
                return [{"id": "sender_matches_brand", "label": f"Sender domain matches {b}'s known domain",
                         "severity": "info", "points": 0, "note": "Sender addresses can be spoofed; this is not proof of authenticity."}]
        if _brand_in_host(brands[0], domain):
            out.append({"id": "sender_lookalike",
                        "label": f"Sender domain imitates '{brands[0]}' but is not its known domain",
                        "severity": "high", "points": 20})
        elif reg in FREEMAIL:
            out.append({"id": "sender_freemail",
                        "label": f"Message claims to be from {brands[0]} but was sent from a free email provider",
                        "severity": "medium", "points": 15})
        else:
            out.append({"id": "sender_mismatch",
                        "label": f"Message mentions {brands[0]} but the sender domain is unrelated to it",
                        "severity": "medium", "points": 12})
    return out


def _level(score):
    if score < 20:
        return "Low"
    if score < 45:
        return "Medium"
    return "High"


def _label(level):
    return {"Low": "No strong phishing indicators found",
            "Medium": "Suspicious - review before acting",
            "High": "Likely phishing"}[level]


# ------------------------------------------------------------------ main
def analyze_message(channel, subject, body, sender, classify=classify_url):
    # ----- validation
    for name, val in (("subject", subject), ("body", body), ("sender", sender)):
        if val is not None and not isinstance(val, str):
            raise MessageValidationError(f"'{name}' must be text.")
    channel = (channel or "sms").lower()
    if channel not in ("sms", "email"):
        raise MessageValidationError("channel must be 'sms' or 'email'.")
    subject, body, sender = (subject or ""), (body or ""), (sender or "")
    if "\x00" in subject + body + sender:
        raise MessageValidationError("Unsupported content: binary data is not accepted.")
    if len(body) > MAX_BODY:
        raise MessageValidationError(f"Message body is too long (max {MAX_BODY} characters).")
    if len(subject) > MAX_SUBJECT:
        raise MessageValidationError(f"Subject is too long (max {MAX_SUBJECT} characters).")
    if len(sender) > MAX_SENDER:
        raise MessageValidationError(f"Sender is too long (max {MAX_SENDER} characters).")
    subject, body, sender = _normalise(subject).strip(), _normalise(body).strip(), _normalise(sender).strip()
    if not body and not subject:
        raise MessageValidationError("Please paste a message to analyze.")
    printable = sum(1 for c in body + subject if c.isprintable() or c in "\n\t")
    if (len(body) + len(subject)) and printable / (len(body) + len(subject)) < 0.9:
        raise MessageValidationError("Unsupported content: the text contains too many non-printable characters.")

    text = (subject + "\n" + body).strip()
    brands = _brand_mentions(text)
    indicators = []

    def add(iid, label, severity, points, m=None, note=None):
        row = {"id": iid, "label": label, "severity": severity, "points": points, "source": "rule"}
        if m is not None:
            row["evidence"] = _evidence(m, text)
        if note:
            row["note"] = note
        indicators.append(row)

    defensive = RE_DEFENSIVE.search(text)
    m_cred = RE_CRED_REQ.search(text)
    credential_flagged = False
    if m_cred and not (defensive and defensive.start() <= m_cred.end() and m_cred.start() <= defensive.end() + 60):
        add("credential_request", "Asks you to provide or confirm a password, PIN, OTP, card or ID details",
            "high", 30, m_cred)
        credential_flagged = True
    elif defensive:
        indicators.append({"id": "otp_warning_notice", "label": "Contains a 'do not share your OTP/password' warning (typical of genuine alerts)",
                           "severity": "info", "points": 0, "source": "rule"})
    m_login = RE_LOGIN_PROMPT.search(text)
    if m_login and not credential_flagged:
        add("login_prompt", "Prompts you to log in or verify your account", "medium", 10, m_login)
    m_pay = RE_PAYMENT.search(text)
    if m_pay:
        add("payment_pressure", "Demands a payment or mentions hard-to-trace payment methods", "high", 20, m_pay)
    m_thr = RE_THREAT.search(text)
    if m_thr:
        add("threat", "Threatens account suspension, expiry or legal consequences", "medium", 15, m_thr)
    m_prize = RE_PRIZE.search(text)
    if m_prize:
        add("prize", "Promises a prize, refund or reward", "medium", 15, m_prize)
    m_cta = RE_CTA.search(text)
    if m_cta:
        add("call_to_action", "Pushes you to click a link", "low", 4, m_cta)
    m_gen = RE_GENERIC_GREETING.search(text)
    if m_gen:
        add("generic_greeting", "Generic greeting instead of your name", "low", 4, m_gen)

    # urgency: contributes meaningfully only alongside another signal
    m_urg = RE_URGENCY.search(text)
    others = [i for i in indicators if i["points"] > 0 and i["id"] not in ("call_to_action", "generic_greeting")]
    # ----- links
    urls_all = extract_urls(text)
    urls = urls_all[:MAX_URLS_ANALYZED]
    url_reports, link_points, ml_points = [], 0, 0
    for u in urls:
        host = _host_of(u)
        rep = {"url": u[:300], "host": host[:253], "rule_flags": _link_flags(u, brands)}
        link_points += max([f["points"] for f in rep["rule_flags"]], default=0)
        full = u if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u) else "http://" + u
        if len(full) > 2048 or not is_valid_url(full):
            rep["ml_analysis"] = {"available": False, "reason": "Not a valid website link, or too long to analyze."}
        else:
            try:
                c = classify(full)
                rep["ml_analysis"] = {
                    "available": True, "source": "ml_model", "model": "RandomForest (URL features only)",
                    "prediction": c["prediction"], "confidence": c["confidence"],
                    "risk_score": c["risk_score"], "reasons": c["reasons"]}
                ml_points += {"PHISHING": 15, "SUSPICIOUS": 8}.get(c["prediction"], 0)
            except Exception:
                rep["ml_analysis"] = {"available": False, "reason": "URL model unavailable."}
        url_reports.append(rep)
    ml_points = min(ml_points, 20)
    link_points = min(link_points, 40)

    if url_reports:
        # deceptive-link flags also surfaced as message-level indicators
        for rep in url_reports:
            for f in rep["rule_flags"]:
                if f["points"] >= 15:
                    indicators.append({"id": f["id"], "label": f["label"] + f" ({rep['host'][:60]})",
                                       "severity": f["severity"], "points": f["points"], "source": "rule"})
    sender_f = _sender_findings(sender, brands)
    sender_points = sum(f["points"] for f in sender_f)

    base = sum(i["points"] for i in indicators if i["id"] not in
               {f["id"] for r in url_reports for f in r["rule_flags"]})
    # Impersonation indicator: brand claim only matters when verifiable evidence mismatches
    brand_flagged = any(f["id"] in ("brand_lookalike", "brand_mismatch") for r in url_reports for f in r["rule_flags"]) \
        or any(f["id"].startswith("sender_") and f["points"] for f in sender_f)
    if brands and brand_flagged:
        indicators.append({"id": "impersonation", "label": f"Possible impersonation of {', '.join(brands[:2])}",
                           "severity": "high", "points": 0, "source": "rule",
                           "note": "Brand named in the message but the link or sender does not match its known domain."})
    elif brands:
        indicators.append({"id": "brand_mention", "label": f"Mentions {', '.join(brands[:2])}",
                           "severity": "info", "points": 0, "source": "rule",
                           "note": "A brand name alone is not suspicious; it counts only if the link or sender does not match."})

    urgency_points = 0
    if m_urg:
        urgency_points = 10 if others or url_reports else 3
        indicators.append({"id": "urgency", "label": "Uses urgent or time-pressure language",
                           "severity": "medium" if urgency_points >= 10 else "low", "points": urgency_points,
                           "source": "rule", "evidence": _evidence(m_urg, text),
                           "note": ("Counted fully because other warning signs are present." if urgency_points >= 10
                                    else "Urgent wording alone is common in genuine messages, so it adds very little risk.")})

    rule_score = min(100, base + urgency_points + link_points + sender_points)
    # combination bonus when several independent risk categories line up
    cats = {i["id"] for i in indicators if i["points"] >= 15}
    if len(cats) >= 2:
        rule_score = min(100, rule_score + 10)
    total = min(100, rule_score + ml_points)
    level = _level(total)

    recs = []
    if level == "High":
        recs += ["Do not click any link, call back numbers in the message, or reply.",
                 "Never share OTPs, passwords, PINs or card details; genuine organisations do not ask for them by message.",
                 "Verify by contacting the organisation through its official app or website that you open yourself.",
                 "Report the message (e.g. forward SMS to 1909 in India, or use your email provider's 'report phishing')."]
    elif level == "Medium":
        recs += ["Do not act on the message until you verify it independently.",
                 "Open the organisation's official app or type its website address yourself instead of using the link.",
                 "Never share OTPs or passwords with anyone who contacts you first."]
    else:
        recs += ["No strong phishing indicators were found, but this is not a guarantee of safety.",
                 "Still avoid sharing OTPs or passwords, and be careful with unexpected links."]
    if any(r["rule_flags"] and any(f["id"] == "shortener" for f in r["rule_flags"]) for r in url_reports):
        recs.append("A shortened link was found: use Website Security Analysis to see where it leads before opening it.")

    return {
        "channel": channel,
        "classification": {
            "label": _label(level), "risk_level": level, "risk_score": total,
            "method": "rule_based",
            "method_note": ("Message text is assessed by hand-written rules; there is no trained text model "
                            "and no accuracy figure. The ML model is applied only to extracted links."),
        },
        "score_breakdown": {"rule_based_points": rule_score, "url_model_points": ml_points, "total": total},
        "message_indicators": indicators,
        "sender_findings": sender_f,
        "urls": url_reports,
        "urls_found": len(urls_all),
        "urls_analyzed": len(urls),
        "urls_truncated": len(urls_all) > len(urls),
        "recommendations": recs,
        "privacy_note": "The message is analyzed in memory and is not stored.",
        "limitations": [
            "Rules can miss novel phishing and can occasionally flag genuine messages.",
            "Sender addresses and phone numbers can be spoofed; a matching sender does not prove authenticity.",
            "Link results come from a URL-structure model trained on synthetic data and do not inspect page content.",
        ],
    }
