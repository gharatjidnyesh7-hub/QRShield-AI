"""
QRShield AI - Dataset Generation
==================================
IMPORTANT / HONESTY NOTE
-------------------------
This sandbox has no internet access, so the real Kaggle phishing-URL
dataset (e.g. "Phishing Website Detector" / UCI Phishing Websites Data
Set) could not be downloaded here. This script instead SYNTHESISES a
dataset of ~6,000 URLs whose feature distributions are built to mirror
the statistical patterns published for that dataset (phishing URLs
skew toward: no HTTPS, IP-based hosts, long URLs, many special chars,
suspicious keywords; legitimate URLs skew the opposite way), so the
end-to-end ML pipeline, metrics, and model are all genuinely trained
and real -- only the source data is synthetic rather than scraped.

TO USE THE REAL KAGGLE DATASET INSTEAD (recommended before your final
submission):
  1. Download e.g. https://www.kaggle.com/datasets/eswarchandt/phishing-website-detector
  2. Place the CSV at Dataset/phishing_raw.csv with a 'url' and 'label'
     column (label: 0 = legitimate, 1 = phishing).
  3. Run: python generate_dataset.py --from-csv Dataset/phishing_raw.csv
  This will re-extract features with the SAME feature_extraction.py
  module used at inference time, guaranteeing consistency.
"""

import sys
import os
import argparse
import random
import pandas as pd
import numpy as np

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "Backend"))
from feature_extraction import extract_features, is_valid_url, FEATURE_ORDER  # noqa: E402

random.seed(42)

LEGIT_DOMAINS = [
    "google.com", "github.com", "wikipedia.org", "amazon.com", "microsoft.com",
    "nptel.ac.in", "mit.edu", "python.org", "stackoverflow.com", "linkedin.com",
    "flipkart.com", "irctc.co.in", "icicibank.com", "hdfcbank.com", "sbi.co.in",
    "geeksforgeeks.org", "w3schools.com", "reddit.com", "nytimes.com", "bbc.com",
]

LEGIT_PATHS = ["", "/home", "/about", "/products", "/blog/2024/article", "/docs/api",
               "/user/profile", "/search?q=machine+learning", "/course/aiml", "/contact"]

PHISH_KEYWORDS = ["login", "verify", "secure", "update", "bank-account", "signin",
                   "confirm-password", "webscr", "billing-update", "account-verify"]

PHISH_TLDS = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work", "info"]

SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd", "cutt.ly"]


def random_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))


def gen_legit_url():
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(LEGIT_PATHS)
    sub = random.choice(["", "www.", "docs.", "www.", "www.", "en."])
    return f"https://{sub}{domain}{path}"


def gen_phishing_url():
    style = random.choice(["ip", "shortener", "fake_subdomain", "long_suspicious", "typosquat"])
    kw = random.choice(PHISH_KEYWORDS)
    if style == "ip":
        return f"http://{random_ip()}/{kw}/index.php?session={random.randint(1000,999999)}"
    if style == "shortener":
        return f"http://{random.choice(SHORTENERS)}/{random.randint(1000,9999)}xz"
    if style == "fake_subdomain":
        base = random.choice(["paypal", "amazon", "icicibank", "hdfcbank", "microsoft"])
        tld = random.choice(PHISH_TLDS)
        return f"http://{kw}.{base}-{random.choice(['secure','update','support'])}.{tld}/{kw}.php"
    if style == "long_suspicious":
        base = random.choice(["paypal", "netflix", "amazon", "sbi"])
        tld = random.choice(PHISH_TLDS)
        junk = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789-", k=random.randint(15, 35)))
        return f"http://{base}-{kw}-{junk}.{tld}/{kw}/{junk}"
    # typosquat
    base = random.choice(["gooogle", "micros0ft", "amaz0n", "paypa1", "faceb00k"])
    tld = random.choice(PHISH_TLDS + ["com"])
    return f"http://{base}.{tld}/{kw}-confirm.html?id={random.randint(100,99999)}"


def gen_borderline_legit_url():
    """Legitimate but slightly unusual URLs (long query strings, extra
    subdomains, a hyphen or two) so the classes overlap a bit, matching
    the ambiguity found in real-world phishing datasets."""
    domain = random.choice(LEGIT_DOMAINS)
    junk = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(8, 20)))
    sub = random.choice(["cdn.", "static-assets.", "api-v2.", "user-portal."])
    return f"https://{sub}{domain}/session/{junk}?ref={random.randint(100,999)}&track=1"


def gen_borderline_phishing_url():
    """Phishing URLs that use HTTPS (via free certs, as real attackers
    increasingly do) and shorter, less obviously malicious paths, so
    'has_https' alone isn't a perfect signal."""
    kw = random.choice(PHISH_KEYWORDS)
    base = random.choice(["paypal", "amazon", "icicibank", "netflix"])
    tld = random.choice(PHISH_TLDS + ["com"])
    return f"https://{base}-{kw}.{tld}/{kw}"


def build_dataframe(n_per_class=3000):
    rows = []
    n_border = int(n_per_class * 0.15)
    n_clear = n_per_class - n_border
    for _ in range(n_clear):
        url = gen_legit_url()
        feat = extract_features(url)
        feat["url"] = url
        feat["label"] = 0  # legitimate
        rows.append(feat)
    for _ in range(n_border):
        url = gen_borderline_legit_url()
        feat = extract_features(url)
        feat["url"] = url
        feat["label"] = 0
        rows.append(feat)
    for _ in range(n_clear):
        url = gen_phishing_url()
        feat = extract_features(url)
        feat["url"] = url
        feat["label"] = 1  # phishing
        rows.append(feat)
    for _ in range(n_border):
        url = gen_borderline_phishing_url()
        feat = extract_features(url)
        feat["url"] = url
        feat["label"] = 1
        rows.append(feat)
    df = pd.DataFrame(rows)

    # Inject small amount of realistic noise: a few % of labels are flipped
    # (mirrors mislabeled/ambiguous entries present in real scraped datasets)
    # and numeric features get minor random jitter.
    rng = random.Random(7)
    n_flip = int(len(df) * 0.03)
    flip_idx = rng.sample(range(len(df)), n_flip)
    df.loc[flip_idx, "label"] = 1 - df.loc[flip_idx, "label"]

    numeric_cols = [c for c in FEATURE_ORDER if c not in
                    ("has_https", "has_ip", "is_shortened", "tld_suspicious", "has_at_symbol")]
    jitter_rng = np.random.default_rng(7)
    for col in numeric_cols:
        jitter = jitter_rng.integers(-2, 3, size=len(df))
        df[col] = (df[col] + jitter).clip(lower=0)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df[["url"] + FEATURE_ORDER + ["label"]]


def build_from_real_csv(path):
    raw = pd.read_csv(path)
    if "url" not in raw.columns or "label" not in raw.columns:
        raise ValueError("CSV must contain 'url' and 'label' columns")
    rows = []
    for _, r in raw.iterrows():
        if not is_valid_url(str(r["url"])):
            continue
        feat = extract_features(str(r["url"]))
        feat["url"] = r["url"]
        feat["label"] = int(r["label"])
        rows.append(feat)
    df = pd.DataFrame(rows)
    return df[["url"] + FEATURE_ORDER + ["label"]]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--from-csv", type=str, default=None,
                        help="Path to a real Kaggle phishing dataset CSV with url,label columns")
    parser.add_argument("--n-per-class", type=int, default=3000)
    args = parser.parse_args()

    out_path = os.path.join(os.path.dirname(__file__), "phishing_features.csv")

    if args.from_csv:
        df = build_from_real_csv(args.from_csv)
        print(f"Built dataset from real CSV: {args.from_csv}")
    else:
        df = build_dataframe(args.n_per_class)
        print("Built SYNTHETIC dataset (no internet access available to fetch real Kaggle CSV).")
        print("See module docstring for instructions to swap in the real dataset.")

    df.to_csv(out_path, index=False)
    print(f"Saved {len(df)} rows -> {out_path}")
    print(df["label"].value_counts())
