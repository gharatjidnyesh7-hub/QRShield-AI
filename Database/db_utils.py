"""
QRShield AI - Database Layer
==============================
SQLite database for scan history and dashboard aggregation.
Uses parameterized queries exclusively to prevent SQL injection.
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "Database", "qrshield.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_date TEXT NOT NULL,
            scan_time TEXT NOT NULL,
            url TEXT NOT NULL,
            source TEXT NOT NULL,           -- 'webcam' | 'upload' | 'manual'
            prediction TEXT NOT NULL,       -- SAFE | SUSPICIOUS | PHISHING
            confidence REAL NOT NULL,
            risk_score INTEGER NOT NULL,
            reasons TEXT,                   -- JSON-encoded list of reason strings
            created_at TEXT NOT NULL
        )
    """)
    # Optional users table (kept minimal, per spec's "Users (optional)")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def insert_scan(url, source, prediction, confidence, risk_score, reasons_json):
    conn = get_connection()
    now = datetime.now()
    conn.execute(
        """INSERT INTO scan_history
           (scan_date, scan_time, url, source, prediction, confidence, risk_score, reasons, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            now.strftime("%Y-%m-%d"),
            now.strftime("%H:%M:%S"),
            url,
            source,
            prediction,
            confidence,
            risk_score,
            reasons_json,
            now.isoformat(),
        ),
    )
    conn.commit()
    new_id = conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    conn.close()
    return new_id


def get_history(limit=200):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM scan_history ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_dashboard_stats():
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) AS c FROM scan_history").fetchone()["c"]
    by_pred = conn.execute(
        "SELECT prediction, COUNT(*) AS c FROM scan_history GROUP BY prediction"
    ).fetchall()
    recent = conn.execute(
        "SELECT * FROM scan_history ORDER BY id DESC LIMIT 10"
    ).fetchall()
    conn.close()

    counts = {"SAFE": 0, "SUSPICIOUS": 0, "PHISHING": 0}
    for row in by_pred:
        counts[row["prediction"]] = row["c"]

    return {
        "total_scans": total,
        "safe_count": counts["SAFE"],
        "suspicious_count": counts["SUSPICIOUS"],
        "phishing_count": counts["PHISHING"],
        "recent_activity": [dict(r) for r in recent],
    }
