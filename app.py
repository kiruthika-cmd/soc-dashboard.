"""
SOC Dashboard - Flask Backend API
Run: python app.py
Then open: http://localhost:5000
"""

from flask import Flask, jsonify, send_from_directory
import sqlite3
import json
from datetime import datetime
from pathlib import Path

app = Flask(__name__, static_folder="dashboard")

DB_PATH = "soc_events.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ─── API Routes ───────────────────────────────

@app.route("/")
def index():
    return send_from_directory("dashboard", "index.html")


@app.route("/api/stats")
def stats():
    conn = get_db()
    cursor = conn.cursor()

    total = cursor.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    critical = cursor.execute("SELECT COUNT(*) FROM events WHERE severity='CRITICAL'").fetchone()[0]
    high = cursor.execute("SELECT COUNT(*) FROM events WHERE severity='HIGH'").fetchone()[0]
    alerts = cursor.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    conn.close()

    return jsonify({
        "total_events": total,
        "critical_events": critical,
        "high_events": high,
        "total_alerts": alerts
    })


@app.route("/api/alerts")
def get_alerts():
    conn = get_db()
    cursor = conn.cursor()
    rows = cursor.execute("""
        SELECT * FROM alerts ORDER BY created_at DESC LIMIT 50
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/events")
def get_events():
    conn = get_db()
    cursor = conn.cursor()
    rows = cursor.execute("""
        SELECT * FROM events ORDER BY timestamp DESC LIMIT 100
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/severity-chart")
def severity_chart():
    conn = get_db()
    cursor = conn.cursor()
    rows = cursor.execute("""
        SELECT severity, COUNT(*) as count FROM events GROUP BY severity
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/top-ips")
def top_ips():
    conn = get_db()
    cursor = conn.cursor()
    rows = cursor.execute("""
        SELECT source_ip, COUNT(*) as count FROM events
        WHERE source_ip != '-' AND source_ip != 'Unknown'
        GROUP BY source_ip ORDER BY count DESC LIMIT 10
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/event-timeline")
def event_timeline():
    conn = get_db()
    cursor = conn.cursor()
    rows = cursor.execute("""
        SELECT substr(timestamp, 1, 13) as hour, COUNT(*) as count
        FROM events GROUP BY hour ORDER BY hour
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    # Auto-run parser if DB doesn't exist
    if not Path(DB_PATH).exists():
        print("[*] Database not found. Running log parser first...")
        import subprocess
        subprocess.run(["python", "log_parser.py"])

    print("\n[✓] SOC Dashboard running at: http://localhost:5000\n")
    app.run(debug=True, port=5000)