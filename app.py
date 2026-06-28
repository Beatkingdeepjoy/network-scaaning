"""
NetSentry Scanner API
----------------------
Flask backend exposing scan operations over HTTP for the dashboard frontend.

Run with:
    python app.py
Then open frontend/index.html in a browser, or serve it with any static
file server. The frontend expects this API at http://localhost:5000.
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import sqlite3
import json
import ipaddress
from datetime import datetime

from scanner import run_scan, USE_NMAP

app = Flask(__name__)
CORS(app)

DB_PATH = "scans.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subnet TEXT NOT NULL,
            engine TEXT NOT NULL,
            host_count INTEGER NOT NULL,
            duration_seconds REAL NOT NULL,
            scanned_at TEXT NOT NULL,
            raw_json TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def save_scan(result: dict) -> int:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute(
        "INSERT INTO scans (subnet, engine, host_count, duration_seconds, scanned_at, raw_json) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (result["subnet"], result["engine"], result["host_count"],
         result["duration_seconds"], result["scanned_at"], json.dumps(result))
    )
    conn.commit()
    scan_id = cur.lastrowid
    conn.close()
    return scan_id


@app.route("/api/status", methods=["GET"])
def status():
    return jsonify({
        "online": True,
        "engine": "nmap" if USE_NMAP else "fallback",
        "message": "nmap detected, full scanning enabled" if USE_NMAP
                    else "nmap not found, using pure-python fallback scanner"
    })


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(force=True) or {}
    subnet = data.get("subnet", "").strip()

    if not subnet:
        return jsonify({"error": "subnet is required, e.g. 192.168.1.0/24"}), 400

    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return jsonify({"error": f"'{subnet}' is not a valid CIDR range"}), 400

    if network.num_addresses > 1024:
        return jsonify({"error": "Range too large. Use a /22 or smaller (max 1024 addresses)."}), 400

    try:
        result = run_scan(subnet)
        scan_id = save_scan(result)
        result["scan_id"] = scan_id
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scans", methods=["GET"])
def list_scans():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT id, subnet, engine, host_count, duration_seconds, scanned_at "
        "FROM scans ORDER BY id DESC LIMIT 20"
    ).fetchall()
    conn.close()

    scans = [
        {
            "scan_id": r[0], "subnet": r[1], "engine": r[2],
            "host_count": r[3], "duration_seconds": r[4], "scanned_at": r[5],
        }
        for r in rows
    ]
    return jsonify({"scans": scans})


@app.route("/api/scans/<int:scan_id>", methods=["GET"])
def get_scan(scan_id):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT raw_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "scan not found"}), 404

    return jsonify(json.loads(row[0]))


if __name__ == "__main__":
    init_db()
    print("=" * 60)
    print(" NetSentry Scanner API")
    print(f" Engine: {'nmap (full)' if USE_NMAP else 'pure-python fallback'}")
    print(" Listening on http://localhost:5000")
    print("=" * 60)
    app.run(debug=True, port=5000)
