from dashboard.traffic_api import traffic_api

from flask import Flask, jsonify, render_template, request
from pathlib import Path
import sqlite3
import json
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "database" / "sdn_blocking.db"
CONFIG_PATH = ROOT / "config" / "rules.json"

app = Flask(__name__)
app.register_blueprint(traffic_api)


def get_db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def read_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as file:
        return json.load(file)


def write_config(config):
    temporary = CONFIG_PATH.with_suffix(".tmp")
    with open(temporary, "w", encoding="utf-8") as file:
        json.dump(config, file, indent=4)
    temporary.replace(CONFIG_PATH)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/overview")
def overview():
    db = get_db()
    now = time.time()

    events = db.execute(
        "SELECT COUNT(*) FROM events"
    ).fetchone()[0]

    detections = db.execute(
        "SELECT COUNT(*) FROM events WHERE event_type='DETECTION'"
    ).fetchone()[0]

    alerts = db.execute(
        "SELECT COUNT(*) FROM events WHERE event_type='ALERT'"
    ).fetchone()[0]

    incidents = db.execute(
        "SELECT COUNT(*) FROM blocking_incidents"
    ).fetchone()[0]

    active_bans = db.execute(
        "SELECT COUNT(*) FROM active_bans WHERE expiry_time > ?",
        (now,)
    ).fetchone()[0]

    hosts = db.execute(
        "SELECT COUNT(DISTINCT source_ip) FROM events WHERE source_ip IS NOT NULL"
    ).fetchone()[0]

    rule_counts = db.execute("""
        SELECT rule_id, COUNT(*) AS total
        FROM events
        WHERE event_type IN ('DETECTION', 'ALERT')
        GROUP BY rule_id
    """).fetchall()

    recent_events = db.execute("""
        SELECT * FROM events
        ORDER BY id DESC LIMIT 8
    """).fetchall()

    db.close()

    return jsonify({
        "total_events": events,
        "detections": detections,
        "alerts": alerts,
        "blocking_incidents": incidents,
        "active_bans": active_bans,
        "observed_hosts": hosts,
        "switches": 4,
        "hosts": 12,
        "rule_counts": [dict(row) for row in rule_counts],
        "recent_events": [dict(row) for row in recent_events]
    })


@app.route("/api/events")
def events():
    limit = request.args.get("limit", 100, type=int)
    limit = max(1, min(limit, 500))

    db = get_db()
    rows = db.execute("""
        SELECT * FROM events
        ORDER BY id DESC LIMIT ?
    """, (limit,)).fetchall()
    db.close()

    return jsonify([dict(row) for row in rows])


@app.route("/api/bans")
def bans():
    db = get_db()
    rows = db.execute("""
        SELECT * FROM active_bans
        ORDER BY expiry_time DESC
    """).fetchall()
    db.close()

    now = time.time()
    result = []

    for row in rows:
        ban = dict(row)
        ban["remaining_seconds"] = max(
            0, int(ban["expiry_time"] - now)
        )
        result.append(ban)

    return jsonify(result)


@app.route("/api/incidents")
def incidents():
    db = get_db()
    rows = db.execute("""
        SELECT * FROM blocking_incidents
        ORDER BY id DESC LIMIT 100
    """).fetchall()
    db.close()

    return jsonify([dict(row) for row in rows])


@app.route("/api/rules", methods=["GET"])
def get_rules():
    return jsonify(read_config())


@app.route("/api/rules", methods=["PUT"])
def update_rules():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid configuration"}), 400

    try:
        current = read_config()

        for rule_id in ("syn_rate", "connection_burst", "port_scan"):
            supplied = data["rules"][rule_id]
            threshold = int(supplied["threshold"])
            window = int(supplied["window_seconds"])

            if threshold < 1 or window < 1:
                raise ValueError("Thresholds and windows must be positive")

            current["rules"][rule_id]["threshold"] = threshold
            current["rules"][rule_id]["window_seconds"] = window

        write_config(current)
        return jsonify({"success": True, "config": current})

    except (KeyError, TypeError, ValueError) as error:
        return jsonify({"error": str(error)}), 400


@app.route("/api/topology")
def topology():
    return jsonify({
        "core": "s1",
        "access_switches": ["s2", "s3", "s4"],
        "hosts": [
            {
                "name": f"h{i}",
                "ip": f"10.0.0.{i}",
                "switch": f"s{2 + (i - 1) // 4}"
            }
            for i in range(1, 13)
        ]
    })


@app.route("/api/activity")
def activity():
    db = get_db()
    rows = db.execute("""
        SELECT
            strftime('%H:00', timestamp) AS hour,
            COUNT(*) AS total
        FROM events
        WHERE timestamp >= datetime('now', '-24 hours')
        GROUP BY hour
        ORDER BY hour
    """).fetchall()
    db.close()

    return jsonify([dict(row) for row in rows])


if __name__ == "__main__":
    print("SDN Security Dashboard starting...")
    print("Open http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
