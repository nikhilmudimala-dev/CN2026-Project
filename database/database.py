import sqlite3
import json
from pathlib import Path


class Database:

    def __init__(self, db_path="database/sdn_blocking.db"):

        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        self.initialize()

    def connect(self):

        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row

        return connection

    def initialize(self):

        schema_path = (
            Path(__file__).parent / "schema.sql"
        )

        with open(schema_path, "r", encoding="utf-8") as file:
            schema = file.read()

        with self.connect() as connection:
            connection.executescript(schema)

    # -------------------------
    # EVENT OPERATIONS
    # -------------------------

    def insert_event(self, event):

        with self.connect() as connection:

            cursor = connection.execute(
                """
                INSERT INTO events (
                    event_type,
                    timestamp,
                    source_ip,
                    rule_id,
                    severity,
                    message,
                    details
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["event_type"],
                    event["timestamp"],
                    event.get("source_ip"),
                    event.get("rule_id"),
                    event.get("severity"),
                    event.get("message"),
                    json.dumps(event.get("details", {}))
                )
            )

            return cursor.lastrowid

    def get_events(self, limit=100):

        with self.connect() as connection:

            rows = connection.execute(
                """
                SELECT * FROM events
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,)
            ).fetchall()

            results = []

            for row in rows:
                event = dict(row)
                event["details"] = json.loads(
                    event["details"] or "{}"
                )
                results.append(event)

            return results

    # -------------------------
    # BLOCKING INCIDENTS
    # -------------------------

    def insert_blocking_incident(self, incident):

        with self.connect() as connection:

            cursor = connection.execute(
                """
                INSERT INTO blocking_incidents (
                    source_ip,
                    rule_id,
                    severity,
                    offence_count,
                    ban_duration_seconds,
                    timestamp
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    incident["source_ip"],
                    incident["rule_id"],
                    incident["severity"],
                    incident["offence_count"],
                    incident["ban_duration_seconds"],
                    incident["timestamp"]
                )
            )

            return cursor.lastrowid

    def get_blocking_history(self, source_ip):

        with self.connect() as connection:

            rows = connection.execute(
                """
                SELECT * FROM blocking_incidents
                WHERE source_ip = ?
                ORDER BY timestamp DESC
                """,
                (source_ip,)
            ).fetchall()

            return [dict(row) for row in rows]

    def count_recent_incidents(
        self,
        source_ip,
        current_time,
        history_window_seconds
    ):

        cutoff = current_time - history_window_seconds

        with self.connect() as connection:

            row = connection.execute(
                """
                SELECT COUNT(*) AS total
                FROM blocking_incidents
                WHERE source_ip = ?
                AND timestamp >= ?
                """,
                (source_ip, cutoff)
            ).fetchone()

            return row["total"]

    # -------------------------
    # ACTIVE BAN OPERATIONS
    # -------------------------

    def insert_active_ban(self, ban):

        with self.connect() as connection:

            connection.execute(
                """
                INSERT OR REPLACE INTO active_bans (
                    source_ip,
                    rule_id,
                    severity,
                    offence_count,
                    start_time,
                    expiry_time,
                    cookie
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ban["source_ip"],
                    ban["rule_id"],
                    ban["severity"],
                    ban["offence_count"],
                    ban["start_time"],
                    ban["expiry_time"],
                    ban["cookie"]
                )
            )

    def remove_active_ban(self, source_ip):

        with self.connect() as connection:

            connection.execute(
                """
                DELETE FROM active_bans
                WHERE source_ip = ?
                """,
                (source_ip,)
            )

    def get_active_bans(self):

        with self.connect() as connection:

            rows = connection.execute(
                """
                SELECT * FROM active_bans
                ORDER BY start_time DESC
                """
            ).fetchall()

            return [dict(row) for row in rows]
