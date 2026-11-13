
from database.database import Database


def test_database_operations(tmp_path):
    db = Database(str(tmp_path / "test_sdn_blocking.db"))

    event = {
        "event_type": "DETECTION",
        "timestamp": "2026-11-10T10:00:00+00:00",
        "source_ip": "10.0.0.1",
        "rule_id": "R1_SYN_RATE",
        "severity": "HIGH",
        "message": "Excessive TCP SYN activity",
        "details": {
            "observed_value": 20,
            "threshold": 10
        }
    }

    db.insert_event(event)

    events = db.get_events()

    assert len(events) == 1
    assert events[0]["source_ip"] == "10.0.0.1"
    assert events[0]["details"]["observed_value"] == 20

    incident = {
        "source_ip": "10.0.0.1",
        "rule_id": "R1_SYN_RATE",
        "severity": "HIGH",
        "offence_count": 1,
        "ban_duration_seconds": 300,
        "timestamp": 1000
    }

    db.insert_blocking_incident(incident)

    history = db.get_blocking_history("10.0.0.1")

    assert len(history) == 1
    assert history[0]["ban_duration_seconds"] == 300

    count = db.count_recent_incidents(
        "10.0.0.1",
        current_time=1100,
        history_window_seconds=3600
    )

    assert count == 1

    ban = {
        "source_ip": "10.0.0.1",
        "rule_id": "R1_SYN_RATE",
        "severity": "HIGH",
        "offence_count": 1,
        "start_time": 1000,
        "expiry_time": 1300,
        "cookie": 12345
    }

    db.insert_active_ban(ban)

    active_bans = db.get_active_bans()

    assert len(active_bans) == 1
    assert active_bans[0]["cookie"] == 12345

    db.remove_active_ban("10.0.0.1")

    assert len(db.get_active_bans()) == 0

