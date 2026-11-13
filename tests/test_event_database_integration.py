
from database.database import Database
from controller.event_manager import EventManager


def test_event_database_integration(tmp_path):
    db = Database(str(tmp_path / "test_event_integration.db"))

    manager = EventManager(database=db)

    received_events = []
    manager.subscribe(received_events.append)

    manager.publish(
        event_type="DETECTION",
        source_ip="10.0.0.5",
        rule_id="R1_SYN_RATE",
        severity="HIGH",
        message="Excessive TCP SYN activity",
        details={
            "observed_value": 25,
            "threshold": 10
        }
    )

    assert manager.get_event_count() == 1

    assert len(received_events) == 1
    assert received_events[0]["source_ip"] == "10.0.0.5"

    stored_events = db.get_events()

    assert len(stored_events) == 1
    assert stored_events[0]["source_ip"] == "10.0.0.5"
    assert stored_events[0]["rule_id"] == "R1_SYN_RATE"

    details = stored_events[0]["details"]

    assert details["observed_value"] == 25
    assert details["threshold"] == 10

