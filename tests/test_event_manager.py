from controller.event_manager import EventManager


manager = EventManager()

received_events = []


# Register a subscriber.
manager.subscribe(received_events.append)


# Publish a detection event.
event1 = manager.publish(
    event_type="DETECTION",
    source_ip="10.0.0.1",
    rule_id="R1_SYN_RATE",
    severity="HIGH",
    message="Excessive TCP SYN activity"
)


# Publish a blocking event.
event2 = manager.publish(
    event_type="HOST_BLOCKED",
    source_ip="10.0.0.1",
    rule_id="R1_SYN_RATE",
    severity="HIGH",
    message="Host temporarily blocked",
    details={
        "duration_seconds": 300
    }
)


# Publish a port scan flag.
event3 = manager.publish(
    event_type="PORT_SCAN_FLAG",
    source_ip="10.0.0.2",
    rule_id="R3_PORT_SCAN",
    severity="MEDIUM",
    message="Suspicious port scanning activity"
)


# Verify event storage.
assert manager.get_event_count() == 3

# Verify subscriber notifications.
assert len(received_events) == 3

# Verify newest event appears first.
latest_events = manager.get_events(limit=2)

assert latest_events[0]["event_type"] == "PORT_SCAN_FLAG"
assert latest_events[1]["event_type"] == "HOST_BLOCKED"

# Verify event details.
assert event2["details"]["duration_seconds"] == 300

# Verify unsubscribe.
manager.unsubscribe(received_events.append)

manager.publish(
    event_type="BAN_EXPIRED",
    source_ip="10.0.0.1",
    message="Ban expired"
)

assert len(received_events) == 3

print("Total stored events:", manager.get_event_count())
print("Subscriber notifications:", len(received_events))
print("Latest event:", manager.get_events(limit=1)[0]["event_type"])

print("\nALL EVENT MANAGER TESTS PASSED")
