from collections import deque
from datetime import datetime, timezone


class EventManager:

    def __init__(self, database=None, max_events=10000):

        self.events = deque(maxlen=max_events)
        self.subscribers = []
        self.database = database

    def subscribe(self, callback):

        if callback not in self.subscribers:
            self.subscribers.append(callback)

    def unsubscribe(self, callback):

        if callback in self.subscribers:
            self.subscribers.remove(callback)

    def publish(
        self,
        event_type,
        source_ip=None,
        rule_id=None,
        severity=None,
        message="",
        details=None
    ):

        event = {
            "event_type": event_type,
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            "source_ip": source_ip,
            "rule_id": rule_id,
            "severity": severity,
            "message": message,
            "details": details or {}
        }

        # Store the event in memory.
        self.events.append(event)

        # Persist the event in SQLite, if a database is connected.
        if self.database is not None:
            self.database.insert_event(event)

        # Notify registered subscribers.
        for callback in self.subscribers:
            try:
                callback(event)
            except Exception as error:
                print(f"Event subscriber error: {error}")

        return event

    def get_events(self, limit=None):

        events = list(self.events)

        if limit is not None:
            if limit <= 0:
                return []

            events = events[-limit:]

        return list(reversed(events))

    def clear_events(self):

        self.events.clear()

    def get_event_count(self):

        return len(self.events)
