
from collections import defaultdict, deque


class OffenderManager:

    BLOCKING_RULES = {
        "R1_SYN_RATE",
        "R2_CONNECTION_BURST"
    }

    def __init__(self, history_window_seconds=3600):

        self.history_window_seconds = history_window_seconds

        # Stores blocking incident timestamps for each host.
        self.incident_history = defaultdict(deque)

    def register_incident(self, source_ip, rule_id, timestamp):

        # Only R1 and R2 contribute to offence history.
        if rule_id not in self.BLOCKING_RULES:
            raise ValueError(
                f"{rule_id} is not permitted to create a blocking incident"
            )

        history = self.incident_history[source_ip]

        # Remove incidents outside the one-hour history window.
        self._remove_expired(history, timestamp)

        # Record the new blocking incident.
        history.append(timestamp)

        return len(history)

    def get_offence_count(self, source_ip, current_time):

        history = self.incident_history[source_ip]

        self._remove_expired(history, current_time)

        return len(history)

    def _remove_expired(self, history, current_time):

        cutoff = current_time - self.history_window_seconds

        while history and history[0] < cutoff:
            history.popleft()

