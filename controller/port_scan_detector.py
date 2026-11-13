from collections import defaultdict, deque

from controller.detection_engine import DetectionResult
from controller.severity_classifier import SeverityClassifier


class PortScanDetector:

    def __init__(
        self,
        threshold,
        window_seconds,
        severity_multipliers
    ):
        self.threshold = threshold
        self.window_seconds = window_seconds

        self.severity_classifier = SeverityClassifier(
            severity_multipliers
        )

        self.port_history = defaultdict(deque)
        self.active_incidents = set()

    def evaluate(self, traffic):

        if traffic.protocol != "TCP":
            return None

        if not traffic.tcp_syn or traffic.tcp_ack:
            return None

        if traffic.dst_port is None:
            return None

        source_ip = traffic.src_ip
        destination_ip = traffic.dst_ip
        current_time = traffic.timestamp

        pair = (source_ip, destination_ip)

        history = self.port_history[pair]

        history.append((current_time, traffic.dst_port))

        while (
            history
            and current_time - history[0][0] > self.window_seconds
        ):
            history.popleft()

        distinct_ports = {
            port for timestamp, port in history
        }

        count = len(distinct_ports)

        if count <= self.threshold:
            self.active_incidents.discard(pair)
            return None

        if pair in self.active_incidents:
            return None

        severity = self.severity_classifier.classify(
            count,
            self.threshold
        )

        self.active_incidents.add(pair)

        return DetectionResult(
            rule_id="R3_PORT_SCAN",
            source_ip=source_ip,
            severity=severity,
            action="FLAG",
            reason=(
                f"Port scan suspected: {count} distinct TCP ports "
                f"contacted on {destination_ip}"
            ),
            observed_value=count,
            threshold=self.threshold
        )
