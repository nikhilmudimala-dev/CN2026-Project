
import logging
from collections import defaultdict, deque

from controller.detection_engine import DetectionResult
from controller.severity_classifier import SeverityClassifier


logger = logging.getLogger(__name__)


class ConnectionBurstDetector:

    def __init__(
        self,
        threshold,
        window_seconds,
        severity_multipliers,
        handshake_timeout=30
    ):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.handshake_timeout = handshake_timeout

        self.severity_classifier = SeverityClassifier(
            severity_multipliers
        )

        self.pending = {}
        self.completed = {}

        self.connection_windows = defaultdict(lambda: {
            "start": None,
            "count": 0
        })

    def evaluate(self, traffic):

        if traffic.protocol != "TCP":
            return None

        if traffic.src_port is None or traffic.dst_port is None:
            return None

        now = traffic.timestamp

        src = (
            traffic.src_ip,
            traffic.src_port,
            traffic.dst_ip,
            traffic.dst_port
        )

        reverse = (
            traffic.dst_ip,
            traffic.dst_port,
            traffic.src_ip,
            traffic.src_port
        )

        expired_pending = [
            key for key, value in self.pending.items()
            if now - value["timestamp"] > self.handshake_timeout
        ]

        for key in expired_pending:
            del self.pending[key]
            logger.info("R2: Pending handshake expired: %s", key)

        expired_completed = [
            key for key, timestamp in self.completed.items()
            if now - timestamp > self.handshake_timeout
        ]

        for key in expired_completed:
            del self.completed[key]

        if traffic.tcp_fin or traffic.tcp_rst:
            self.pending.pop(src, None)
            self.pending.pop(reverse, None)
            return None

        if traffic.tcp_syn and not traffic.tcp_ack:

            if src in self.completed:
                return None

            if src not in self.pending:
                self.pending[src] = {
                    "state": "SYN_SENT",
                    "timestamp": now
                }

                logger.info("R2: New SYN recorded: %s", src)

            return None

        if traffic.tcp_syn and traffic.tcp_ack:

            if reverse in self.pending:

                state = self.pending[reverse]["state"]

                if state == "SYN_SENT":
                    self.pending[reverse]["state"] = "SYN_ACK_RECEIVED"
                    logger.info("R2: SYN-ACK matched: %s", reverse)

            return None

        if traffic.tcp_ack and not traffic.tcp_syn:

            if src not in self.pending:
                return None

            if self.pending[src]["state"] != "SYN_ACK_RECEIVED":
                return None

            del self.pending[src]
            self.completed[src] = now

            source_ip = traffic.src_ip
            window = self.connection_windows[source_ip]

            if window["start"] is None:
                window["start"] = now

            if now - window["start"] >= self.window_seconds:
                return None

            window["count"] += 1

            logger.info(
                "R2: Connection established from %s. Count: %s",
                source_ip,
                window["count"]
            )

        return None

    def finalize_windows(self, current_time):

        results = []

        for source_ip, window in list(self.connection_windows.items()):

            if window["start"] is None:
                continue

            if current_time - window["start"] < self.window_seconds:
                continue

            count = window["count"]

            if count >= self.threshold:

                severity = self.severity_classifier.classify(
                    count,
                    self.threshold
                )

                logger.info(
                    "R2: Observation window completed for %s: %s connections",
                    source_ip,
                    count
                )

                results.append(
                    DetectionResult(
                        rule_id="R2_CONNECTION_BURST",
                        source_ip=source_ip,
                        severity=severity,
                        action="BLOCK",
                        reason=f"Excessive established TCP connections: {count}",
                        observed_value=count,
                        threshold=self.threshold
                    )
                )

            del self.connection_windows[source_ip]

        return results

