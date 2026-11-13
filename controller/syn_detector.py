
from collections import defaultdict

from controller.detection_engine import DetectionResult
from controller.severity_classifier import SeverityClassifier


class SynRateDetector:

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

        self.windows = defaultdict(lambda: {
            "start": None,
            "count": 0
        })

    def evaluate(self, traffic):

        if traffic.protocol != "TCP":
            return None

        if not traffic.tcp_syn or traffic.tcp_ack:
            return None

        source_ip = traffic.src_ip
        current_time = traffic.timestamp

        window = self.windows[source_ip]

        if window["start"] is None:
            window["start"] = current_time

        if current_time - window["start"] >= self.window_seconds:
            return None

        window["count"] += 1

        return None

    def finalize_windows(self, current_time):

        results = []

        for source_ip, window in list(self.windows.items()):

            if window["start"] is None:
                continue

            if current_time - window["start"] < self.window_seconds:
                continue

            count = window["count"]

            if count > self.threshold:

                severity = self.severity_classifier.classify(
                    count,
                    self.threshold
                )

                results.append(
                    DetectionResult(
                        rule_id="R1_SYN_RATE",
                        source_ip=source_ip,
                        severity=severity,
                        action="BLOCK",
                        reason=f"Excessive TCP SYN activity: {count} packets",
                        observed_value=count,
                        threshold=self.threshold
                    )
                )

            del self.windows[source_ip]

        return results

