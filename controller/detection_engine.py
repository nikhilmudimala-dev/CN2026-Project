
from dataclasses import dataclass
from typing import Optional


@dataclass
class TrafficRecord:
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str

    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    tcp_syn: bool = False
    tcp_ack: bool = False
    tcp_fin: bool = False
    tcp_rst: bool = False


@dataclass
class DetectionResult:
    rule_id: str
    source_ip: str
    severity: str
    action: str
    reason: str

    observed_value: float
    threshold: float


class DetectionEngine:

    def __init__(self):
        self.detectors = []

    def register_detector(self, detector):
        self.detectors.append(detector)

    def process_traffic(self, traffic):

        results = []

        for detector in self.detectors:

            result = detector.evaluate(traffic)

            if result is not None:
                if isinstance(result, list):
                    results.extend(result)
                else:
                    results.append(result)

        return results

    def finalize_windows(self, current_time):

        results = []

        for detector in self.detectors:

            finalize = getattr(detector, "finalize_windows", None)

            if finalize is not None:
                detector_results = finalize(current_time)

                if detector_results:
                    results.extend(detector_results)

        return results

