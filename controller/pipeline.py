
from controller.config_loader import ConfigLoader

from controller.detection_engine import DetectionEngine
from controller.syn_detector import SynRateDetector
from controller.connection_detector import ConnectionBurstDetector
from controller.port_scan_detector import PortScanDetector

from controller.event_manager import EventManager
from controller.offender_manager import OffenderManager
from controller.ban_calculator import BanCalculator
from controller.blocking_manager import BlockingManager

from database.database import Database


class DetectionPipeline:

    def __init__(
        self,
        config_path="config/rules.json",
        database_path="database/sdn_blocking.db"
    ):

        self.config = ConfigLoader(config_path).load()

        rules = self.config["rules"]
        multipliers = self.config["severity_multipliers"]
        policy = self.config["ban_policy"]

        self.database = Database(database_path)
        self.event_manager = EventManager(database=self.database)

        self.detection_engine = DetectionEngine()

        if rules["syn_rate"]["enabled"]:
            settings = rules["syn_rate"]

            self.detection_engine.register_detector(
                SynRateDetector(
                    threshold=settings["threshold"],
                    window_seconds=settings["window_seconds"],
                    severity_multipliers=multipliers
                )
            )

        if rules["connection_burst"]["enabled"]:
            settings = rules["connection_burst"]

            self.detection_engine.register_detector(
                ConnectionBurstDetector(
                    threshold=settings["threshold"],
                    window_seconds=settings["window_seconds"],
                    severity_multipliers=multipliers,
                    handshake_timeout=settings["handshake_timeout"]
                )
            )

        if rules["port_scan"]["enabled"]:
            settings = rules["port_scan"]

            self.detection_engine.register_detector(
                PortScanDetector(
                    threshold=settings["threshold"],
                    window_seconds=settings["window_seconds"],
                    severity_multipliers=multipliers
                )
            )

        self.offender_manager = OffenderManager(
            history_window_seconds=policy["history_window_seconds"]
        )

        self.ban_calculator = BanCalculator(
            base_durations=policy["base_duration"],
            escalation_factor=policy["escalation_factor"],
            maximum_seconds=policy["maximum_seconds"]
        )

        self.blocking_manager = BlockingManager(
            offender_manager=self.offender_manager,
            ban_calculator=self.ban_calculator,
            database=self.database
        )

    def process_traffic(self, traffic, datapaths):

        detections = self.detection_engine.process_traffic(traffic)

        return self._process_detections(
            detections,
            datapaths,
            traffic.timestamp
        )

    def finalize_windows(self, current_time, datapaths):

        detections = self.detection_engine.finalize_windows(
            current_time
        )

        return self._process_detections(
            detections,
            datapaths,
            current_time
        )

    def _process_detections(self, detections, datapaths, timestamp):

        results = []

        for detection in detections:

            self.event_manager.publish(
                event_type="DETECTION",
                source_ip=detection.source_ip,
                rule_id=detection.rule_id,
                severity=detection.severity,
                message=detection.reason,
                details={
                    "observed_value": detection.observed_value,
                    "threshold": detection.threshold,
                    "action": detection.action
                }
            )

            if detection.action == "BLOCK":

                blocking_result = self.blocking_manager.block_host(
                    detection,
                    datapaths,
                    timestamp
                )

                self.event_manager.publish(
                    event_type="BLOCKING_RESULT",
                    source_ip=detection.source_ip,
                    rule_id=detection.rule_id,
                    severity=detection.severity,
                    message="Blocking manager processed detection",
                    details={
                        "result": str(blocking_result)
                    }
                )

                results.append({
                    "detection": detection,
                    "blocking_result": blocking_result
                })

            elif detection.action == "FLAG":

                self.event_manager.publish(
                    event_type="ALERT",
                    source_ip=detection.source_ip,
                    rule_id=detection.rule_id,
                    severity=detection.severity,
                    message=detection.reason,
                    details={
                        "action": "FLAG",
                        "blocking_performed": False
                    }
                )

                results.append({
                    "detection": detection,
                    "blocking_result": None
                })

        return results

