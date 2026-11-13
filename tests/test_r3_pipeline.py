
from controller.pipeline import DetectionPipeline
from controller.detection_engine import DetectionResult


class FakeDetectionEngine:

    def process_traffic(self, traffic):
        return [
            DetectionResult(
                rule_id="R3_PORT_SCAN",
                source_ip="10.0.0.1",
                severity="MEDIUM",
                action="FLAG",
                reason="Port scan suspected",
                observed_value=9,
                threshold=8
            )
        ]


class FakeEventManager:

    def __init__(self):
        self.events = []

    def publish(self, **kwargs):
        self.events.append(kwargs)


class FakeBlockingManager:

    def __init__(self):
        self.calls = 0

    def block_host(self, *args, **kwargs):
        self.calls += 1


def test_r3_only_generates_alert():

    pipeline = DetectionPipeline.__new__(DetectionPipeline)

    pipeline.detection_engine = FakeDetectionEngine()
    pipeline.event_manager = FakeEventManager()
    pipeline.blocking_manager = FakeBlockingManager()

    results = pipeline.process_traffic(
        traffic=None,
        datapaths=[]
    )

    assert len(results) == 1
    assert results[0]["detection"].rule_id == "R3_PORT_SCAN"
    assert results[0]["blocking_result"] is None

    assert pipeline.blocking_manager.calls == 0

    event_types = [
        event["event_type"]
        for event in pipeline.event_manager.events
    ]

    assert "ALERT" in event_types
    assert "BLOCKING_RESULT" not in event_types

    print("PASS: test_r3_only_generates_alert")


if __name__ == "__main__":
    test_r3_only_generates_alert()
    print("\nAll R3 pipeline tests passed.")
