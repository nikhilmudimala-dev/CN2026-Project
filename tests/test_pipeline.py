
import time
from types import SimpleNamespace

from controller.pipeline import DetectionPipeline
from controller.detection_engine import TrafficRecord


class MockParser:

    def OFPMatch(self, **kwargs):
        return kwargs

    def OFPFlowMod(self, **kwargs):
        return kwargs


class MockDatapath:

    def __init__(self, datapath_id):
        self.id = datapath_id

        self.ofproto = SimpleNamespace(
            OFPFC_ADD=0,
            OFPFF_SEND_FLOW_REM=1
        )

        self.ofproto_parser = MockParser()
        self.sent_messages = []

    def send_msg(self, message):
        self.sent_messages.append(message)


def test_detection_pipeline(tmp_path):

    pipeline = DetectionPipeline(
        database_path=str(
            tmp_path / "test_pipeline_integration.db"
        )
    )

    switch1 = MockDatapath(1)
    switch2 = MockDatapath(2)

    datapaths = [switch1, switch2]

    current_time = time.time()

    # TEST 1: R3 should generate an alert, not a block.

    results = []

    for port in range(1, 10):

        traffic = TrafficRecord(
            timestamp=current_time + port * 0.01,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.100",
            protocol="TCP",
            src_port=40000 + port,
            dst_port=port,
            tcp_syn=True
        )

        results.extend(
            pipeline.process_traffic(traffic, datapaths)
        )

    assert len(results) == 1
    assert results[0]["detection"].rule_id == "R3_PORT_SCAN"
    assert results[0]["detection"].action == "FLAG"
    assert results[0]["blocking_result"] is None

    assert not pipeline.blocking_manager.is_blocked("10.0.0.1")
    assert len(switch1.sent_messages) == 0
    assert len(switch2.sent_messages) == 0

    # TEST 2: R1 should block a host.

    results = []

    for count in range(21):

        traffic = TrafficRecord(
            timestamp=current_time + 1 + count * 0.01,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.100",
            protocol="TCP",
            src_port=50000 + count,
            dst_port=80,
            tcp_syn=True
        )

        results.extend(
            pipeline.process_traffic(traffic, datapaths)
        )

    assert len(results) == 1
    assert results[0]["detection"].rule_id == "R1_SYN_RATE"
    assert results[0]["detection"].action == "BLOCK"

    blocking_result = results[0]["blocking_result"]

    assert blocking_result["event"] == "HOST_BLOCKED"
    assert pipeline.blocking_manager.is_blocked("10.0.0.2")

    assert len(switch1.sent_messages) == 1
    assert len(switch2.sent_messages) == 1

    # TEST 3: Verify event logging.

    events = pipeline.event_manager.get_events()

    event_types = [
        event["event_type"] for event in events
    ]

    assert "DETECTION" in event_types
    assert "ALERT" in event_types
    assert "BLOCKING_RESULT" in event_types

