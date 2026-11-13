
from types import SimpleNamespace

from controller.blocking_manager import BlockingManager
from controller.offender_manager import OffenderManager
from controller.ban_calculator import BanCalculator
from controller.detection_engine import DetectionResult
from database.database import Database


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


def test_blocking_database_integration(tmp_path):
    db = Database(
        str(tmp_path / "test_blocking_integration.db")
    )

    offender_manager = OffenderManager(3600)

    ban_calculator = BanCalculator(
        {
            "low": 30,
            "medium": 120,
            "high": 300
        },
        escalation_factor=0.5,
        maximum_seconds=1800
    )

    manager = BlockingManager(
        offender_manager,
        ban_calculator,
        database=db
    )

    switch1 = MockDatapath(1)
    switch2 = MockDatapath(2)

    switches = [switch1, switch2]

    detection = DetectionResult(
        rule_id="R1_SYN_RATE",
        source_ip="10.0.0.5",
        severity="LOW",
        action="BLOCK",
        reason="Excessive TCP SYN activity",
        observed_value=10,
        threshold=5
    )

    result = manager.block_host(
        detection,
        switches,
        timestamp=1000
    )

    assert result["event"] == "HOST_BLOCKED"
    assert result["duration_seconds"] == 30

    history = db.get_blocking_history("10.0.0.5")

    assert len(history) == 1
    assert history[0]["offence_count"] == 1

    saved_bans = db.get_active_bans()

    assert len(saved_bans) == 1
    assert saved_bans[0]["expiry_time"] == 1030

    new_manager = BlockingManager(
        OffenderManager(3600),
        ban_calculator,
        database=db
    )

    assert new_manager.is_blocked("10.0.0.5")

    restored = new_manager.restore_active_bans(
        switches,
        current_time=1010
    )

    assert restored == ["10.0.0.5"]
    assert len(switch1.sent_messages) == 2
    assert len(switch2.sent_messages) == 2

    cookie = new_manager.active_bans["10.0.0.5"]["cookie"]

    new_manager.handle_flow_removed(1, cookie)

    assert new_manager.is_blocked("10.0.0.5")

    new_manager.handle_flow_removed(2, cookie)

    assert not new_manager.is_blocked("10.0.0.5")
    assert len(db.get_active_bans()) == 0

    history = db.get_blocking_history("10.0.0.5")

    assert len(history) == 1

