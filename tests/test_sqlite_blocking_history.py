
import os
import tempfile

from controller.blocking_manager import BlockingManager
from controller.offender_manager import OffenderManager
from controller.ban_calculator import BanCalculator
from controller.detection_engine import DetectionResult
from database.database import Database


class FakeParser:

    def OFPMatch(self, **kwargs):
        return kwargs

    def OFPFlowMod(self, **kwargs):
        return kwargs


class FakeOfproto:

    OFPFC_ADD = 0
    OFPFF_SEND_FLOW_REM = 1


class FakeDatapath:

    def __init__(self):
        self.id = 1
        self.ofproto = FakeOfproto()
        self.ofproto_parser = FakeParser()
        self.messages = []

    def send_msg(self, message):
        self.messages.append(message)


def create_detection(rule_id):
    return DetectionResult(
        rule_id=rule_id,
        source_ip="10.0.0.1",
        severity="LOW",
        action="BLOCK",
        reason="SQLite integration test",
        observed_value=25,
        threshold=20
    )


def test_sqlite_preserves_shared_history():

    with tempfile.TemporaryDirectory() as temp_dir:

        db_path = os.path.join(
            temp_dir,
            "test_blocking.db"
        )

        database = Database(db_path=db_path)

        offender_manager = OffenderManager(
            history_window_seconds=3600
        )

        ban_calculator = BanCalculator(
            base_durations={
                "low": 30,
                "medium": 120,
                "high": 300
            },
            escalation_factor=0.5,
            maximum_seconds=1800
        )

        blocking_manager = BlockingManager(
            offender_manager=offender_manager,
            ban_calculator=ban_calculator,
            database=database
        )

        datapath = FakeDatapath()

        # First incident: R1
        first = blocking_manager.block_host(
            create_detection("R1_SYN_RATE"),
            [datapath],
            100
        )

        assert first["offence_count"] == 1
        assert first["duration_seconds"] == 30

        # Simulate the first ban expiring.
        database.remove_active_ban("10.0.0.1")
        blocking_manager.active_bans.clear()

        # Second incident: R2, same host.
        second = blocking_manager.block_host(
            create_detection("R2_CONNECTION_BURST"),
            [datapath],
            200
        )

        assert second["offence_count"] == 2
        assert second["duration_seconds"] == 45

        history = database.get_blocking_history("10.0.0.1")

        assert len(history) == 2

        rules = {
            incident["rule_id"]
            for incident in history
        }

        assert "R1_SYN_RATE" in rules
        assert "R2_CONNECTION_BURST" in rules

        print("PASS: test_sqlite_preserves_shared_history")


if __name__ == "__main__":
    test_sqlite_preserves_shared_history()
    print("\nAll SQLite blocking history tests passed.")

