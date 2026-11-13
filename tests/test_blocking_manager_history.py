
from controller.blocking_manager import BlockingManager
from controller.offender_manager import OffenderManager
from controller.ban_calculator import BanCalculator
from controller.detection_engine import DetectionResult


class FakeDatabase:

    def __init__(self):
        self.incidents = []
        self.active_bans = {}

    def get_active_bans(self):
        return list(self.active_bans.values())

    def count_recent_incidents(self, source_ip, current_time, window):
        cutoff = current_time - window

        return sum(
            1 for incident in self.incidents
            if incident["source_ip"] == source_ip
            and incident["timestamp"] >= cutoff
        )

    def insert_blocking_incident(self, incident):
        self.incidents.append(incident)

    def insert_active_ban(self, ban):
        self.active_bans[ban["source_ip"]] = ban

    def remove_active_ban(self, source_ip):
        self.active_bans.pop(source_ip, None)


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
        reason="Test detection",
        observed_value=25,
        threshold=20
    )


def test_r1_then_r2_share_database_history():

    database = FakeDatabase()

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

    # Simulate expiry of the first ban.
    database.remove_active_ban("10.0.0.1")
    blocking_manager.active_bans.clear()

    # Second incident: R2, same source IP.
    second = blocking_manager.block_host(
        create_detection("R2_CONNECTION_BURST"),
        [datapath],
        200
    )

    assert second["offence_count"] == 2
    assert second["duration_seconds"] == 45

    assert len(database.incidents) == 2
    assert database.incidents[0]["rule_id"] == "R1_SYN_RATE"
    assert database.incidents[1]["rule_id"] == "R2_CONNECTION_BURST"

    print("PASS: test_r1_then_r2_share_database_history")


def run_tests():
    tests = [
        test_r1_then_r2_share_database_history
    ]

    for test in tests:
        test()

    print("\nAll blocking manager history tests passed.")


if __name__ == "__main__":
    run_tests()
