from types import SimpleNamespace

from controller.blocking_manager import BlockingManager
from controller.offender_manager import OffenderManager
from controller.ban_calculator import BanCalculator
from controller.detection_engine import DetectionResult


# Mock OpenFlow objects for testing.

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


# Set up the managers.

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

events = []

blocking_manager = BlockingManager(
    offender_manager,
    ban_calculator,
    event_callback=events.append
)


# Simulate two connected switches.

switch1 = MockDatapath(1)
switch2 = MockDatapath(2)

switches = [switch1, switch2]


# Create a detection result.

detection = DetectionResult(
    rule_id="R1_SYN_RATE",
    source_ip="10.0.0.1",
    severity="LOW",
    action="BLOCK",
    reason="Excessive TCP SYN activity",
    observed_value=10,
    threshold=5
)


# TEST 1: First detection should block the host.

print("\nTEST 1: First detection")

result = blocking_manager.block_host(
    detection,
    switches,
    timestamp=1000
)

print("Event:", result["event"])
print("Ban duration:", result["duration_seconds"])
print("Offence count:", result["offence_count"])
print("Switch 1 rules:", len(switch1.sent_messages))
print("Switch 2 rules:", len(switch2.sent_messages))

assert result["event"] == "HOST_BLOCKED"
assert result["duration_seconds"] == 30
assert result["offence_count"] == 1
assert len(switch1.sent_messages) == 1
assert len(switch2.sent_messages) == 1
assert blocking_manager.is_blocked("10.0.0.1")


# TEST 2: Another detection during the ban.

print("\nTEST 2: Detection while already blocked")

result = blocking_manager.block_host(
    detection,
    switches,
    timestamp=1010
)

print("Event:", result["event"])
print("Offence count:", offender_manager.get_offence_count(
    "10.0.0.1", 1010
))

assert result["event"] == "ALREADY_BLOCKED"
assert offender_manager.get_offence_count("10.0.0.1", 1010) == 1


# TEST 3: First switch reports rule removal.

print("\nTEST 3: First switch reports expiry")

cookie = blocking_manager.active_bans["10.0.0.1"]["cookie"]

result = blocking_manager.handle_flow_removed(
    datapath_id=1,
    cookie=cookie
)

print("Result:", result)
print("Still blocked:", blocking_manager.is_blocked("10.0.0.1"))

assert result is None
assert blocking_manager.is_blocked("10.0.0.1")


# TEST 4: Second switch reports rule removal.

print("\nTEST 4: Second switch reports expiry")

result = blocking_manager.handle_flow_removed(
    datapath_id=2,
    cookie=cookie
)

print("Event:", result["event"])
print("Still blocked:", blocking_manager.is_blocked("10.0.0.1"))

assert result["event"] == "BAN_EXPIRED"
assert not blocking_manager.is_blocked("10.0.0.1")


# TEST 5: A new detection after expiry.

print("\nTEST 5: New detection after expiry")

result = blocking_manager.block_host(
    detection,
    switches,
    timestamp=1040
)

print("Event:", result["event"])
print("Offence count:", result["offence_count"])
print("Ban duration:", result["duration_seconds"])

assert result["event"] == "HOST_BLOCKED"
assert result["offence_count"] == 2
assert result["duration_seconds"] == 45


print("\nALL BLOCKING MANAGER TESTS PASSED")
