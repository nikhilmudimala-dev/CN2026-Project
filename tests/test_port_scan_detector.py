
from controller.port_scan_detector import PortScanDetector
from controller.detection_engine import TrafficRecord


def make_packet(
    timestamp,
    dst_port,
    src_ip="10.0.0.1",
    dst_ip="10.0.0.5",
    protocol="TCP",
    syn=True,
    ack=False
):
    return TrafficRecord(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=40000,
        dst_port=dst_port,
        tcp_syn=syn,
        tcp_ack=ack
    )


def create_detector(threshold=8, window=10):
    return PortScanDetector(
        threshold=threshold,
        window_seconds=window,
        severity_multipliers={
            "medium": 1.5,
            "high": 2.5
        }
    )


def test_exact_threshold_does_not_trigger():
    detector = create_detector(threshold=3)

    for port in [80, 443, 8080]:
        result = detector.evaluate(
            make_packet(port, port)
        )
        assert result is None

    print("PASS: test_exact_threshold_does_not_trigger")


def test_threshold_exceeded_triggers():
    detector = create_detector(threshold=3)

    result = None

    for index, port in enumerate([80, 443, 8080, 22]):
        result = detector.evaluate(
            make_packet(index, port)
        )

    assert result is not None
    assert result.rule_id == "R3_PORT_SCAN"
    assert result.action == "FLAG"
    assert result.observed_value == 4

    print("PASS: test_threshold_exceeded_triggers")


def test_duplicate_ports_count_once():
    detector = create_detector(threshold=2)

    for index in range(5):
        result = detector.evaluate(
            make_packet(index, 80)
        )
        assert result is None

    assert len(detector.port_history[
        ("10.0.0.1", "10.0.0.5")
    ]) == 5

    print("PASS: test_duplicate_ports_count_once")


def test_different_destination_ports_trigger():
    detector = create_detector(threshold=2)

    detector.evaluate(make_packet(1, 80))
    detector.evaluate(make_packet(2, 443))

    result = detector.evaluate(make_packet(3, 22))

    assert result is not None
    assert result.observed_value == 3

    print("PASS: test_different_destination_ports_trigger")


def test_different_destinations_are_tracked_separately():
    detector = create_detector(threshold=2)

    detector.evaluate(
        make_packet(1, 80, dst_ip="10.0.0.5")
    )
    detector.evaluate(
        make_packet(2, 443, dst_ip="10.0.0.6")
    )

    result = detector.evaluate(
        make_packet(3, 22, dst_ip="10.0.0.5")
    )

    assert result is None

    print("PASS: test_different_destinations_are_tracked_separately")


def test_non_tcp_and_non_initial_syn_are_ignored():
    detector = create_detector(threshold=1)

    non_tcp = detector.evaluate(
        make_packet(1, 80, protocol="UDP")
    )

    syn_ack = detector.evaluate(
        make_packet(2, 443, syn=True, ack=True)
    )

    assert non_tcp is None
    assert syn_ack is None

    print("PASS: test_non_tcp_and_non_initial_syn_are_ignored")


def test_rolling_window_removes_old_ports():
    detector = create_detector(
        threshold=2,
        window=10
    )

    detector.evaluate(make_packet(1, 80))
    detector.evaluate(make_packet(2, 443))

    history = detector.port_history[
        ("10.0.0.1", "10.0.0.5")
    ]

    assert len(history) == 2

    detector.evaluate(make_packet(20, 22))

    assert len(history) == 1
    assert list(history) == [(20, 22)]

    print("PASS: test_rolling_window_removes_old_ports")


def test_incident_rearming():
    detector = create_detector(threshold=2, window=10)

    detector.evaluate(make_packet(1, 80))
    detector.evaluate(make_packet(2, 443))

    first_alert = detector.evaluate(make_packet(3, 22))

    assert first_alert is not None

    # Old ports expire; the active incident should clear.
    detector.evaluate(make_packet(20, 8080))

    # Two more distinct ports exceed the threshold again.
    detector.evaluate(make_packet(21, 3306))
    second_alert = detector.evaluate(make_packet(22, 25))

    assert second_alert is not None
    assert second_alert.rule_id == "R3_PORT_SCAN"
    assert second_alert.action == "FLAG"

    print("PASS: test_incident_rearming")


def run_tests():
    tests = [
        test_exact_threshold_does_not_trigger,
        test_threshold_exceeded_triggers,
        test_duplicate_ports_count_once,
        test_different_destination_ports_trigger,
        test_different_destinations_are_tracked_separately,
        test_non_tcp_and_non_initial_syn_are_ignored,
        test_rolling_window_removes_old_ports,
        test_incident_rearming
    ]

    for test in tests:
        test()

    print("\nAll R3 detector tests passed.")


if __name__ == "__main__":
    run_tests()

