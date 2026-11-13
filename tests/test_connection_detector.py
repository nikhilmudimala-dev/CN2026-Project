
from controller.connection_detector import ConnectionBurstDetector
from controller.detection_engine import TrafficRecord


def make_packet(
    timestamp,
    src_ip="10.0.0.1",
    dst_ip="10.0.0.5",
    src_port=40000,
    dst_port=8000,
    syn=False,
    ack=False,
    fin=False,
    rst=False
):
    return TrafficRecord(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol="TCP",
        src_port=src_port,
        dst_port=dst_port,
        tcp_syn=syn,
        tcp_ack=ack,
        tcp_fin=fin,
        tcp_rst=rst
    )


def create_detector(threshold=10, timeout=30):
    return ConnectionBurstDetector(
        threshold=threshold,
        window_seconds=30,
        severity_multipliers={
            "medium": 1.5,
            "high": 2.5
        },
        handshake_timeout=timeout
    )


def complete_handshake(detector, start, port):
    detector.evaluate(
        make_packet(start, src_port=port, syn=True)
    )

    detector.evaluate(
        make_packet(
            start + 0.1,
            src_ip="10.0.0.5",
            dst_ip="10.0.0.1",
            src_port=8000,
            dst_port=port,
            syn=True,
            ack=True
        )
    )

    return detector.evaluate(
        make_packet(
            start + 0.2,
            src_port=port,
            ack=True
        )
    )


def test_retransmissions_count_once():
    detector = create_detector()

    detector.evaluate(make_packet(1, syn=True))

    # Duplicate SYN
    detector.evaluate(make_packet(1.1, syn=True))

    # SYN-ACK and its retransmission
    detector.evaluate(
        make_packet(
            1.2,
            src_ip="10.0.0.5",
            dst_ip="10.0.0.1",
            src_port=8000,
            dst_port=40000,
            syn=True,
            ack=True
        )
    )

    detector.evaluate(
        make_packet(
            1.3,
            src_ip="10.0.0.5",
            dst_ip="10.0.0.1",
            src_port=8000,
            dst_port=40000,
            syn=True,
            ack=True
        )
    )

    detector.evaluate(make_packet(1.4, ack=True))

    # Duplicate final ACK
    detector.evaluate(make_packet(1.5, ack=True))

    assert len(detector.connection_history["10.0.0.1"]) == 1


def test_incomplete_handshake_expires():
    detector = create_detector(timeout=5)

    detector.evaluate(make_packet(1, syn=True))

    # Trigger timeout cleanup with another packet
    detector.evaluate(
        make_packet(7, src_port=40001, syn=True)
    )

    assert (
        "10.0.0.1", 40000, "10.0.0.5", 8000
    ) not in detector.pending


def test_rst_clears_pending_handshake():
    detector = create_detector()

    detector.evaluate(make_packet(1, syn=True))

    detector.evaluate(
        make_packet(2, rst=True)
    )

    assert not detector.pending


def test_threshold_triggers_at_exact_count():
    detector = create_detector(threshold=2)

    first = complete_handshake(detector, 1, 40000)
    second = complete_handshake(detector, 2, 40001)

    assert first is None
    assert second is not None
    assert second.rule_id == "R2_CONNECTION_BURST"
    assert second.observed_value == 2
    
def test_rolling_window_removes_old_connections():
    detector = create_detector(threshold=3)

    complete_handshake(detector, 1, 40000)
    complete_handshake(detector, 2, 40001)

    history = detector.connection_history["10.0.0.1"]
    assert len(history) == 2

    # A new connection after the 30-second window
    complete_handshake(detector, 40, 40002)

    assert len(history) == 1
    assert list(history) == [40.2]

def test_incident_rearming():
    detector = create_detector(threshold=2)

    first = complete_handshake(detector, 1, 40000)
    second = complete_handshake(detector, 2, 40001)

    assert first is None
    assert second is not None

    # Let the previous connections leave the rolling window.
    third = complete_handshake(detector, 40, 40002)
    assert third is None

    fourth = complete_handshake(detector, 41, 40003)
    assert fourth is not None
    assert fourth.rule_id == "R2_CONNECTION_BURST"

    print("PASS: test_incident_rearming")
    
def run_tests():
    tests = [
        test_retransmissions_count_once,
        test_incomplete_handshake_expires,
        test_rst_clears_pending_handshake,
        test_threshold_triggers_at_exact_count,
        test_rolling_window_removes_old_connections,
        test_incident_rearming
    ]

    for test in tests:
        test()
        print("PASS:", test.__name__)

    print("\nAll R2 detector tests passed.")


if __name__ == "__main__":
    run_tests()

