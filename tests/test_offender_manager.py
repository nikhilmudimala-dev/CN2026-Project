
from controller.offender_manager import OffenderManager


def test_r1_and_r2_share_history():
    manager = OffenderManager(history_window_seconds=3600)

    first = manager.register_incident(
        "10.0.0.1", "R1_SYN_RATE", 100
    )

    second = manager.register_incident(
        "10.0.0.1", "R2_CONNECTION_BURST", 200
    )

    assert first == 1
    assert second == 2
    assert manager.get_offence_count("10.0.0.1", 200) == 2

    print("PASS: test_r1_and_r2_share_history")


def test_different_hosts_have_separate_history():
    manager = OffenderManager()

    manager.register_incident(
        "10.0.0.1", "R1_SYN_RATE", 100
    )

    count = manager.get_offence_count("10.0.0.2", 100)

    assert count == 0

    print("PASS: test_different_hosts_have_separate_history")


def test_r3_cannot_register_offence():
    manager = OffenderManager()

    try:
        manager.register_incident(
            "10.0.0.1", "R3_PORT_SCAN", 100
        )
    except ValueError:
        pass
    else:
        raise AssertionError("R3 should not register an offence")

    print("PASS: test_r3_cannot_register_offence")


def test_old_incidents_expire():
    manager = OffenderManager(history_window_seconds=3600)

    manager.register_incident(
        "10.0.0.1", "R1_SYN_RATE", 100
    )

    manager.register_incident(
        "10.0.0.1", "R2_CONNECTION_BURST", 200
    )

    # At 3801, the first incident is outside the history window.
    count = manager.get_offence_count("10.0.0.1", 3801)

    assert count == 0

    print("PASS: test_old_incidents_expire")


def run_tests():
    tests = [
        test_r1_and_r2_share_history,
        test_different_hosts_have_separate_history,
        test_r3_cannot_register_offence,
        test_old_incidents_expire
    ]

    for test in tests:
        test()

    print("\nAll offender manager tests passed.")


if __name__ == "__main__":
    run_tests()

