
from controller.detection_engine import TrafficRecord
from controller.syn_detector import SynRateDetector


detector = SynRateDetector(
    threshold=5,
    window_seconds=10,
    severity_multipliers={
        "medium": 1.5,
        "high": 2.5
    }
)

for i in range(1, 9):

    traffic = TrafficRecord(
        timestamp=float(i),
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        protocol="TCP",
        src_port=40000 + i,
        dst_port=80,
        tcp_syn=True
    )

    result = detector.evaluate(traffic)

    if result:
        print(result)

