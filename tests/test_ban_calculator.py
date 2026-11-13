

from controller.ban_calculator import BanCalculator


calculator = BanCalculator(
    base_durations={
        "low": 30,
        "medium": 120,
        "high": 300
    },
    escalation_factor=0.5,
    maximum_seconds=1800
)


test_cases = [
    ("LOW", 1),
    ("LOW", 2),
    ("LOW", 3),
    ("MEDIUM", 1),
    ("MEDIUM", 2),
    ("HIGH", 1),
    ("HIGH", 5),
    ("HIGH", 20)
]


for severity, offences in test_cases:

    duration = calculator.calculate(
        severity,
        offences
    )

    print(
        f"Severity: {severity}, "
        f"Offences: {offences}, "
        f"Ban duration: {duration} seconds"
    )
