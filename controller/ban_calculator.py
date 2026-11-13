class BanCalculator:

    def __init__(
        self,
        base_durations,
        escalation_factor=0.5,
        maximum_seconds=1800
    ):
        self.base_durations = {
            severity.lower(): duration
            for severity, duration in base_durations.items()
        }

        self.escalation_factor = escalation_factor
        self.maximum_seconds = maximum_seconds

    def calculate(self, severity, offence_count):

        severity = severity.lower()

        if severity not in self.base_durations:
            raise ValueError(f"Unknown severity: {severity}")

        if offence_count < 1:
            raise ValueError("Offence count must be at least 1")

        if self.escalation_factor < 0:
            raise ValueError("Escalation factor cannot be negative")

        if self.maximum_seconds <= 0:
            raise ValueError("Maximum duration must be positive")

        base_duration = self.base_durations[severity]

        duration = base_duration * (
            1 + self.escalation_factor * (offence_count - 1)
        )

        return min(
            self.maximum_seconds,
            int(duration)
        )
