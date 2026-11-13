import json
from pathlib import Path


class ConfigLoader:

    def __init__(self, config_path="config/rules.json"):
        self.config_path = Path(config_path)

    def load(self):

        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Configuration file not found: {self.config_path}"
            )

        with self.config_path.open("r", encoding="utf-8") as file:
            config = json.load(file)

        self._validate(config)

        return config

    def _validate(self, config):

        required_sections = [
            "severity_multipliers",
            "ban_policy",
            "rules"
        ]

        for section in required_sections:
            if section not in config:
                raise ValueError(
                    f"Missing configuration section: {section}"
                )

        multipliers = config["severity_multipliers"]

        if (
            multipliers["medium"] <= 0
            or multipliers["high"] <= multipliers["medium"]
        ):
            raise ValueError("Invalid severity multipliers")

        policy = config["ban_policy"]

        if policy["history_window_seconds"] <= 0:
            raise ValueError("History window must be positive")

        if policy["escalation_factor"] < 0:
            raise ValueError("Escalation factor cannot be negative")

        if policy["maximum_seconds"] <= 0:
            raise ValueError("Maximum ban duration must be positive")

        for severity in ("low", "medium", "high"):
            if policy["base_duration"][severity] <= 0:
                raise ValueError(
                    f"Invalid base duration for {severity}"
                )

        expected_rules = {
            "syn_rate": "block",
            "connection_burst": "block",
            "port_scan": "flag"
        }

        for rule_name, expected_action in expected_rules.items():

            if rule_name not in config["rules"]:
                raise ValueError(
                    f"Missing rule configuration: {rule_name}"
                )

            rule = config["rules"][rule_name]

            if rule["action"] != expected_action:
                raise ValueError(
                    f"{rule_name} must use action '{expected_action}'"
                )

            if rule["threshold"] <= 0:
                raise ValueError(
                    f"{rule_name} threshold must be positive"
                )

            if rule["window_seconds"] <= 0:
                raise ValueError(
                    f"{rule_name} window must be positive"
                )

        connection_rule = config["rules"]["connection_burst"]

        if connection_rule["handshake_timeout"] <= 0:
            raise ValueError("Handshake timeout must be positive")
