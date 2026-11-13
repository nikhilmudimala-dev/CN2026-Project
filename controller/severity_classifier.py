
class SeverityClassifier:

    def __init__(self, multipliers):
        self.multipliers = multipliers

    def classify(self, observed_value, threshold):

        if threshold <= 0:
            raise ValueError("Threshold must be greater than zero")

        ratio = observed_value / threshold

        if ratio >= self.multipliers["high"]:
            return "HIGH"

        elif ratio >= self.multipliers["medium"]:
            return "MEDIUM"

        return "LOW"
