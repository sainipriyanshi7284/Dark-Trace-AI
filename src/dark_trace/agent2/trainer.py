"""Agent 2 Training Interface Notice.

In the Dark-Trace-AI architecture, Agent 2 operates with a pre-trained, calibrated
Isolation Forest model artifact (agent2_isolation_forest.joblib) and verified metadata
(agent2_metadata.json) trained on CICIDS2017 baseline data.

Retraining or altering model parameters in production is strictly prohibited by
project architectural boundaries to ensure consistency with the evaluated benchmark
metrics and Agent 3 evidence fusion calibrations.
"""

from typing import Any, Optional


class ModelTrainer:
    """Architectural placeholder enforcing no-retraining rule for Agent 2."""

    def __init__(self, *args, **kwargs):
        pass

    def train(self, *args, **kwargs):
        """Retraining is disallowed."""
        raise NotImplementedError(
            "Agent 2 Isolation Forest model is pre-trained and calibrated. "
            "Retraining is strictly prohibited to preserve benchmark reproducibility."
        )


class TrainedAnomalyModel:
    """Placeholder reference for pre-trained model container."""

    def __init__(self, *args, **kwargs):
        pass
