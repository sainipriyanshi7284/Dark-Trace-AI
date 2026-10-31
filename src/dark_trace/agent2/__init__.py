"""Agent 2: Network Anomaly Detection.

This package provides unsupervised statistical network anomaly detection for the
Dark-Trace-AI platform using a calibrated 74-feature Isolation Forest model.
"""

from dark_trace.agent2.agent import Agent2, AnomalyAgent2
from dark_trace.agent2.agent3_contract import create_agent3_composite_handover, format_agent2_for_agent3
from dark_trace.agent2.batch import BatchAnomalyProcessor, BatchProcessingResult
from dark_trace.agent2.config import Agent2Config
from dark_trace.agent2.model import (
    AnomalyDetectorInterface,
    IsolationForestDetector,
    IsolationForestModel,
)
from dark_trace.agent2.schemas import (
    Agent2Evidence,
    AnomalyScore,
    FeatureContribution,
    NetworkFlowInput,
    create_disabled_threat_intel_payload,
)
from dark_trace.agent2.trainer import ModelTrainer, TrainedAnomalyModel

__all__ = [
    "Agent2",
    "AnomalyAgent2",
    "Agent2Config",
    "AnomalyDetectorInterface",
    "IsolationForestDetector",
    "IsolationForestModel",
    "NetworkFlowInput",
    "Agent2Evidence",
    "AnomalyScore",
    "FeatureContribution",
    "create_disabled_threat_intel_payload",
    "format_agent2_for_agent3",
    "create_agent3_composite_handover",
    "BatchAnomalyProcessor",
    "BatchProcessingResult",
    "ModelTrainer",
    "TrainedAnomalyModel",
]
