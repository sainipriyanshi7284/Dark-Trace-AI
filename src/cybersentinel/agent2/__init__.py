"""Agent 2 package: Intelligent Anomaly Detection for CyberSentinel.

Re-exports and adapts AnomalyAgent2 from dark_trace for CyberSentinel pipelines.
"""

from dark_trace.agent2.agent import AnomalyAgent2
from dark_trace.agent2.agent3_contract import format_agent2_for_agent3
from dark_trace.agent2.batch import BatchAnomalyProcessor, BatchProcessingResult
from dark_trace.agent2.model import IsolationForestModel
from dark_trace.agent2.trainer import ModelTrainer, TrainedAnomalyModel
from dark_trace.common.schemas import Agent2Evidence, NetworkFlow

from cybersentinel.agent2.adapter import adapt_agent2_evidence_to_assessment
from cybersentinel.agent3.schemas import Agent2AnomalyAssessment

__all__ = [
    "AnomalyAgent2",
    "format_agent2_for_agent3",
    "BatchAnomalyProcessor",
    "BatchProcessingResult",
    "IsolationForestModel",
    "ModelTrainer",
    "TrainedAnomalyModel",
    "Agent2Evidence",
    "NetworkFlow",
    "adapt_agent2_evidence_to_assessment",
    "Agent2AnomalyAssessment",
]

