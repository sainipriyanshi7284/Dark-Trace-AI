"""Schemas package defining input/output contracts for CyberSentinel agents."""

from cybersentinel.agent3.contract import (
    A1DetectionResult,
    A2DetectionResult,
    Agent3Input,
    Agent3Output,
    AgentStatus,
    FlowContext,
    FusionStatus,
    RecommendedAction,
    Verdict,
)
from cybersentinel.agent3.schemas import (
    Agent1ThreatPrediction,
    Agent2AnomalyAssessment,
    Agent3FusionInput,
    Agent3ThreatAssessment,
)
from cybersentinel.agent3.validator import (
    A1ThreatClass,
    CANONICAL_A1_CLASSES,
    validate_agent1_output,
    validate_agent2_output,
    validate_fusion_input,
)

__all__ = [
    "A1DetectionResult",
    "A2DetectionResult",
    "Agent3Input",
    "Agent3Output",
    "AgentStatus",
    "FlowContext",
    "FusionStatus",
    "RecommendedAction",
    "Verdict",
    "A1ThreatClass",
    "CANONICAL_A1_CLASSES",
    "Agent1ThreatPrediction",
    "Agent2AnomalyAssessment",
    "Agent3FusionInput",
    "Agent3ThreatAssessment",
    "validate_agent1_output",
    "validate_agent2_output",
    "validate_fusion_input",
]
