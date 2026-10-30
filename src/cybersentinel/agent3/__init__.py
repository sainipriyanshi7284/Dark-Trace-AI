"""Agent 3 package for CyberSentinel (Contextual Fusion, Alert Correlation, and Triage)."""

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
from cybersentinel.agent3.evidence_correlator import (
    CorrelationResult,
    CorrelationScenario,
    EvidenceCorrelator,
    EvidenceStatus,
    InvestigationPriority,
    correlate_evidence,
)
from cybersentinel.agent3.exceptions import (
    Agent3Error,
    FusionExecutionError,
    InvalidInputError,
    MissingAgentError,
    SchemaValidationError,
)
from cybersentinel.agent3.explainer import (
    ExplanationResult,
    ThreatExplainer,
    explain_threat,
)
from cybersentinel.agent3.fusion_scorer import (
    AssessmentVerdict,
    ConfidenceLevel,
    FusionConfig,
    FusionResult,
    FusionScorer,
    RiskLevel,
    compute_fusion_score,
)
from cybersentinel.agent3.schemas import (
    Agent1ThreatPrediction,
    Agent2AnomalyAssessment,
    Agent3FusionInput,
    Agent3ThreatAssessment,
)
from cybersentinel.agent3.skeleton import Agent3Skeleton, process_flow
from cybersentinel.agent3.validator import (
    A1ThreatClass,
    CANONICAL_A1_CLASSES,
    ValidationErrorDetail,
    ValidationResult,
    validate_agent1_output,
    validate_agent2_output,
    validate_fusion_input,
)

__all__ = [
    # Block 1 Base Contracts
    "A1DetectionResult",
    "A2DetectionResult",
    "Agent3Input",
    "Agent3Output",
    "Agent3Skeleton",
    "AgentStatus",
    "FlowContext",
    "FusionStatus",
    "RecommendedAction",
    "Verdict",
    "Agent3Error",
    "InvalidInputError",
    "MissingAgentError",
    "FusionExecutionError",
    # Block 2 Schemas and Validators
    "SchemaValidationError",
    "A1ThreatClass",
    "CANONICAL_A1_CLASSES",
    "Agent1ThreatPrediction",
    "Agent2AnomalyAssessment",
    "Agent3FusionInput",
    "ValidationErrorDetail",
    "ValidationResult",
    "validate_agent1_output",
    "validate_agent2_output",
    "validate_fusion_input",
    # Block 3 Evidence Correlator
    "EvidenceCorrelator",
    "CorrelationResult",
    "CorrelationScenario",
    "EvidenceStatus",
    "InvestigationPriority",
    "correlate_evidence",
    # Block 4 Intelligent Fusion Scorer
    "FusionConfig",
    "FusionResult",
    "FusionScorer",
    "compute_fusion_score",
    "RiskLevel",
    "ConfidenceLevel",
    "AssessmentVerdict",
    # Block 5 & Integration Additions
    "Agent3ThreatAssessment",
    "process_flow",
    "ExplanationResult",
    "ThreatExplainer",
    "explain_threat",
]
