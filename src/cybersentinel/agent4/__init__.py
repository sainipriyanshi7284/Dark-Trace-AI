"""Agent 4: Adaptive Policy Engine for CyberSentinel.

Translates multi-agent threat assessments and fusion scores into calibrated,
explainable, and simulated enforcement decisions (ALLOW, ALERT, REVIEW, BLOCK).
Includes Policy What-If Simulator, Response Impact Analysis, and end-to-end Pipeline.
"""

from cybersentinel.agent4.adaptive_policy import (
    AdaptivePolicyEngine,
    evaluate_adaptive_policy,
)
from cybersentinel.agent4.audit_log import DEFAULT_AUDIT_LOG_PATH, PolicyAuditLogger
from cybersentinel.agent4.contract import (
    PolicyAction,
    PolicyDecision,
    PolicyProfile,
    ValidatedThreatAssessment,
    parse_assessment_input,
)
from cybersentinel.agent4.exceptions import (
    Agent4Error,
    AuditLogError,
    AuditLogReadError,
    AuditLogWriteError,
    InvalidAssessmentError,
    InvalidJsonError,
    InvalidProfileError,
    MissingAssessmentError,
    PolicyConfigurationError,
    PolicyExecutionError,
    PolicyInputError,
    SimulationError,
)
from cybersentinel.agent4.pipeline import (
    CyberSentinelPipeline,
    EnforcementResult,
    process_and_enforce_flow,
)
from cybersentinel.agent4.policy_config import PolicyConfig
from cybersentinel.agent4.policy_engine import PolicyEngine, evaluate_policy
from cybersentinel.agent4.policy_simulator import (
    FlowSimulationRecord,
    PolicySimulator,
    ProfileMetrics,
    ResponseImpactMetrics,
    SecurityEvaluationMetrics,
    SimulationResult,
    calculate_security_metrics,
    is_malicious_label,
    simulate_policy,
)

__all__ = [
    # Contracts & Enums
    "PolicyAction",
    "PolicyProfile",
    "PolicyDecision",
    "ValidatedThreatAssessment",
    "parse_assessment_input",
    # Configuration
    "PolicyConfig",
    # Engines & Functions
    "PolicyEngine",
    "evaluate_policy",
    "AdaptivePolicyEngine",
    "evaluate_adaptive_policy",
    # Audit Logging
    "PolicyAuditLogger",
    "DEFAULT_AUDIT_LOG_PATH",
    # What-If Simulator & Impact Analysis
    "PolicySimulator",
    "simulate_policy",
    "calculate_security_metrics",
    "is_malicious_label",
    "ProfileMetrics",
    "SecurityEvaluationMetrics",
    "ResponseImpactMetrics",
    "FlowSimulationRecord",
    "SimulationResult",
    # Pipeline & Integration
    "CyberSentinelPipeline",
    "EnforcementResult",
    "process_and_enforce_flow",
    # Exceptions
    "Agent4Error",
    "PolicyInputError",
    "MissingAssessmentError",
    "InvalidJsonError",
    "InvalidAssessmentError",
    "PolicyConfigurationError",
    "PolicyExecutionError",
    "InvalidProfileError",
    "AuditLogError",
    "AuditLogWriteError",
    "AuditLogReadError",
    "SimulationError",
]
