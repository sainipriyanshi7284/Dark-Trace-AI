"""Agent 4: Adaptive Policy Engine for CyberSentinel.

Translates multi-agent threat assessments and fusion scores into calibrated,
explainable, and simulated enforcement decisions (ALLOW, ALERT, REVIEW, BLOCK).
"""

from cybersentinel.agent4.contract import (
    PolicyAction,
    PolicyDecision,
    PolicyProfile,
    ValidatedThreatAssessment,
    parse_assessment_input,
)
from cybersentinel.agent4.exceptions import (
    Agent4Error,
    InvalidAssessmentError,
    InvalidJsonError,
    MissingAssessmentError,
    PolicyConfigurationError,
    PolicyExecutionError,
    PolicyInputError,
)
from cybersentinel.agent4.policy_config import PolicyConfig
from cybersentinel.agent4.policy_engine import PolicyEngine, evaluate_policy

__all__ = [
    # Contracts & Enums
    "PolicyAction",
    "PolicyProfile",
    "PolicyDecision",
    "ValidatedThreatAssessment",
    "parse_assessment_input",
    # Configuration
    "PolicyConfig",
    # Engine & Functions
    "PolicyEngine",
    "evaluate_policy",
    # Exceptions
    "Agent4Error",
    "PolicyInputError",
    "MissingAssessmentError",
    "InvalidJsonError",
    "InvalidAssessmentError",
    "PolicyConfigurationError",
    "PolicyExecutionError",
]

