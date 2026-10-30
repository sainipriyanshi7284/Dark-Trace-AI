"""Custom exceptions for CyberSentinel Agent 4 (Policy Engine)."""

from __future__ import annotations


class Agent4Error(Exception):
    """Base exception for all Agent 4 Policy Engine errors."""
    pass


class PolicyInputError(Agent4Error):
    """Base exception for invalid or unparseable policy input payloads."""
    pass


class MissingAssessmentError(PolicyInputError):
    """Raised when an assessment input is required but absent (None)."""
    pass


class InvalidJsonError(PolicyInputError):
    """Raised when an assessment string cannot be parsed as valid JSON."""
    pass


class InvalidAssessmentError(PolicyInputError):
    """Raised when an assessment structure is missing required fields or has invalid types."""
    pass


class PolicyConfigurationError(Agent4Error):
    """Raised when policy engine configuration parameters are invalid."""
    pass


class PolicyExecutionError(Agent4Error):
    """Raised when policy evaluation encounters an unexpected runtime error."""
    pass

