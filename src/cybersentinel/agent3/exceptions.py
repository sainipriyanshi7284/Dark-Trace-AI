"""Agent 3 custom exceptions."""

from typing import Any


class Agent3Error(Exception):
    """Base exception for all Agent 3 errors."""
    pass


class InvalidInputError(Agent3Error):
    """Raised when the input payload fails structural or semantic validation."""
    pass


class SchemaValidationError(InvalidInputError):
    """Raised when schema validation fails with structured errors."""

    def __init__(self, message: str, validation_result: Any = None) -> None:
        super().__init__(message)
        self.validation_result = validation_result



class MissingAgentError(Agent3Error):
    """Raised when critical agent inputs are absent and strict mode is active."""
    pass


class FusionExecutionError(Agent3Error):
    """Raised when fusion reasoning encounters an unrecoverable failure."""
    pass

