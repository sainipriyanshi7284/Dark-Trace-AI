"""Agent 3 custom exceptions."""


class Agent3Error(Exception):
    """Base exception for all Agent 3 errors."""
    pass


class InvalidInputError(Agent3Error):
    """Raised when the input payload fails structural or semantic validation."""
    pass


class MissingAgentError(Agent3Error):
    """Raised when critical agent inputs are absent and strict mode is active."""
    pass


class FusionExecutionError(Agent3Error):
    """Raised when fusion reasoning encounters an unrecoverable failure."""
    pass

