"""Agent 4: Temporal Correlation Agent package for CyberSentinel.

Provides:
  - TemporalCorrelationAgent
  - TemporalGroup
  - TemporalCorrelationConfig
  - TemporalCorrelationResult
  - parse_timestamp_to_epoch
"""

from cybersentinel.temporal_agent.agent import (
    TemporalCorrelationAgent,
    parse_timestamp_to_epoch,
)
from cybersentinel.temporal_agent.contract import (
    TemporalCorrelationConfig,
    TemporalCorrelationResult,
    TemporalGroup,
)

__all__ = [
    "TemporalCorrelationAgent",
    "TemporalGroup",
    "TemporalCorrelationConfig",
    "TemporalCorrelationResult",
    "parse_timestamp_to_epoch",
]

