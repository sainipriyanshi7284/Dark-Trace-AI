"""Agent 4: Temporal Correlation Agent for CyberSentinel.

Preserves compatibility with existing Agent 4 temporal imports by re-exporting
the canonical implementation from cybersentinel.temporal_agent.
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
