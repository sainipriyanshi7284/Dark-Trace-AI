"""CyberSentinel: Autonomous Multi-Agent Network Intrusion Detection & Response System."""

from cybersentinel.orchestration.pipeline import CyberSentinelPipeline
from cybersentinel.orchestration.contracts import FlowProcessingResult, BatchProcessingSummary

__version__ = "0.1.0"

__all__ = [
    "CyberSentinelPipeline",
    "FlowProcessingResult",
    "BatchProcessingSummary",
]
