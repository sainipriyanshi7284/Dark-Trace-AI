"""Data contracts and schemas for the CyberSentinel central orchestration pipeline.

Defines the consolidated output representations and batch aggregation models
ensuring JSON-serializability, flow ID preservation, and evidence retention.
"""

from dataclasses import asdict, dataclass, field
import json
from typing import Any, Dict, List, Optional


@dataclass
class FlowProcessingResult:
    """Consolidated end-to-end outcome for a single network flow across all 5 modules.

    Attributes:
        flow_id: Identifier of the processed network flow (preserved throughout).
        data_quality_report: Structured report emitted by DataQualityMonitor.
        agent1_result: Classification output from Agent 1 (Threat Classifier).
        agent2_result: Anomaly output from Agent 2 (Behavioral Anomaly & Threat Intel).
        agent3_assessment: Correlated evidence assessment from Agent 3 (Evidence Fusion).
        agent4_policy_decision: Final policy action and rationale from Agent 4 (Policy Engine).
        final_status: High-level operational processing status.
        action: Final policy decision (ALLOW, ALERT, REVIEW, BLOCK - simulated).
        processing_errors: Diagnostics and error messages recorded during pipeline execution.
        metadata: Original routing and transport metadata (IPs, ports, protocols, timestamps).
    """

    flow_id: str
    data_quality_report: Dict[str, Any]
    agent1_result: Optional[Dict[str, Any]] = None
    agent2_result: Optional[Dict[str, Any]] = None
    agent3_assessment: Optional[Dict[str, Any]] = None
    agent4_policy_decision: Optional[Dict[str, Any]] = None
    final_status: str = "SUCCESS"
    action: str = "REVIEW"
    processing_errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to clean, fully JSON-serializable dictionary."""
        def _sanitize(val: Any) -> Any:
            if hasattr(val, "to_dict") and callable(val.to_dict):
                return _sanitize(val.to_dict())
            if hasattr(val, "value"):
                return val.value
            if isinstance(val, dict):
                return {k: _sanitize(v) for k, v in val.items()}
            if isinstance(val, (list, tuple, set)):
                return [_sanitize(v) for v in val]
            return val

        return {
            "flow_id": str(self.flow_id),
            "data_quality_report": _sanitize(self.data_quality_report),
            "agent1_result": _sanitize(self.agent1_result) if self.agent1_result else None,
            "agent2_result": _sanitize(self.agent2_result) if self.agent2_result else None,
            "agent3_assessment": _sanitize(self.agent3_assessment) if self.agent3_assessment else None,
            "agent4_policy_decision": _sanitize(self.agent4_policy_decision) if self.agent4_policy_decision else None,
            "final_status": str(self.final_status),
            "action": str(self.action),
            "processing_errors": list(self.processing_errors),
            "metadata": _sanitize(self.metadata),
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize result to formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)


@dataclass
class BatchProcessingSummary:
    """Aggregated batch execution statistics and individual flow outcomes."""

    total_flows: int = 0
    allow_count: int = 0
    alert_count: int = 0
    review_count: int = 0
    block_count: int = 0
    error_count: int = 0
    quality_critical_count: int = 0
    quality_warning_count: int = 0
    results: List[FlowProcessingResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize batch summary to dictionary."""
        return {
            "summary": {
                "total_flows": self.total_flows,
                "allow_count": self.allow_count,
                "alert_count": self.alert_count,
                "review_count": self.review_count,
                "block_count": self.block_count,
                "error_count": self.error_count,
                "quality_critical_count": self.quality_critical_count,
                "quality_warning_count": self.quality_warning_count,
            },
            "results": [r.to_dict() for r in self.results],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize batch summary to formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

