"""Schema Definitions for Agent 2 (Network Anomaly Detection).

Provides data contracts for:
1. NetworkFlowInput: Input network flow containing metadata and 74 flow features.
2. FeatureContribution: Attribution placeholder for individual features.
3. AnomalyScore: Output schema for calibrated Isolation Forest anomaly inference.
4. Agent2Evidence: Formal evidence payload delivered to Agent 3 for evidence fusion.

ARCHITECTURAL PRINCIPLES:
- Agent 2 operates independently of Agent 1. It never ingests or requires Agent 1's outputs.
- Agent 2 provides objective anomaly evidence; it does NOT make final threat verdicts.
- When the model is unavailable or un-evaluated, is_anomaly is explicitly None
  (never assumed normal/False), and status is set to 'MODEL_NOT_READY' or an explicit error status.
- External threat intelligence (TinyFish) is completely disabled. A standardized
  non-fabricating disabled evidence structure is retained for Agent 3 schema compatibility.
"""

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Union
import time


@dataclass
class NetworkFlowInput:
    """Input schema for a network flow.

    Contains standard network flow routing metadata and a dictionary of
    the 74 numerical features required by the trained Isolation Forest model.
    """

    flow_id: str
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    src_ip: str = "0.0.0.0"
    dst_ip: str = "0.0.0.0"
    src_port: int = 0
    dst_port: int = 0
    protocol: Union[str, int] = "TCP"

    # Mapping of 74 numerical CICIDS2017 flow features
    features: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert network flow input to a dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NetworkFlowInput":
        """Instantiate and sanitize NetworkFlowInput from a dictionary."""
        if not isinstance(data, dict):
            raise ValueError(f"Flow data must be a dictionary, got {type(data).__name__}")
        return cls(
            flow_id=str(data.get("flow_id", "unknown")),
            timestamp=str(data.get("timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))),
            src_ip=str(data.get("src_ip", "0.0.0.0")),
            dst_ip=str(data.get("dst_ip", "0.0.0.0")),
            src_port=int(data.get("src_port", 0)),
            dst_port=int(data.get("dst_port", 0)),
            protocol=data.get("protocol", "TCP"),
            features=dict(data.get("features", {})) if isinstance(data.get("features"), dict) else {},
            metadata=dict(data.get("metadata", {})) if isinstance(data.get("metadata"), dict) else {},
        )


@dataclass
class FeatureContribution:
    """Explaining individual feature influence on the anomaly score."""

    feature_name: str
    feature_value: float
    contribution_score: float
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert feature contribution to dictionary."""
        return asdict(self)


@dataclass
class AnomalyScore:
    """Output schema for Isolation Forest anomaly detection inference.

    CRITICAL SAFETY RULES:
    - Never report is_anomaly=False or True without an actual evaluated model prediction.
    - When the model is unavailable, status is 'MODEL_NOT_READY' and is_anomaly is None.
    - When validation fails or an exception occurs, status reflects the error and is_anomaly is None.
    - Score convention: anomaly_score = -model.score_samples(X). Higher means more anomalous.
    - is_anomaly = True if score >= threshold else False.

    Attributes:
        status: Evaluation status ('EVALUATED', 'MODEL_NOT_READY', 'VALIDATION_ERROR', 'INFERENCE_ERROR').
        is_anomaly: Optional boolean flag; None when model is unavailable or flow un-evaluated.
        raw_score: Raw anomaly score from -model.score_samples(X), or None if un-evaluated.
        normalized_score: Set to None unless a defensible normalization formula is calibrated.
        threshold: Calibrated decision threshold from metadata, or None if uncalibrated.
        model_version: Identifier / metadata string for the loaded model artifact.
        supporting_features: Empty list (Isolation Forest does not provide reliable per-feature explanations).
        inference_latency_ms: Latency of inference in milliseconds, or None if not run.
        error_message: Optional error message if validation or inference failed.
    """

    status: str = "MODEL_NOT_READY"
    is_anomaly: Optional[bool] = None
    raw_score: Optional[float] = None
    normalized_score: Optional[float] = None
    threshold: Optional[float] = None
    model_version: str = "unavailable"
    supporting_features: List[FeatureContribution] = field(default_factory=list)
    inference_latency_ms: Optional[float] = None
    error_message: Optional[str] = None

    @property
    def anomaly_label(self) -> str:
        """Categorical label derived strictly from is_anomaly."""
        if self.is_anomaly is True:
            return "ANOMALOUS"
        elif self.is_anomaly is False:
            return "NORMAL"
        return "UNKNOWN"

    def to_dict(self) -> Dict[str, Any]:
        """Convert anomaly score to dictionary with complete Agent 3 contract compatibility."""
        score_alias = self.normalized_score if self.normalized_score is not None else (
            self.raw_score if self.raw_score is not None else 0.0
        )
        res: Dict[str, Any] = {
            "status": self.status,
            "is_anomaly": self.is_anomaly,
            "anomaly_label": self.anomaly_label,
            "raw_score": self.raw_score,
            "normalized_score": self.normalized_score,
            "anomaly_score": score_alias,  # Agent 3 compatibility alias (finite float or 0.0)
            "threshold": self.threshold,
            "decision_threshold": self.threshold,    # Agent 3 compatibility alias
            "model_version": self.model_version,
            "supporting_features": [f.to_dict() if hasattr(f, "to_dict") else f for f in self.supporting_features],
            "inference_latency_ms": self.inference_latency_ms,
        }
        if self.error_message:
            res["error_message"] = self.error_message
        return res


def create_disabled_threat_intel_payload() -> Dict[str, Any]:
    """Create a standardized disabled threat intelligence payload for Agent 3 compatibility.

    TinyFish and external threat intelligence are completely disabled for Agent 2.
    This explicit structure prevents breaking Agent 3 consumers while guaranteeing
    no fabricated intelligence is emitted.
    """
    return {
        "status": "DISABLED",
        "investigation_status": "NOT_APPLICABLE",
        "is_enriched": False,
        "provider": "none",
        "findings": [],
        "sources": [],
        "reputation_summary": "Threat intelligence disabled; Agent 2 is purely network anomaly detection.",
        "details": {},
    }


@dataclass
class Agent2Evidence:
    """Standardized evidence payload delivered to Agent 3 for evidence fusion.

    Contains:
    - flow_id: Unique flow identifier.
    - timestamp: Generation timestamp.
    - agent_id: 'A2'.
    - anomaly_evidence: AnomalyScore dictionary or evaluation error report.
    - threat_intelligence: Standardized disabled threat intelligence block.
    - routing_metadata: Source/destination IPs, ports, and protocol.
    """

    flow_id: str
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    agent_id: str = "A2"
    anomaly_evidence: Dict[str, Any] = field(default_factory=dict)
    threat_intelligence: Dict[str, Any] = field(default_factory=create_disabled_threat_intel_payload)
    routing_metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def anomaly_detection(self) -> Dict[str, Any]:
        """Compatibility property for downstream consumers expecting anomaly_detection."""
        return self.anomaly_evidence

    @property
    def metadata(self) -> Dict[str, Any]:
        """Compatibility property for downstream consumers expecting metadata."""
        return self.routing_metadata

    def to_dict(self) -> Dict[str, Any]:
        """Serialize complete evidence payload to a dictionary for Agent 3."""
        return {
            "agent_id": self.agent_id,
            "flow_id": self.flow_id,
            "timestamp": self.timestamp,
            "anomaly_evidence": self.anomaly_evidence,
            "threat_intelligence": self.threat_intelligence,
            "routing_metadata": self.routing_metadata,
        }
