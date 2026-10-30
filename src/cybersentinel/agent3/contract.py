"""PROVISIONAL INTERFACE CONTRACT FOR AGENT 3 (CyberSentinel).

===============================================================================
STATUS: PROVISIONAL CONTRACT
===============================================================================
NOTICE:
As of repository inspection (Block 1), Agent 1 (Signature / Line-Rate Triage)
and Agent 2 (Anomaly / Behavioral Analysis) implementations have not yet been
committed to this repository.

This contract defines the provisional input/output interfaces for Agent 3.
The following items REQUIRE CONFIRMATION from Agent 1 and Agent 2 owners:
  1. Exact field naming for threat classification (e.g., 'threat_type' vs 'attack_category').
  2. Confidence and anomaly score scaling (assumed normalized to [0.0, 1.0]).
  3. Flow identification key format (assumed standard 5-tuple + timestamp or flow_id UUID).
  4. Transmission mechanism: In-process direct call vs async message queue (e.g., Kafka/Redis) vs REST API.
  5. Timeout SLA: Maximum wait time for A1/A2 results before triggering missing-agent fallback.
===============================================================================
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class AgentStatus(str, Enum):
    """Operational status of an upstream agent detection."""
    SUCCESS = "SUCCESS"
    NOT_DETECTED = "NOT_DETECTED"
    TIMED_OUT = "TIMED_OUT"
    ERROR = "ERROR"
    UNAVAILABLE = "UNAVAILABLE"


class FusionStatus(str, Enum):
    """Execution status of Agent 3 decision fusion."""
    DUAL_AGENT = "DUAL_AGENT"
    SINGLE_AGENT_A1_ONLY = "SINGLE_AGENT_A1_ONLY"
    SINGLE_AGENT_A2_ONLY = "SINGLE_AGENT_A2_ONLY"
    NO_AGENT_DATA = "NO_AGENT_DATA"
    DEGRADED = "DEGRADED"


class Verdict(str, Enum):
    """Final correlated triage verdict."""
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    BENIGN = "BENIGN"
    INCONCLUSIVE = "INCONCLUSIVE"


class RecommendedAction(str, Enum):
    """Recommended action category passed downstream to Policy Engine."""
    DROP = "DROP"
    QUARANTINE = "QUARANTINE"
    RATE_LIMIT = "RATE_LIMIT"
    ALERT = "ALERT"
    LOG_ALLOW = "LOG_ALLOW"


@dataclass
class FlowContext:
    """Network flow metadata associated with the event (Required Input)."""
    flow_id: str
    timestamp: str  # ISO 8601 string
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str  # e.g., "TCP", "UDP", "ICMP"
    packet_count: Optional[int] = None
    byte_count: Optional[int] = None

    def validate(self) -> None:
        """Validate required flow context fields."""
        if not self.flow_id:
            raise ValueError("flow_id must not be empty")
        if not self.timestamp:
            raise ValueError("timestamp must not be empty")
        if not self.src_ip or not self.dst_ip:
            raise ValueError("src_ip and dst_ip must not be empty")
        if not (0 <= self.src_port <= 65535) or not (0 <= self.dst_port <= 65535):
            raise ValueError("src_port and dst_port must be in range [0, 65535]")


@dataclass
class A1DetectionResult:
    """Provisional output schema received from Agent 1 (Signature / Line-Rate Triage)."""
    agent_id: str = "agent_1"
    status: AgentStatus = AgentStatus.SUCCESS
    threat_detected: bool = False
    threat_type: Optional[str] = None
    confidence: float = 0.0  # Range [0.0, 1.0]
    rule_id: Optional[str] = None
    features: Dict[str, Any] = field(default_factory=dict)
    latency_ms: Optional[float] = None
    error_message: Optional[str] = None

    def validate(self) -> None:
        """Validate A1 detection values."""
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("Agent 1 confidence must be in range [0.0, 1.0]")


@dataclass
class A2DetectionResult:
    """Provisional output schema received from Agent 2 (Anomaly / Behavioral Analysis)."""
    agent_id: str = "agent_2"
    status: AgentStatus = AgentStatus.SUCCESS
    anomaly_detected: bool = False
    anomaly_score: float = 0.0  # Range [0.0, 1.0]
    anomaly_type: Optional[str] = None
    confidence: float = 0.0  # Range [0.0, 1.0]
    model_version: Optional[str] = None
    features: Dict[str, Any] = field(default_factory=dict)
    latency_ms: Optional[float] = None
    error_message: Optional[str] = None

    def validate(self) -> None:
        """Validate A2 detection values."""
        if not (0.0 <= self.anomaly_score <= 1.0):
            raise ValueError("Agent 2 anomaly_score must be in range [0.0, 1.0]")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("Agent 2 confidence must be in range [0.0, 1.0]")


@dataclass
class Agent3Input:
    """Consolidated input structure ingested by Agent 3."""
    flow_context: FlowContext
    a1_result: Optional[A1DetectionResult] = None
    a2_result: Optional[A2DetectionResult] = None
    network_metadata: Optional[Dict[str, Any]] = field(default_factory=dict)

    def validate(self) -> None:
        """Validate top-level input."""
        if self.flow_context is None:
            raise ValueError("flow_context is required")
        self.flow_context.validate()
        if self.a1_result is not None:
            self.a1_result.validate()
        if self.a2_result is not None:
            self.a2_result.validate()


@dataclass
class Agent3Output:
    """Output JSON schema produced by Agent 3 for Policy Engine ingestion."""
    incident_id: str
    flow_id: str
    timestamp: str
    verdict: Verdict
    fused_risk_score: float  # Range [0.0, 1.0]
    confidence: float  # Range [0.0, 1.0]
    contributing_agents: List[str]
    fusion_status: FusionStatus
    threat_summary: str
    details: Dict[str, Any]
    recommended_policy_action: RecommendedAction
    processing_time_ms: float

    def to_dict(self) -> Dict[str, Any]:
        """Convert output to a clean serializable dictionary."""
        data = asdict(self)
        data["verdict"] = self.verdict.value
        data["fusion_status"] = self.fusion_status.value
        data["recommended_policy_action"] = self.recommended_policy_action.value
        return data

    def to_json(self, indent: Optional[int] = 2) -> str:
        """Serialize output to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Agent3Output:
        """Deserialize from dictionary."""
        return cls(
            incident_id=data["incident_id"],
            flow_id=data["flow_id"],
            timestamp=data["timestamp"],
            verdict=Verdict(data["verdict"]),
            fused_risk_score=float(data["fused_risk_score"]),
            confidence=float(data["confidence"]),
            contributing_agents=list(data["contributing_agents"]),
            fusion_status=FusionStatus(data["fusion_status"]),
            threat_summary=str(data["threat_summary"]),
            details=dict(data.get("details", {})),
            recommended_policy_action=RecommendedAction(data["recommended_policy_action"]),
            processing_time_ms=float(data.get("processing_time_ms", 0.0)),
        )

