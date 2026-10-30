"""Modular typed schemas for CyberSentinel Agent 3 and upstream agents.

Defines:
  - Agent1ThreatPrediction: Typed schema for Agent 1 signature / threat predictions.
  - Agent2AnomalyAssessment: Typed schema for Agent 2 behavioral anomaly assessments.
  - Agent3FusionInput: Typed schema for multi-agent input ingested by Agent 3.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from cybersentinel.agent3.contract import (
    Agent3Output,
    AgentStatus,
    FlowContext,
    FusionStatus,
    RecommendedAction,
    Verdict,
)
from cybersentinel.agent3.exceptions import InvalidInputError, SchemaValidationError
from cybersentinel.agent3.validator import (
    A1_CLASS_NORMALIZATION,
    A1ThreatClass,
    ValidationResult,
    validate_agent1_output,
    validate_agent2_output,
    validate_fusion_input,
)


@dataclass
class Agent1ThreatPrediction:
    """Typed schema for Agent 1 (Signature / Line-Rate Triage) threat prediction.

    Attributes:
        predicted_class: Class name (BENIGN, BRUTE FORCE, DOS, DDOS, PORT SCAN).
        confidence: Prediction confidence score in range [0.0, 1.0].
        probabilities: Optional mapping of class names to probability floats.
        agent_id: Identifier for reporting agent (default: "agent_1").
        status: Operational status (default: AgentStatus.SUCCESS).
        rule_id: Optional signature rule identifier triggered.
        features: Optional extracted feature mapping.
        latency_ms: Optional execution latency in milliseconds.
        error_message: Optional error message if status is non-success.
    """
    predicted_class: str = "BENIGN"
    confidence: float = 0.0
    probabilities: Optional[Dict[str, float]] = None
    agent_id: str = "agent_1"
    status: AgentStatus = AgentStatus.SUCCESS
    rule_id: Optional[str] = None
    features: Dict[str, Any] = field(default_factory=dict)
    latency_ms: Optional[float] = None
    error_message: Optional[str] = None

    @property
    def threat_class(self) -> str:
        """Alias for predicted_class."""
        return self.predicted_class

    @property
    def threat_type(self) -> str:
        """Alias for predicted_class (backward compatibility with Block 1)."""
        return self.predicted_class

    @property
    def threat_detected(self) -> bool:
        """Returns True if the predicted class is not BENIGN."""
        norm = A1_CLASS_NORMALIZATION.get(self.predicted_class.strip().upper(), self.predicted_class)
        return norm != "BENIGN"

    def validate(self, raise_on_error: bool = False) -> ValidationResult:
        """Validate this prediction instance against Block 2 rules.

        Args:
            raise_on_error: If True, raises SchemaValidationError on failure.

        Returns:
            ValidationResult containing status and structured errors.
        """
        res = validate_agent1_output(self)
        if raise_on_error and not res.is_valid:
            msg = "; ".join(res.error_messages)
            raise SchemaValidationError(f"Agent 1 validation failed: {msg}", validation_result=res)
        return res

    def to_dict(self) -> Dict[str, Any]:
        """Convert prediction to serializable dictionary."""
        data = asdict(self)
        data["status"] = self.status.value if isinstance(self.status, Enum) else str(self.status)
        data["threat_detected"] = self.threat_detected
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Agent1ThreatPrediction:
        """Create Agent1ThreatPrediction from raw dictionary."""
        p_class = (
            data.get("predicted_class")
            or data.get("threat_class")
            or data.get("class")
            or data.get("threat_type")
            or "BENIGN"
        )
        status_val = data.get("status", AgentStatus.SUCCESS)
        if isinstance(status_val, str):
            try:
                status_enum = AgentStatus(status_val)
            except ValueError:
                status_enum = AgentStatus.SUCCESS
        else:
            status_enum = status_val

        return cls(
            predicted_class=str(p_class),
            confidence=float(data.get("confidence", 0.0)),
            probabilities=dict(data["probabilities"]) if data.get("probabilities") is not None else None,
            agent_id=str(data.get("agent_id", "agent_1")),
            status=status_enum,
            rule_id=data.get("rule_id"),
            features=dict(data.get("features", {})),
            latency_ms=float(data["latency_ms"]) if data.get("latency_ms") is not None else None,
            error_message=data.get("error_message"),
        )


@dataclass
class Agent2AnomalyAssessment:
    """Typed schema for Agent 2 (Anomaly / Behavioral Analysis) assessment.

    Attributes:
        anomaly_score: Continuous anomaly indicator (finite float >= 0.0).
                       Note: NEVER assumed to be a probability.
        anomaly_detected: Boolean flag indicating if anomaly threshold is exceeded.
        evidence: List of descriptive string indicators / anomalous feature explanations.
        agent_id: Identifier for reporting agent (default: "agent_2").
        status: Operational status (default: AgentStatus.SUCCESS).
        anomaly_type: Optional classification or cluster label for the anomaly.
        confidence: Confidence in the anomaly estimation in range [0.0, 1.0].
        model_version: Optional identifier of the detection model artifact.
        features: Optional dictionary of raw numerical or extracted features.
        latency_ms: Optional execution latency in milliseconds.
        error_message: Optional error message if status is non-success.
    """
    anomaly_score: float = 0.0
    anomaly_detected: bool = False
    evidence: List[str] = field(default_factory=list)
    agent_id: str = "agent_2"
    status: AgentStatus = AgentStatus.SUCCESS
    anomaly_type: Optional[str] = None
    confidence: float = 0.0
    model_version: Optional[str] = None
    features: Dict[str, Any] = field(default_factory=dict)
    latency_ms: Optional[float] = None
    error_message: Optional[str] = None

    @property
    def is_anomaly(self) -> bool:
        """Alias for anomaly_detected."""
        return self.anomaly_detected

    def validate(self, raise_on_error: bool = False) -> ValidationResult:
        """Validate this assessment instance against Block 2 rules.

        Args:
            raise_on_error: If True, raises SchemaValidationError on failure.

        Returns:
            ValidationResult containing status and structured errors.
        """
        res = validate_agent2_output(self)
        if raise_on_error and not res.is_valid:
            msg = "; ".join(res.error_messages)
            raise SchemaValidationError(f"Agent 2 validation failed: {msg}", validation_result=res)
        return res

    def to_dict(self) -> Dict[str, Any]:
        """Convert assessment to serializable dictionary."""
        data = asdict(self)
        data["status"] = self.status.value if isinstance(self.status, Enum) else str(self.status)
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Agent2AnomalyAssessment:
        """Create Agent2AnomalyAssessment from raw dictionary."""
        status_val = data.get("status", AgentStatus.SUCCESS)
        if isinstance(status_val, str):
            try:
                status_enum = AgentStatus(status_val)
            except ValueError:
                status_enum = AgentStatus.SUCCESS
        else:
            status_enum = status_val

        detected_val = (
            data.get("anomaly_detected")
            if "anomaly_detected" in data
            else data.get("is_anomaly", False)
        )
        evidence_raw = data.get("evidence", [])
        evidence_list = list(evidence_raw) if isinstance(evidence_raw, list) else []

        return cls(
            anomaly_score=float(data.get("anomaly_score", 0.0)),
            anomaly_detected=bool(detected_val),
            evidence=evidence_list,
            agent_id=str(data.get("agent_id", "agent_2")),
            status=status_enum,
            anomaly_type=data.get("anomaly_type"),
            confidence=float(data.get("confidence", 0.0)),
            model_version=data.get("model_version"),
            features=dict(data.get("features", {})),
            latency_ms=float(data["latency_ms"]) if data.get("latency_ms") is not None else None,
            error_message=data.get("error_message"),
        )


@dataclass
class Agent3FusionInput:
    """Typed schema for multi-agent input ingested by Agent 3 for fusion.

    Attributes:
        flow_context: FlowContext defining network flow metadata (Required).
        a1_prediction: Optional Agent1ThreatPrediction from Agent 1.
        a2_assessment: Optional Agent2AnomalyAssessment from Agent 2.
        network_metadata: Optional dictionary of network environment metadata.
    """
    flow_context: FlowContext
    a1_prediction: Optional[Agent1ThreatPrediction] = None
    a2_assessment: Optional[Agent2AnomalyAssessment] = None
    network_metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def a1_result(self) -> Optional[Agent1ThreatPrediction]:
        """Alias for backward compatibility with Block 1."""
        return self.a1_prediction

    @property
    def a2_result(self) -> Optional[Agent2AnomalyAssessment]:
        """Alias for backward compatibility with Block 1."""
        return self.a2_assessment

    def validate(self, strict: bool = False, raise_on_error: bool = False) -> ValidationResult:
        """Validate fusion input against Block 2 rules.

        Args:
            strict: If True, requires both A1 and A2 to be present.
            raise_on_error: If True, raises SchemaValidationError on failure.

        Returns:
            ValidationResult with detailed status.
        """
        res = validate_fusion_input(self, strict=strict)
        if raise_on_error and not res.is_valid:
            msg = "; ".join(res.error_messages)
            raise SchemaValidationError(f"Fusion input validation failed: {msg}", validation_result=res)
        return res

    def to_dict(self) -> Dict[str, Any]:
        """Convert fusion input to serializable dictionary."""
        return {
            "flow_context": asdict(self.flow_context),
            "a1_prediction": self.a1_prediction.to_dict() if self.a1_prediction else None,
            "a2_assessment": self.a2_assessment.to_dict() if self.a2_assessment else None,
            "network_metadata": self.network_metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Agent3FusionInput:
        """Create Agent3FusionInput from raw dictionary."""
        flow_raw = data.get("flow_context")
        if not isinstance(flow_raw, dict):
            raise InvalidInputError("Missing or invalid 'flow_context' in payload.")

        flow_context = FlowContext(
            flow_id=str(flow_raw.get("flow_id", "")),
            timestamp=str(flow_raw.get("timestamp", "")),
            src_ip=str(flow_raw.get("src_ip", "")),
            src_port=int(flow_raw.get("src_port", 0)),
            dst_ip=str(flow_raw.get("dst_ip", "")),
            dst_port=int(flow_raw.get("dst_port", 0)),
            protocol=str(flow_raw.get("protocol", "TCP")),
            packet_count=flow_raw.get("packet_count"),
            byte_count=flow_raw.get("byte_count"),
        )

        a1_raw = data.get("a1_prediction") if "a1_prediction" in data else data.get("a1_result")
        a1_prediction = Agent1ThreatPrediction.from_dict(a1_raw) if a1_raw is not None else None

        a2_raw = data.get("a2_assessment") if "a2_assessment" in data else data.get("a2_result")
        a2_assessment = Agent2AnomalyAssessment.from_dict(a2_raw) if a2_raw is not None else None

        return cls(
            flow_context=flow_context,
            a1_prediction=a1_prediction,
            a2_assessment=a2_assessment,
            network_metadata=dict(data.get("network_metadata", {})),
        )


@dataclass
class Agent3ThreatAssessment:
    """Final structured threat assessment emitted by Agent 3 for Policy Engine ingestion.

    Matches the exact schema specified in CyberSentinel Agent 3 specification.
    """
    agent_id: str = "A3"
    flow_id: str = ""
    final_class: str = "UNKNOWN"
    assessment: str = "INCONCLUSIVE"
    evidence_status: str = "INSUFFICIENT_EVIDENCE"
    agent_agreement: Optional[bool] = None
    fusion_score: Optional[float] = None
    risk_level: str = "UNKNOWN"
    confidence_level: str = "LOW"
    supporting_evidence: List[str] = field(default_factory=list)
    conflicting_evidence: List[str] = field(default_factory=list)
    uncertainty: List[str] = field(default_factory=list)
    score_breakdown: Dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""
    investigation_priority: str = "LOW"
    timestamp: Optional[str] = None
    recommended_action: Optional[str] = None
    explanation: Optional[Dict[str, str]] = None
    processing_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert assessment to clean dictionary matching specification."""
        return {
            "agent_id": self.agent_id,
            "flow_id": self.flow_id,
            "final_class": self.final_class,
            "assessment": self.assessment,
            "evidence_status": self.evidence_status,
            "agent_agreement": self.agent_agreement,
            "fusion_score": self.fusion_score,
            "risk_level": self.risk_level,
            "confidence_level": self.confidence_level,
            "supporting_evidence": list(self.supporting_evidence),
            "conflicting_evidence": list(self.conflicting_evidence),
            "uncertainty": list(self.uncertainty),
            "score_breakdown": dict(self.score_breakdown),
            "reasoning": self.reasoning,
            "investigation_priority": self.investigation_priority,
        }

    def to_json(self, indent: Optional[int] = 2) -> str:
        """Serialize output to JSON string."""
        import json
        return json.dumps(self.to_dict(), indent=indent)

    def __getitem__(self, item: str) -> Any:
        """Allow dict-like subscripting."""
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def get(self, key: str, default: Any = None) -> Any:
        """Allow dict-like .get() access."""
        return getattr(self, key, default)

    def to_agent3_output(self, incident_id: Optional[str] = None) -> Agent3Output:
        """Convert assessment to Block 1 Agent3Output for downstream Policy Engine."""
        import uuid

        verdict_map = {
            "MALICIOUS": Verdict.MALICIOUS,
            "SUSPICIOUS": Verdict.SUSPICIOUS,
            "BENIGN": Verdict.BENIGN,
            "INCONCLUSIVE": Verdict.INCONCLUSIVE,
        }
        verdict = verdict_map.get(self.assessment, Verdict.INCONCLUSIVE)

        action_map = {
            "CRITICAL": RecommendedAction.DROP,
            "HIGH": RecommendedAction.ALERT,
            "MEDIUM": RecommendedAction.RATE_LIMIT,
            "LOW": RecommendedAction.LOG_ALLOW,
        }
        rec_action = action_map.get(self.risk_level, RecommendedAction.LOG_ALLOW)

        contributing: List[str] = []
        if self.score_breakdown.get("classifier_score") is not None:
            contributing.append("agent_1")
        if self.score_breakdown.get("anomaly_score") is not None:
            contributing.append("agent_2")

        if "agent_1" in contributing and "agent_2" in contributing:
            f_status = FusionStatus.DUAL_AGENT
        elif "agent_1" in contributing:
            f_status = FusionStatus.SINGLE_AGENT_A1_ONLY
        elif "agent_2" in contributing:
            f_status = FusionStatus.SINGLE_AGENT_A2_ONLY
        else:
            f_status = FusionStatus.NO_AGENT_DATA

        conf_num = (
            0.90 if self.confidence_level == "HIGH"
            else (0.60 if self.confidence_level == "MEDIUM" else 0.30)
        )

        return Agent3Output(
            incident_id=incident_id or f"inc-{uuid.uuid4().hex[:12]}",
            flow_id=self.flow_id,
            timestamp=self.timestamp or "",
            verdict=verdict,
            fused_risk_score=self.fusion_score if self.fusion_score is not None else 0.0,
            confidence=conf_num,
            contributing_agents=contributing,
            fusion_status=f_status,
            threat_summary=self.reasoning,
            details=self.to_dict(),
            recommended_policy_action=rec_action,
            processing_time_ms=self.processing_time_ms,
        )


