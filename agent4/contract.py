"""Interface contracts and data models for CyberSentinel Agent 4 (Policy Engine).

Defines:
  - PolicyAction: Standardized enforcement actions (ALLOW, ALERT, REVIEW, BLOCK).
  - PolicyProfile: Configurable operational profiles (DEFAULT, STRICT, PERMISSIVE).
  - ValidatedThreatAssessment: Normalized input model derived from Agent 3 threat assessment.
  - PolicyDecision: Structured output model emitted by the Policy Engine.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

from cybersentinel.agent4.exceptions import (
    InvalidAssessmentError,
    InvalidJsonError,
    MissingAssessmentError,
    PolicyInputError,
)


class PolicyAction(str, Enum):
    """Enforcement policy actions evaluated by Agent 4.

    NOTICE:
      BLOCK is strictly a simulated policy decision. Never configure an actual
      firewall or disrupt physical network traffic.
    """
    ALLOW = "ALLOW"
    ALERT = "ALERT"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class PolicyProfile(str, Enum):
    """Operational posture profiles for policy evaluation."""
    BALANCED = "BALANCED"
    STRICT = "STRICT"
    CONSERVATIVE = "CONSERVATIVE"
    DEFAULT = "DEFAULT"
    PERMISSIVE = "PERMISSIVE"


@dataclass
class ValidatedThreatAssessment:
    """Normalized threat assessment ingested from Agent 3."""
    flow_id: str
    final_class: str
    assessment: str
    risk_level: str
    confidence_level: str
    fusion_score: Optional[float] = None
    evidence_status: str = "INSUFFICIENT_EVIDENCE"
    investigation_priority: str = "LOW"
    reasoning: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class PolicyDecision:
    """Structured policy evaluation decision emitted by Agent 4.

    Attributes:
        agent_id: Fixed identifier for Agent 4 ('A4').
        flow_id: Correlated network flow identifier.
        action: Selected policy decision (ALLOW, ALERT, REVIEW, BLOCK).
        policy_profile: Name of active evaluation profile (e.g. 'DEFAULT').
        risk_level: Input risk level assessed by Agent 3.
        confidence_level: Input confidence level from Agent 3.
        matched_rule: Name or identifier of policy rule matched.
        decision_reason: Human-readable rationale for selected policy action.
        requires_human_review: True if flow requires manual SOC analyst review.
        simulated: True indicating BLOCK decisions are simulated only.
        timestamp: ISO 8601 UTC timestamp of policy evaluation.
        metadata: Optional dictionary with additional audit and score metadata.
    """
    agent_id: str = "A4"
    flow_id: str = "UNKNOWN"
    action: PolicyAction = PolicyAction.REVIEW
    policy_profile: str = "BALANCED"
    risk_level: str = "UNKNOWN"
    confidence_level: str = "LOW"
    evidence_status: str = "INSUFFICIENT_EVIDENCE"
    matched_rule: str = "RULE_UNSPECIFIED"
    decision_reason: str = ""
    requires_human_review: bool = True
    simulated: bool = True
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert policy decision to clean dictionary matching contract."""
        act_val = self.action.value if hasattr(self.action, "value") else str(self.action)
        return {
            "agent_id": self.agent_id,
            "flow_id": self.flow_id,
            "action": act_val,
            "policy_profile": self.policy_profile,
            "risk_level": self.risk_level,
            "confidence_level": self.confidence_level,
            "evidence_status": self.evidence_status,
            "matched_rule": self.matched_rule,
            "decision_reason": self.decision_reason,
            "requires_human_review": self.requires_human_review,
            "simulated": self.simulated,
            "timestamp": self.timestamp,
        }

    def to_json(self, indent: Optional[int] = 2) -> str:
        """Serialize policy decision to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def __getitem__(self, item: str) -> Any:
        """Allow dict-like subscript access."""
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def get(self, key: str, default: Any = None) -> Any:
        """Allow dict-like get method."""
        return getattr(self, key, default)


def parse_assessment_input(
    raw_input: Any,
    raise_on_error: bool = False,
) -> Tuple[Optional[ValidatedThreatAssessment], Optional[str]]:
    """Parse and validate Agent 3 assessment from objects, dicts, or JSON strings.

    Supports:
      - Assessment objects with attributes (e.g. Agent3ThreatAssessment, Agent3Output).
      - Raw dictionary structures.
      - JSON strings produced by assessment.to_json().

    Args:
        raw_input: Raw input payload.
        raise_on_error: If True, raises specific exceptions on invalid inputs.

    Returns:
        Tuple of (ValidatedThreatAssessment or None, error_message or None).

    Raises:
        MissingAssessmentError: If raw_input is None and raise_on_error is True.
        InvalidJsonError: If raw_input is unparseable JSON string and raise_on_error is True.
        InvalidAssessmentError: If structure or fields are missing/malformed and raise_on_error is True.
    """
    if raw_input is None:
        msg = "Assessment input is missing (None provided)."
        if raise_on_error:
            raise MissingAssessmentError(msg)
        return None, msg

    data: Dict[str, Any] = {}

    # 1. Parse JSON string if string provided
    if isinstance(raw_input, str):
        stripped = raw_input.strip()
        if not stripped:
            msg = "Assessment input string is empty."
            if raise_on_error:
                raise InvalidJsonError(msg)
            return None, msg
        try:
            parsed = json.loads(stripped)
            if not isinstance(parsed, dict):
                msg = f"Parsed JSON must be an object/dict, got {type(parsed).__name__}."
                if raise_on_error:
                    raise InvalidAssessmentError(msg)
                return None, msg
            data = parsed
        except json.JSONDecodeError as exc:
            msg = f"Invalid JSON string: {exc}"
            if raise_on_error:
                raise InvalidJsonError(msg) from exc
            return None, msg

    # 2. Extract from dictionary
    elif isinstance(raw_input, dict):
        data = raw_input

    # 3. Extract from object with attributes
    elif hasattr(raw_input, "__dict__") or hasattr(raw_input, "flow_id"):
        # Check if to_dict exists
        if callable(getattr(raw_input, "to_dict", None)):
            try:
                data = raw_input.to_dict()
            except Exception:
                data = {}
        if not data:
            data = {
                "flow_id": getattr(raw_input, "flow_id", None),
                "final_class": getattr(raw_input, "final_class", None),
                "assessment": getattr(raw_input, "assessment", None),
                "risk_level": getattr(raw_input, "risk_level", None),
                "confidence_level": getattr(raw_input, "confidence_level", None),
                "fusion_score": getattr(raw_input, "fusion_score", None) or getattr(raw_input, "fused_risk_score", None),
                "evidence_status": getattr(raw_input, "evidence_status", None),
                "investigation_priority": getattr(raw_input, "investigation_priority", None),
                "reasoning": getattr(raw_input, "reasoning", None) or getattr(raw_input, "threat_summary", None),
            }
            # Handle Block 1 Agent3Output where details holds rich metadata
            details = getattr(raw_input, "details", None)
            if isinstance(details, dict):
                for k, v in details.items():
                    if data.get(k) is None:
                        data[k] = v

    else:
        msg = f"Unsupported input type for assessment: {type(raw_input).__name__}. Expected dict, dataclass, or JSON string."
        if raise_on_error:
            raise InvalidAssessmentError(msg)
        return None, msg

    # Unpack nested 'details' dict if present (e.g. from Agent3Output or legacy dicts)
    details = data.get("details")
    if isinstance(details, dict):
        for k, v in details.items():
            if data.get(k) is None:
                data[k] = v

    # 4. Validate required fields
    flow_id = data.get("flow_id")
    if not flow_id or not isinstance(flow_id, str):
        msg = f"Missing or invalid 'flow_id' field: {flow_id!r}."
        if raise_on_error:
            raise InvalidAssessmentError(msg)
        return None, msg

    # Normalize risk_level
    raw_risk = data.get("risk_level")
    if not raw_risk or not isinstance(raw_risk, str):
        msg = f"Missing or invalid 'risk_level' field: {raw_risk!r}."
        if raise_on_error:
            raise InvalidAssessmentError(msg)
        return None, msg
    risk_level = raw_risk.strip().upper()

    # Normalize confidence_level
    raw_conf = data.get("confidence_level")
    if not raw_conf:
        # Check if numeric confidence is present
        num_conf = data.get("confidence")
        if isinstance(num_conf, (int, float)):
            raw_conf = "HIGH" if num_conf >= 0.75 else ("MEDIUM" if num_conf >= 0.50 else "LOW")
        else:
            msg = "Missing 'confidence_level' field."
            if raise_on_error:
                raise InvalidAssessmentError(msg)
            return None, msg
    confidence_level = str(raw_conf).strip().upper()

    # Extract assessment / verdict
    assessment = str(data.get("assessment") or data.get("verdict") or "UNKNOWN").strip().upper()

    # Extract final_class
    final_class = str(data.get("final_class") or data.get("predicted_class") or "UNKNOWN").strip().upper()

    # Extract fusion_score
    raw_score = data.get("fusion_score") if "fusion_score" in data else data.get("fused_risk_score")
    fusion_score: Optional[float] = None
    if raw_score is not None:
        try:
            fusion_score = float(raw_score)
        except (ValueError, TypeError):
            fusion_score = None

    # Extract evidence_status
    raw_ev = data.get("evidence_status")
    if raw_ev:
        evidence_status = str(raw_ev).strip().upper()
    else:
        if risk_level == "UNKNOWN" or assessment == "INCONCLUSIVE":
            evidence_status = "INSUFFICIENT_EVIDENCE"
        else:
            evidence_status = "AGREEMENT"

    # Extract investigation_priority
    investigation_priority = str(data.get("investigation_priority") or "LOW").strip().upper()

    # Extract reasoning
    reasoning = str(data.get("reasoning") or data.get("threat_summary") or "").strip()

    validated = ValidatedThreatAssessment(
        flow_id=str(flow_id).strip(),
        final_class=final_class,
        assessment=assessment,
        risk_level=risk_level,
        confidence_level=confidence_level,
        fusion_score=fusion_score,
        evidence_status=evidence_status,
        investigation_priority=investigation_priority,
        reasoning=reasoning,
        metadata=dict(data),
    )
    return validated, None
