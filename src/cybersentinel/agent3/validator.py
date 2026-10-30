"""Robust input validation and structured error reporting for CyberSentinel Agent 3.

Validates upstream outputs from:
  - Agent 1: Line-Rate Signature Triage & Threat Prediction
  - Agent 2: Deep Behavioral Anomaly Assessment
  - Agent 3: Combined Multi-Agent Fusion Input
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union


class A1ThreatClass(str, Enum):
    """Allowed threat classification categories for Agent 1."""
    BENIGN = "BENIGN"
    BRUTE_FORCE = "BRUTE FORCE"
    DOS = "DOS"
    DDOS = "DDOS"
    PORT_SCAN = "PORT SCAN"


# Canonical string representation of the 5 allowed classes
CANONICAL_A1_CLASSES: Set[str] = {
    "BENIGN",
    "BRUTE FORCE",
    "DOS",
    "DDOS",
    "PORT SCAN",
}

# Mapping including standard identifier aliases (e.g., BRUTE_FORCE -> BRUTE FORCE)
A1_CLASS_NORMALIZATION: Dict[str, str] = {
    "BENIGN": "BENIGN",
    "BRUTE FORCE": "BRUTE FORCE",
    "BRUTE_FORCE": "BRUTE FORCE",
    "DOS": "DOS",
    "DDOS": "DDOS",
    "PORT SCAN": "PORT SCAN",
    "PORT_SCAN": "PORT SCAN",
    "SYN_FLOOD": "DOS",
    "SYN FLOOD": "DOS",
}


@dataclass
class ValidationErrorDetail:
    """Detailed structured error object for validation failures."""
    field: str
    message: str
    error_code: str
    invalid_value: Any = None
    agent_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert error detail to dictionary."""
        return {
            "field": self.field,
            "message": self.message,
            "error_code": self.error_code,
            "invalid_value": str(self.invalid_value) if self.invalid_value is not None else None,
            "agent_id": self.agent_id,
        }


@dataclass
class ValidationResult:
    """Structured validation result holding status, error details, and metadata."""
    is_valid: bool
    is_missing: bool = False
    is_malformed: bool = False
    errors: List[ValidationErrorDetail] = field(default_factory=list)
    agent_id: Optional[str] = None
    validated_data: Optional[Any] = None
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def error_codes(self) -> List[str]:
        """List of all error codes recorded."""
        return [err.error_code for err in self.errors]

    @property
    def error_messages(self) -> List[str]:
        """List of all error messages recorded."""
        return [err.message for err in self.errors]

    def has_error(self, error_code: str) -> bool:
        """Check if a specific error code is present."""
        return any(err.error_code == error_code for err in self.errors)

    def add_error(
        self,
        field: str,
        message: str,
        error_code: str,
        invalid_value: Any = None,
        agent_id: Optional[str] = None,
    ) -> None:
        """Record a validation error and update status flags."""
        self.is_valid = False
        self.is_malformed = True
        self.errors.append(
            ValidationErrorDetail(
                field=field,
                message=message,
                error_code=error_code,
                invalid_value=invalid_value,
                agent_id=agent_id or self.agent_id,
            )
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert validation result to dictionary."""
        return {
            "is_valid": self.is_valid,
            "is_missing": self.is_missing,
            "is_malformed": self.is_malformed,
            "agent_id": self.agent_id,
            "errors": [err.to_dict() for err in self.errors],
            "details": self.details,
        }


def _is_finite_number(value: Any) -> bool:
    """Check if value is a numeric type and finite (not NaN, not Inf, not bool)."""
    if isinstance(value, bool):
        return False
    if not isinstance(value, (int, float)):
        return False
    return not (math.isnan(value) or math.isinf(value))


def validate_agent1_output(data: Any) -> ValidationResult:
    """Validate Agent 1 threat prediction output.

    Validation rules:
      1. Distinguishes missing input (data is None) from malformed input.
      2. Class must be one of: BENIGN, BRUTE FORCE, DOS, DDOS, PORT SCAN.
      3. Confidence must be finite and in range [0.0, 1.0]. Reject NaN/Inf.
      4. Validate probability keys (must be valid classes) and values (finite in [0, 1]).
      5. If all 5 probabilities are present, their sum must be approximately 1.0.
      6. Reject NaN and infinity anywhere in numeric fields.

    Args:
        data: Agent1ThreatPrediction, A1DetectionResult, or dict.

    Returns:
        ValidationResult with status and structured error details.
    """
    result = ValidationResult(is_valid=True, agent_id="agent_1")

    # 1. Distinguish missing agent output
    if data is None:
        result.is_valid = False
        result.is_missing = True
        result.is_malformed = False
        result.errors.append(
            ValidationErrorDetail(
                field="agent_1",
                message="Agent 1 output is missing or unavailable.",
                error_code="MISSING_AGENT",
                agent_id="agent_1",
            )
        )
        return result

    # 2. Extract fields from dict or object
    if isinstance(data, dict):
        raw_dict = data
        if not raw_dict:
            result.is_valid = False
            result.is_missing = False
            result.is_malformed = True
            result.errors.append(
                ValidationErrorDetail(
                    field="agent_1",
                    message="Agent 1 payload is empty.",
                    error_code="MALFORMED_INPUT",
                    agent_id="agent_1",
                )
            )
            return result

        class_key = None
        for k in ("predicted_class", "threat_class", "class", "threat_type"):
            if k in raw_dict:
                class_key = k
                break
        if class_key is None and raw_dict.get("threat_detected") is False:
            class_val = "BENIGN"
            class_present = True
        else:
            class_present = class_key is not None
            class_val = raw_dict[class_key] if class_present else None
        conf_val = raw_dict.get("confidence")
        probs_val = raw_dict.get("probabilities")
    elif hasattr(data, "__dataclass_fields__") or hasattr(data, "confidence"):
        class_key = None
        for k in ("predicted_class", "threat_class", "threat_type"):
            if getattr(data, k, None) is not None:
                class_key = k
                break
        if class_key is None and getattr(data, "threat_detected", None) is False:
            class_val = "BENIGN"
            class_present = True
        else:
            class_present = class_key is not None
            class_val = getattr(data, class_key, None) if class_present else None
        conf_val = getattr(data, "confidence", None)
        probs_val = getattr(data, "probabilities", None)
    else:
        result.is_valid = False
        result.is_missing = False
        result.is_malformed = True
        result.errors.append(
            ValidationErrorDetail(
                field="agent_1",
                message=f"Agent 1 payload must be a dict or dataclass, got {type(data).__name__}.",
                error_code="MALFORMED_INPUT",
                invalid_value=type(data).__name__,
                agent_id="agent_1",
            )
        )
        return result

    # 3. Validate threat class
    if not class_present:
        result.add_error(
            field="predicted_class",
            message="Agent 1 predicted class is missing.",
            error_code="MISSING_FIELD",
        )
    elif not isinstance(class_val, str):
        result.add_error(
            field="predicted_class",
            message=f"Agent 1 class must be a string, got {type(class_val).__name__}.",
            error_code="INVALID_CLASS",
            invalid_value=class_val,
        )
    else:
        norm_class = A1_CLASS_NORMALIZATION.get(class_val.strip().upper())
        if not norm_class:
            result.add_error(
                field="predicted_class",
                message=(
                    f"Invalid Agent 1 class '{class_val}'. "
                    f"Must be one of: {sorted(CANONICAL_A1_CLASSES)}"
                ),
                error_code="INVALID_CLASS",
                invalid_value=class_val,
            )

    # 4. Validate confidence
    if conf_val is None:
        result.add_error(
            field="confidence",
            message="Agent 1 confidence is missing.",
            error_code="MISSING_FIELD",
        )
    elif isinstance(conf_val, bool) or not isinstance(conf_val, (int, float)):
        result.add_error(
            field="confidence",
            message=f"Agent 1 confidence must be a number, got {type(conf_val).__name__}.",
            error_code="INVALID_CONFIDENCE",
            invalid_value=conf_val,
        )
    elif math.isnan(conf_val) or math.isinf(conf_val):
        result.add_error(
            field="confidence",
            message=f"Agent 1 confidence cannot be NaN or infinity, got {conf_val}.",
            error_code="NAN_OR_INFINITY",
            invalid_value=conf_val,
        )
    elif not (0.0 <= float(conf_val) <= 1.0):
        result.add_error(
            field="confidence",
            message=f"Agent 1 confidence must be in range [0.0, 1.0], got {conf_val}.",
            error_code="CONFIDENCE_OUT_OF_BOUNDS",
            invalid_value=conf_val,
        )

    # 5. Validate probabilities (if present)
    if probs_val is not None:
        if not isinstance(probs_val, dict):
            result.add_error(
                field="probabilities",
                message=f"Agent 1 probabilities must be a dict, got {type(probs_val).__name__}.",
                error_code="INVALID_PROBABILITIES",
                invalid_value=type(probs_val).__name__,
            )
        else:
            canonical_classes_seen: Set[str] = set()
            numeric_values: List[float] = []
            has_prob_value_error = False

            for raw_k, raw_v in probs_val.items():
                # Validate probability key
                if not isinstance(raw_k, str):
                    result.add_error(
                        field=f"probabilities.{raw_k}",
                        message=f"Probability key must be a string, got {type(raw_k).__name__}.",
                        error_code="INVALID_PROBABILITY_KEY",
                        invalid_value=raw_k,
                    )
                else:
                    k_norm = A1_CLASS_NORMALIZATION.get(raw_k.strip().upper())
                    if not k_norm:
                        result.add_error(
                            field=f"probabilities.{raw_k}",
                            message=(
                                f"Probability key '{raw_k}' is not an allowed class "
                                f"({sorted(CANONICAL_A1_CLASSES)})."
                            ),
                            error_code="INVALID_PROBABILITY_KEY",
                            invalid_value=raw_k,
                        )
                    else:
                        canonical_classes_seen.add(k_norm)

                # Validate probability value
                if isinstance(raw_v, bool) or not isinstance(raw_v, (int, float)):
                    result.add_error(
                        field=f"probabilities.{raw_k}",
                        message=f"Probability value must be a number, got {type(raw_v).__name__}.",
                        error_code="INVALID_PROBABILITY_VALUE",
                        invalid_value=raw_v,
                    )
                    has_prob_value_error = True
                elif math.isnan(raw_v) or math.isinf(raw_v):
                    result.add_error(
                        field=f"probabilities.{raw_k}",
                        message=f"Probability value cannot be NaN or infinity, got {raw_v}.",
                        error_code="NAN_OR_INFINITY",
                        invalid_value=raw_v,
                    )
                    has_prob_value_error = True
                elif not (0.0 <= float(raw_v) <= 1.0):
                    result.add_error(
                        field=f"probabilities.{raw_k}",
                        message=f"Probability value must be in range [0.0, 1.0], got {raw_v}.",
                        error_code="INVALID_PROBABILITY_VALUE",
                        invalid_value=raw_v,
                    )
                    has_prob_value_error = True
                else:
                    numeric_values.append(float(raw_v))

            # 6. Check sum if all five classes are present
            if len(canonical_classes_seen) == 5 and not has_prob_value_error:
                total_prob = sum(numeric_values)
                if not math.isclose(total_prob, 1.0, rel_tol=1e-2, abs_tol=1e-2):
                    result.add_error(
                        field="probabilities",
                        message=(
                            f"All five class probabilities present but sum to {total_prob:.4f}, "
                            f"expected approximately 1.0."
                        ),
                        error_code="PROBABILITY_SUM_MISMATCH",
                        invalid_value=total_prob,
                    )

    result.validated_data = data
    return result


def validate_agent2_output(data: Any) -> ValidationResult:
    """Validate Agent 2 anomaly assessment output.

    Validation rules:
      1. Distinguishes missing input (data is None) from malformed input.
      2. Anomaly status must conform to documented interface (boolean or valid AgentStatus).
      3. Anomaly score must be a finite non-negative number.
         NEVER assume anomaly score is a probability (scores > 1.0 are valid).
      4. Reject NaN and infinity.
      5. Evidence must be a list of strings.

    Args:
        data: Agent2AnomalyAssessment, A2DetectionResult, or dict.

    Returns:
        ValidationResult with status and structured error details.
    """
    result = ValidationResult(is_valid=True, agent_id="agent_2")

    # 1. Distinguish missing agent output
    if data is None:
        result.is_valid = False
        result.is_missing = True
        result.is_malformed = False
        result.errors.append(
            ValidationErrorDetail(
                field="agent_2",
                message="Agent 2 output is missing or unavailable.",
                error_code="MISSING_AGENT",
                agent_id="agent_2",
            )
        )
        return result

    # 2. Extract fields from dict or object
    if isinstance(data, dict):
        raw_dict = data
        if not raw_dict:
            result.is_valid = False
            result.is_missing = False
            result.is_malformed = True
            result.errors.append(
                ValidationErrorDetail(
                    field="agent_2",
                    message="Agent 2 payload is empty.",
                    error_code="MALFORMED_INPUT",
                    agent_id="agent_2",
                )
            )
            return result

        score_val = raw_dict.get("anomaly_score")
        detected_val = (
            raw_dict.get("anomaly_detected")
            if "anomaly_detected" in raw_dict
            else raw_dict.get("is_anomaly")
        )
        status_val = raw_dict.get("status")
        evidence_val = raw_dict.get("evidence")
    elif hasattr(data, "__dataclass_fields__") or hasattr(data, "anomaly_score"):
        score_val = getattr(data, "anomaly_score", None)
        detected_val = getattr(data, "anomaly_detected", None)
        status_val = getattr(data, "status", None)
        evidence_val = getattr(data, "evidence", None)
    else:
        result.is_valid = False
        result.is_missing = False
        result.is_malformed = True
        result.errors.append(
            ValidationErrorDetail(
                field="agent_2",
                message=f"Agent 2 payload must be a dict or dataclass, got {type(data).__name__}.",
                error_code="MALFORMED_INPUT",
                invalid_value=type(data).__name__,
                agent_id="agent_2",
            )
        )
        return result

    # 3. Validate anomaly status
    if detected_val is not None:
        if not isinstance(detected_val, bool):
            result.add_error(
                field="anomaly_detected",
                message=f"Anomaly detected flag must be a boolean, got {type(detected_val).__name__}.",
                error_code="INVALID_ANOMALY_STATUS",
                invalid_value=detected_val,
            )

    if status_val is not None:
        valid_status_tokens = {
            "SUCCESS", "NOT_DETECTED", "TIMED_OUT", "ERROR", "UNAVAILABLE",
            "ANOMALOUS", "NORMAL", "BENIGN", "ANOMALY", "UNKNOWN",
        }
        st_str = status_val.value if hasattr(status_val, "value") else str(status_val)
        if not isinstance(status_val, (str, Enum)) or st_str.upper() not in valid_status_tokens:
            result.add_error(
                field="status",
                message=f"Invalid Agent 2 status '{status_val}'.",
                error_code="INVALID_STATUS",
                invalid_value=status_val,
            )

    # 4. Validate anomaly score
    if score_val is None:
        result.add_error(
            field="anomaly_score",
            message="Agent 2 anomaly_score is missing.",
            error_code="MISSING_FIELD",
        )
    elif isinstance(score_val, bool) or not isinstance(score_val, (int, float)):
        result.add_error(
            field="anomaly_score",
            message=f"Agent 2 anomaly_score must be a number, got {type(score_val).__name__}.",
            error_code="INVALID_ANOMALY_SCORE",
            invalid_value=score_val,
        )
    elif math.isnan(score_val) or math.isinf(score_val):
        result.add_error(
            field="anomaly_score",
            message=f"Agent 2 anomaly_score cannot be NaN or infinity, got {score_val}.",
            error_code="NAN_OR_INFINITY",
            invalid_value=score_val,
        )
    elif float(score_val) < 0.0:
        result.add_error(
            field="anomaly_score",
            message=f"Agent 2 anomaly_score must be non-negative (>= 0.0), got {score_val}.",
            error_code="SCORE_OUT_OF_BOUNDS",
            invalid_value=score_val,
        )
    # Note: We deliberately DO NOT check score_val <= 1.0 because anomaly scores
    # are not probabilities (e.g., reconstruction loss or Mahalanobis distance).

    # 5. Validate evidence
    if evidence_val is not None:
        if not isinstance(evidence_val, list):
            result.add_error(
                field="evidence",
                message=f"Agent 2 evidence must be a list of strings, got {type(evidence_val).__name__}.",
                error_code="INVALID_EVIDENCE_TYPE",
                invalid_value=type(evidence_val).__name__,
            )
        else:
            non_str_items = [item for item in evidence_val if not isinstance(item, str)]
            if non_str_items:
                result.add_error(
                    field="evidence",
                    message=(
                        f"All items in Agent 2 evidence list must be strings. "
                        f"Found invalid item types: {[type(x).__name__ for x in non_str_items]}."
                    ),
                    error_code="INVALID_EVIDENCE_ITEM",
                    invalid_value=non_str_items,
                )

    result.validated_data = data
    return result


def validate_fusion_input(data: Any, strict: bool = False) -> ValidationResult:
    """Validate combined fusion input ingested by Agent 3.

    Validates:
      1. Overall payload structure and FlowContext requirements.
      2. Validates Agent 1 output (if present) via validate_agent1_output.
      3. Validates Agent 2 output (if present) via validate_agent2_output.
      4. Distinguishes missing agents from malformed agents.
      5. Never converts missing evidence or agents to BENIGN.

    Args:
        data: Agent3FusionInput, Agent3Input, or dict.
        strict: If True, requires both A1 and A2 to be present and valid.

    Returns:
        ValidationResult summarizing multi-agent input validity and details.
    """
    result = ValidationResult(is_valid=True, agent_id="agent_3")

    if data is None:
        result.is_valid = False
        result.is_missing = True
        result.is_malformed = False
        result.errors.append(
            ValidationErrorDetail(
                field="fusion_input",
                message="Fusion input payload is None.",
                error_code="MISSING_INPUT",
                agent_id="agent_3",
            )
        )
        return result

    # Extract components
    if isinstance(data, dict):
        flow_raw = data.get("flow_context")
        a1_data = data.get("a1_prediction") if "a1_prediction" in data else data.get("a1_result")
        a2_data = data.get("a2_assessment") if "a2_assessment" in data else data.get("a2_result")
    elif hasattr(data, "flow_context"):
        flow_raw = getattr(data, "flow_context", None)
        a1_data = getattr(data, "a1_prediction", None) or getattr(data, "a1_result", None)
        a2_data = getattr(data, "a2_assessment", None) or getattr(data, "a2_result", None)
    else:
        result.is_valid = False
        result.is_missing = False
        result.is_malformed = True
        result.errors.append(
            ValidationErrorDetail(
                field="fusion_input",
                message=f"Fusion input must be a dict or dataclass, got {type(data).__name__}.",
                error_code="MALFORMED_INPUT",
                invalid_value=type(data).__name__,
                agent_id="agent_3",
            )
        )
        return result

    # Validate FlowContext
    if flow_raw is None:
        result.add_error(
            field="flow_context",
            message="flow_context is required for fusion.",
            error_code="MISSING_FLOW_CONTEXT",
        )
    else:
        if isinstance(flow_raw, dict):
            flow_id = flow_raw.get("flow_id")
            ts = flow_raw.get("timestamp")
            src_ip = flow_raw.get("src_ip")
            src_port = flow_raw.get("src_port")
            dst_ip = flow_raw.get("dst_ip")
            dst_port = flow_raw.get("dst_port")
            proto = flow_raw.get("protocol")
        else:
            flow_id = getattr(flow_raw, "flow_id", None)
            ts = getattr(flow_raw, "timestamp", None)
            src_ip = getattr(flow_raw, "src_ip", None)
            src_port = getattr(flow_raw, "src_port", None)
            dst_ip = getattr(flow_raw, "dst_ip", None)
            dst_port = getattr(flow_raw, "dst_port", None)
            proto = getattr(flow_raw, "protocol", None)

        if not flow_id or not isinstance(flow_id, str):
            result.add_error("flow_context.flow_id", "flow_id must be a non-empty string.", "INVALID_FLOW_CONTEXT", flow_id)
        if not ts or not isinstance(ts, str):
            result.add_error("flow_context.timestamp", "timestamp must be a non-empty string.", "INVALID_FLOW_CONTEXT", ts)
        if not src_ip or not dst_ip:
            result.add_error("flow_context.ips", "src_ip and dst_ip must not be empty.", "INVALID_FLOW_CONTEXT")
        if (
            isinstance(src_port, bool)
            or not isinstance(src_port, int)
            or not (0 <= src_port <= 65535)
        ):
            result.add_error("flow_context.src_port", f"src_port must be in [0, 65535], got {src_port}.", "INVALID_FLOW_CONTEXT", src_port)
        if (
            isinstance(dst_port, bool)
            or not isinstance(dst_port, int)
            or not (0 <= dst_port <= 65535)
        ):
            result.add_error("flow_context.dst_port", f"dst_port must be in [0, 65535], got {dst_port}.", "INVALID_FLOW_CONTEXT", dst_port)
        if not proto:
            result.add_error("flow_context.protocol", "protocol must not be empty.", "INVALID_FLOW_CONTEXT", proto)

    # Validate Agent 1
    if a1_data is None:
        result.details["a1_status"] = "MISSING"
        result.details["a1_missing"] = True
        result.details["a1_malformed"] = False
        if strict:
            result.add_error("agent_1", "Strict mode enabled: Agent 1 output is required.", "MISSING_AGENT", agent_id="agent_1")
    else:
        a1_res = validate_agent1_output(a1_data)
        if not a1_res.is_valid:
            result.is_valid = False
            result.errors.extend(a1_res.errors)
            if a1_res.is_malformed:
                result.is_malformed = True
                result.details["a1_status"] = "MALFORMED"
                result.details["a1_malformed"] = True
        else:
            result.details["a1_status"] = "VALID"
            result.details["a1_missing"] = False
            result.details["a1_malformed"] = False

    # Validate Agent 2
    if a2_data is None:
        result.details["a2_status"] = "MISSING"
        result.details["a2_missing"] = True
        result.details["a2_malformed"] = False
        if strict:
            result.add_error("agent_2", "Strict mode enabled: Agent 2 output is required.", "MISSING_AGENT", agent_id="agent_2")
    else:
        a2_res = validate_agent2_output(a2_data)
        if not a2_res.is_valid:
            result.is_valid = False
            result.errors.extend(a2_res.errors)
            if a2_res.is_malformed:
                result.is_malformed = True
                result.details["a2_status"] = "MALFORMED"
                result.details["a2_malformed"] = True
        else:
            result.details["a2_status"] = "VALID"
            result.details["a2_missing"] = False
            result.details["a2_malformed"] = False

    # Derive overall fusion status in details
    a1_ok = result.details.get("a1_status") == "VALID"
    a2_ok = result.details.get("a2_status") == "VALID"

    if a1_ok and a2_ok:
        result.details["fusion_mode"] = "DUAL_AGENT"
    elif a1_ok and not a2_ok:
        result.details["fusion_mode"] = "SINGLE_AGENT_A1_ONLY"
    elif not a1_ok and a2_ok:
        result.details["fusion_mode"] = "SINGLE_AGENT_A2_ONLY"
    else:
        result.details["fusion_mode"] = "NO_AGENT_DATA"

    result.validated_data = data
    return result
