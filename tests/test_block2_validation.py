"""Comprehensive unit tests for Block 2: Input Validation and Data Schemas."""

import math
import pytest

from cybersentinel.agent3 import (
    A1DetectionResult,
    A2DetectionResult,
    Agent1ThreatPrediction,
    Agent2AnomalyAssessment,
    Agent3FusionInput,
    Agent3Input,
    AgentStatus,
    FlowContext,
    SchemaValidationError,
    validate_agent1_output,
    validate_agent2_output,
    validate_fusion_input,
)


@pytest.fixture
def valid_flow() -> FlowContext:
    return FlowContext(
        flow_id="flow-blk2-001",
        timestamp="2026-10-30T15:00:00Z",
        src_ip="192.168.1.50",
        src_port=54321,
        dst_ip="10.0.0.1",
        dst_port=443,
        protocol="TCP",
        packet_count=200,
        byte_count=102400,
    )


# -----------------------------------------------------------------------------
# 1. Valid inputs
# -----------------------------------------------------------------------------
def test_valid_agent1_inputs():
    """Verify valid Agent 1 inputs for all allowed classes and boundary confidences."""
    allowed_classes = ["BENIGN", "BRUTE FORCE", "DOS", "DDOS", "PORT SCAN", "BRUTE_FORCE", "PORT_SCAN"]
    for cls_name in allowed_classes:
        res = validate_agent1_output({
            "predicted_class": cls_name,
            "confidence": 0.85,
        })
        assert res.is_valid is True
        assert res.is_missing is False
        assert res.is_malformed is False
        assert len(res.errors) == 0

    # Dataclass with valid probabilities summing to 1.0
    a1 = Agent1ThreatPrediction(
        predicted_class="PORT SCAN",
        confidence=0.92,
        probabilities={
            "BENIGN": 0.02,
            "BRUTE FORCE": 0.01,
            "DOS": 0.02,
            "DDOS": 0.03,
            "PORT SCAN": 0.92,
        },
    )
    res = validate_agent1_output(a1)
    assert res.is_valid is True
    assert a1.threat_detected is True
    assert a1.threat_class == "PORT SCAN"


def test_valid_agent2_inputs():
    """Verify valid Agent 2 inputs including anomaly scores > 1.0 (non-probability)."""
    # Anomaly score > 1.0 is valid because anomaly scores are not probabilities
    valid_scores = [0.0, 0.45, 1.0, 5.8, 120.5]
    for score in valid_scores:
        res = validate_agent2_output({
            "anomaly_score": score,
            "anomaly_detected": score > 1.0,
            "evidence": ["abnormal burst size", "entropy ratio 0.94"],
        })
        assert res.is_valid is True
        assert res.is_missing is False
        assert res.is_malformed is False

    # Dataclass with empty evidence list
    a2 = Agent2AnomalyAssessment(
        anomaly_score=0.15,
        anomaly_detected=False,
        evidence=[],
    )
    res = validate_agent2_output(a2)
    assert res.is_valid is True


def test_valid_fusion_input(valid_flow):
    """Verify valid combined fusion input."""
    a1 = Agent1ThreatPrediction(predicted_class="DOS", confidence=0.88)
    a2 = Agent2AnomalyAssessment(anomaly_score=2.4, anomaly_detected=True, evidence=["high pps"])

    fusion_in = Agent3FusionInput(
        flow_context=valid_flow,
        a1_prediction=a1,
        a2_assessment=a2,
    )
    res = validate_fusion_input(fusion_in)
    assert res.is_valid is True
    assert res.details["fusion_mode"] == "DUAL_AGENT"
    assert res.details["a1_status"] == "VALID"
    assert res.details["a2_status"] == "VALID"


# -----------------------------------------------------------------------------
# 2. Invalid classes
# -----------------------------------------------------------------------------
def test_invalid_classes():
    """Verify rejection of classes outside {BENIGN, BRUTE FORCE, DOS, DDOS, PORT SCAN}."""
    invalid_classes = ["MALWARE", "UNKNOWN", "RANSOMWARE", "BOTNET", "EXPLOIT", "", None, 123]
    for bad_cls in invalid_classes:
        res = validate_agent1_output({
            "predicted_class": bad_cls,
            "confidence": 0.8,
        })
        assert res.is_valid is False
        assert res.has_error("INVALID_CLASS")
        err = [e for e in res.errors if e.error_code == "INVALID_CLASS"][0]
        assert err.field == "predicted_class"
        assert err.agent_id == "agent_1"


# -----------------------------------------------------------------------------
# 3. Invalid confidence
# -----------------------------------------------------------------------------
def test_invalid_confidence():
    """Verify rejection of confidence outside [0.0, 1.0] and non-numeric types."""
    bad_confidences = [-0.1, -1.0, 1.05, 2.0, "0.95", True, False, None]
    for bad_conf in bad_confidences:
        res = validate_agent1_output({
            "predicted_class": "BENIGN",
            "confidence": bad_conf,
        })
        assert res.is_valid is False
        assert (
            res.has_error("CONFIDENCE_OUT_OF_BOUNDS")
            or res.has_error("INVALID_CONFIDENCE")
            or res.has_error("MISSING_FIELD")
        )


# -----------------------------------------------------------------------------
# 4. NaN / Infinity
# -----------------------------------------------------------------------------
def test_nan_and_infinity():
    """Verify rejection of NaN and Infinity across all numeric fields."""
    # A1 confidence NaN / inf
    for bad_val in [float("nan"), float("inf"), float("-inf")]:
        res_a1 = validate_agent1_output({
            "predicted_class": "BENIGN",
            "confidence": bad_val,
        })
        assert res_a1.is_valid is False
        assert res_a1.has_error("NAN_OR_INFINITY")

    # A1 probability values with NaN / inf
    res_prob = validate_agent1_output({
        "predicted_class": "BENIGN",
        "confidence": 0.5,
        "probabilities": {"BENIGN": float("nan")},
    })
    assert res_prob.is_valid is False
    assert res_prob.has_error("NAN_OR_INFINITY")

    # A2 anomaly score NaN / inf
    for bad_val in [float("nan"), float("inf"), float("-inf")]:
        res_a2 = validate_agent2_output({
            "anomaly_score": bad_val,
            "anomaly_detected": False,
        })
        assert res_a2.is_valid is False
        assert res_a2.has_error("NAN_OR_INFINITY")


# -----------------------------------------------------------------------------
# 5. Invalid probabilities
# -----------------------------------------------------------------------------
def test_invalid_probabilities():
    """Verify validation of probability dictionary types, keys, and values."""
    # Probabilities is not a dictionary
    res = validate_agent1_output({
        "predicted_class": "BENIGN",
        "confidence": 0.5,
        "probabilities": [0.1, 0.9],
    })
    assert res.is_valid is False
    assert res.has_error("INVALID_PROBABILITIES")

    # Invalid probability key
    res = validate_agent1_output({
        "predicted_class": "BENIGN",
        "confidence": 0.5,
        "probabilities": {"SQL_INJECTION": 0.8},
    })
    assert res.is_valid is False
    assert res.has_error("INVALID_PROBABILITY_KEY")

    # Invalid probability values (out of range or non-numeric)
    bad_prob_values = [-0.1, 1.5, "0.5", True, None]
    for bad_val in bad_prob_values:
        res = validate_agent1_output({
            "predicted_class": "BENIGN",
            "confidence": 0.5,
            "probabilities": {"BENIGN": bad_val},
        })
        assert res.is_valid is False
        assert res.has_error("INVALID_PROBABILITY_VALUE")


# -----------------------------------------------------------------------------
# 6. Probability sum mismatch
# -----------------------------------------------------------------------------
def test_probability_sum_mismatch():
    """Verify that if all 5 probabilities are present, sum must be approx 1.0."""
    # Sum is 0.60 (mismatch)
    res_under = validate_agent1_output({
        "predicted_class": "DOS",
        "confidence": 0.6,
        "probabilities": {
            "BENIGN": 0.1,
            "BRUTE FORCE": 0.1,
            "DOS": 0.2,
            "DDOS": 0.1,
            "PORT SCAN": 0.1,
        },
    })
    assert res_under.is_valid is False
    assert res_under.has_error("PROBABILITY_SUM_MISMATCH")

    # Sum is 1.40 (mismatch)
    res_over = validate_agent1_output({
        "predicted_class": "DOS",
        "confidence": 0.6,
        "probabilities": {
            "BENIGN": 0.3,
            "BRUTE FORCE": 0.3,
            "DOS": 0.4,
            "DDOS": 0.2,
            "PORT SCAN": 0.2,
        },
    })
    assert res_over.is_valid is False
    assert res_over.has_error("PROBABILITY_SUM_MISMATCH")

    # Sum is 0.999 (within tolerance) -> valid
    res_close = validate_agent1_output({
        "predicted_class": "DOS",
        "confidence": 0.6,
        "probabilities": {
            "BENIGN": 0.2,
            "BRUTE FORCE": 0.2,
            "DOS": 0.2,
            "DDOS": 0.2,
            "PORT SCAN": 0.199,
        },
    })
    assert res_close.is_valid is True


# -----------------------------------------------------------------------------
# 7. Invalid anomaly score
# -----------------------------------------------------------------------------
def test_invalid_anomaly_score():
    """Verify rejection of negative anomaly scores and non-numeric scores."""
    # Negative scores
    for bad_score in [-0.01, -1.0, -50.0]:
        res = validate_agent2_output({
            "anomaly_score": bad_score,
            "anomaly_detected": False,
        })
        assert res.is_valid is False
        assert res.has_error("SCORE_OUT_OF_BOUNDS")

    # Non-numeric scores
    for bad_score in ["0.85", True, False, [1.0]]:
        res = validate_agent2_output({
            "anomaly_score": bad_score,
            "anomaly_detected": False,
        })
        assert res.is_valid is False
        assert res.has_error("INVALID_ANOMALY_SCORE")

    # Confirm non-probability scores (> 1.0) are NOT rejected
    res_high = validate_agent2_output({
        "anomaly_score": 14.8,
        "anomaly_detected": True,
        "evidence": ["reconstruction error 14.8"],
    })
    assert res_high.is_valid is True


# -----------------------------------------------------------------------------
# 8. Wrong evidence types
# -----------------------------------------------------------------------------
def test_wrong_evidence_types():
    """Verify that evidence must be a list of strings."""
    # Evidence is a string instead of a list
    res_str = validate_agent2_output({
        "anomaly_score": 0.5,
        "evidence": "abnormal connection count",
    })
    assert res_str.is_valid is False
    assert res_str.has_error("INVALID_EVIDENCE_TYPE")

    # Evidence is an int
    res_int = validate_agent2_output({
        "anomaly_score": 0.5,
        "evidence": 42,
    })
    assert res_int.is_valid is False
    assert res_int.has_error("INVALID_EVIDENCE_TYPE")

    # Evidence contains non-string items
    bad_lists = [
        [123, 456],
        ["valid indicator", None],
        ["valid indicator", 99.9],
        [True],
    ]
    for bad_list in bad_lists:
        res_list = validate_agent2_output({
            "anomaly_score": 0.5,
            "evidence": bad_list,
        })
        assert res_list.is_valid is False
        assert res_list.has_error("INVALID_EVIDENCE_ITEM")


# -----------------------------------------------------------------------------
# 9. Missing Agent 1 or Agent 2
# -----------------------------------------------------------------------------
def test_missing_agent_handling(valid_flow):
    """Verify distinguishing missing agents from malformed agents, and no conversion to BENIGN."""
    # A1 missing
    res_a1_none = validate_agent1_output(None)
    assert res_a1_none.is_valid is False
    assert res_a1_none.is_missing is True
    assert res_a1_none.is_malformed is False
    assert res_a1_none.has_error("MISSING_AGENT")

    # A2 missing
    res_a2_none = validate_agent2_output(None)
    assert res_a2_none.is_valid is False
    assert res_a2_none.is_missing is True
    assert res_a2_none.is_malformed is False
    assert res_a2_none.has_error("MISSING_AGENT")

    # Missing A1 in fusion input (graceful degradation)
    a2 = Agent2AnomalyAssessment(anomaly_score=0.9, anomaly_detected=True, evidence=["beaconing"])
    fusion_missing_a1 = Agent3FusionInput(
        flow_context=valid_flow,
        a1_prediction=None,
        a2_assessment=a2,
    )
    res_fusion = validate_fusion_input(fusion_missing_a1, strict=False)
    assert res_fusion.is_valid is True
    assert res_fusion.details["a1_status"] == "MISSING"
    assert res_fusion.details["a1_missing"] is True
    assert res_fusion.details["fusion_mode"] == "SINGLE_AGENT_A2_ONLY"

    # Strict mode rejects missing agent
    res_strict = validate_fusion_input(fusion_missing_a1, strict=True)
    assert res_strict.is_valid is False
    assert res_strict.has_error("MISSING_AGENT")

    # Ensure missing evidence does NOT convert to BENIGN
    a2_empty_evidence = Agent2AnomalyAssessment(anomaly_score=1.5, anomaly_detected=True, evidence=[])
    assert a2_empty_evidence.anomaly_detected is True


# -----------------------------------------------------------------------------
# 10. Malformed input
# -----------------------------------------------------------------------------
def test_malformed_input(valid_flow):
    """Verify distinguishing malformed input from missing input."""
    # Empty dictionary is malformed, not missing
    res_empty_a1 = validate_agent1_output({})
    assert res_empty_a1.is_valid is False
    assert res_empty_a1.is_malformed is True
    assert res_empty_a1.is_missing is False
    assert res_empty_a1.has_error("MALFORMED_INPUT")

    res_empty_a2 = validate_agent2_output({})
    assert res_empty_a2.is_valid is False
    assert res_empty_a2.is_malformed is True
    assert res_empty_a2.is_missing is False
    assert res_empty_a2.has_error("MALFORMED_INPUT")

    # Unsupported data types
    res_int = validate_agent1_output(42)
    assert res_int.is_malformed is True
    assert res_int.has_error("MALFORMED_INPUT")

    # Malformed FlowContext in fusion
    bad_flow_port = FlowContext(
        flow_id="f1",
        timestamp="2026-10-30T10:00:00Z",
        src_ip="1.1.1.1",
        src_port=70000,  # Invalid port
        dst_ip="2.2.2.2",
        dst_port=80,
        protocol="TCP",
    )
    res_bad_flow = validate_fusion_input({"flow_context": bad_flow_port})
    assert res_bad_flow.is_valid is False
    assert res_bad_flow.has_error("INVALID_FLOW_CONTEXT")


# -----------------------------------------------------------------------------
# 11. Schema methods, serialization & exception raising
# -----------------------------------------------------------------------------
def test_schema_methods_and_exceptions(valid_flow):
    """Verify schema validate(raise_on_error=True) and serialization roundtrips."""
    # Agent1 validate raise_on_error
    bad_a1 = Agent1ThreatPrediction(predicted_class="INVALID_THREAT", confidence=0.8)
    with pytest.raises(SchemaValidationError) as exc_info:
        bad_a1.validate(raise_on_error=True)
    assert exc_info.value.validation_result.has_error("INVALID_CLASS")

    # Agent2 validate raise_on_error
    bad_a2 = Agent2AnomalyAssessment(anomaly_score=-5.0)
    with pytest.raises(SchemaValidationError) as exc_info:
        bad_a2.validate(raise_on_error=True)
    assert exc_info.value.validation_result.has_error("SCORE_OUT_OF_BOUNDS")

    # Roundtrip serialization
    good_a1 = Agent1ThreatPrediction(predicted_class="DDOS", confidence=0.95, probabilities={"DDOS": 0.95})
    d1 = good_a1.to_dict()
    reloaded_a1 = Agent1ThreatPrediction.from_dict(d1)
    assert reloaded_a1.predicted_class == "DDOS"
    assert reloaded_a1.confidence == 0.95

    good_a2 = Agent2AnomalyAssessment(anomaly_score=3.2, anomaly_detected=True, evidence=["syn flag"])
    d2 = good_a2.to_dict()
    reloaded_a2 = Agent2AnomalyAssessment.from_dict(d2)
    assert reloaded_a2.anomaly_score == 3.2
    assert reloaded_a2.evidence == ["syn flag"]

