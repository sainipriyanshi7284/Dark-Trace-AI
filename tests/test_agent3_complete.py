"""Exhaustive unit and pipeline integration tests for Agent 3 Complete Implementation.

Covers all 14 required verification scenarios:
  1. Both agents agree on malicious traffic.
  2. Both agents agree on benign traffic.
  3. BENIGN prediction with strong anomaly (Safeguard 1).
  4. Attack prediction with low anomaly (Safeguard 2).
  5. Missing Agent 1 (Safeguard 3 & Renormalization).
  6. Missing Agent 2 (Safeguard 4 & Renormalization).
  7. Both agents missing (Safeguard 5 & INSUFFICIENT_EVIDENCE).
  8. Conflicting evidence handling.
  9. Invalid input handling & strict mode validation.
  10. Correct deterministic fusion score calculation.
  11. Missing evidence handling without zero-substitution.
  12. Explainability output & template-based narrative verification.
  13. Deterministic repeated execution.
  14. Complete process_flow execution with dicts, dataclasses, and serialization.
"""

import json
import math
import pytest

from cybersentinel.agent3 import (
    A1DetectionResult,
    A2DetectionResult,
    Agent1ThreatPrediction,
    Agent2AnomalyAssessment,
    Agent3Skeleton,
    Agent3ThreatAssessment,
    ConfidenceLevel,
    EvidenceStatus,
    ExplanationResult,
    FlowContext,
    FusionConfig,
    InvalidInputError,
    InvestigationPriority,
    MissingAgentError,
    RiskLevel,
    SchemaValidationError,
    ThreatExplainer,
    process_flow,
)


@pytest.fixture
def sample_flow() -> FlowContext:
    """Fixture providing standard flow context."""
    return FlowContext(
        flow_id="FLOW-COMPLETE-001",
        timestamp="2026-10-30T17:00:00Z",
        src_ip="192.168.10.50",
        src_port=52344,
        dst_ip="10.0.0.1",
        dst_port=443,
        protocol="TCP",
        packet_count=500,
        byte_count=250000,
    )


# =============================================================================
# 1. Both agents agree on malicious traffic
# =============================================================================
def test_both_agents_agree_on_malicious(sample_flow):
    """Scenario 1: Both agents corroborate malicious attack."""
    a1 = Agent1ThreatPrediction(
        predicted_class="DDOS",
        confidence=0.95,
        probabilities={"DDOS": 0.95, "BENIGN": 0.05},
        rule_id="RULE-DDOS-01",
    )
    a2 = Agent2AnomalyAssessment(
        anomaly_score=0.92,
        anomaly_detected=True,
        evidence=["extreme packet burst", "syn flood pattern"],
    )

    result = process_flow(a1, a2, flow_id=sample_flow.flow_id, flow_context=sample_flow)

    assert isinstance(result, Agent3ThreatAssessment)
    assert result.final_class == "DDOS"
    assert result.assessment == "MALICIOUS"
    assert result.agent_agreement is True
    assert result.evidence_status == EvidenceStatus.AGREEMENT.value
    assert result.risk_level == RiskLevel.CRITICAL.value
    assert result.investigation_priority == InvestigationPriority.CRITICAL.value
    assert result.confidence_level == ConfidenceLevel.HIGH.value
    assert result.fusion_score is not None and result.fusion_score >= 0.75
    assert len(result.supporting_evidence) > 0
    assert "DDOS" in result.reasoning
    assert "anomalous" in result.reasoning.lower()


# =============================================================================
# 2. Both agents agree on benign traffic
# =============================================================================
def test_both_agents_agree_on_benign(sample_flow):
    """Scenario 2: Both agents confirm clean benign traffic."""
    a1 = Agent1ThreatPrediction(
        predicted_class="BENIGN",
        confidence=0.96,
        probabilities={"BENIGN": 0.96, "DOS": 0.04},
    )
    a2 = Agent2AnomalyAssessment(
        anomaly_score=0.03,
        anomaly_detected=False,
        evidence=[],
    )

    result = process_flow(a1, a2, flow_id=sample_flow.flow_id, flow_context=sample_flow)

    assert result.final_class == "BENIGN"
    assert result.assessment == "BENIGN"
    assert result.agent_agreement is True
    assert result.evidence_status == EvidenceStatus.AGREEMENT.value
    assert result.risk_level == RiskLevel.LOW.value
    assert result.investigation_priority == InvestigationPriority.LOW.value
    assert result.confidence_level == ConfidenceLevel.HIGH.value
    assert result.fusion_score is not None and result.fusion_score < 0.25
    assert len(result.conflicting_evidence) == 0


# =============================================================================
# 3. BENIGN prediction with strong anomaly (Safeguard 1)
# =============================================================================
def test_benign_prediction_with_strong_anomaly(sample_flow):
    """Scenario 3: A1 BENIGN + strong A2 anomaly (zero-day/evasion safeguard)."""
    a1 = Agent1ThreatPrediction(
        predicted_class="BENIGN",
        confidence=0.92,
        probabilities={"BENIGN": 0.92, "PORT SCAN": 0.08},
    )
    a2 = Agent2AnomalyAssessment(
        anomaly_score=0.88,
        anomaly_detected=True,
        evidence=["dns payload exfiltration signature", "unusual entropy"],
    )

    result = process_flow(a1, a2, flow_id=sample_flow.flow_id, flow_context=sample_flow)

    assert result.agent_agreement is False
    assert result.evidence_status == EvidenceStatus.DISAGREEMENT.value
    assert result.final_class == "BENIGN"  # Never invent attack class from anomaly
    assert result.risk_level in (RiskLevel.HIGH.value, RiskLevel.CRITICAL.value)
    assert result.assessment == "SUSPICIOUS"
    assert result.confidence_level == ConfidenceLevel.LOW.value
    assert any("zero-day" in u.lower() or "disagreement" in u.lower() for u in result.uncertainty)
    assert "disagree" in result.reasoning.lower()


# =============================================================================
# 4. Attack prediction with low anomaly (Safeguard 2)
# =============================================================================
def test_attack_prediction_with_low_anomaly(sample_flow):
    """Scenario 4: A1 attack + low A2 anomaly (signature preservation safeguard)."""
    a1 = Agent1ThreatPrediction(
        predicted_class="PORT SCAN",
        confidence=0.88,
        probabilities={"PORT SCAN": 0.88, "BENIGN": 0.12},
    )
    a2 = Agent2AnomalyAssessment(
        anomaly_score=0.08,
        anomaly_detected=False,
        evidence=[],
    )

    result = process_flow(a1, a2, flow_id=sample_flow.flow_id, flow_context=sample_flow)

    assert result.agent_agreement is False
    assert result.evidence_status == EvidenceStatus.DISAGREEMENT.value
    # Preserves attack classification; never downgraded to BENIGN
    assert result.final_class == "PORT SCAN"
    assert result.assessment != "BENIGN"
    assert result.risk_level in (RiskLevel.MEDIUM.value, RiskLevel.HIGH.value)
    assert any("preserved" in u.lower() for u in result.uncertainty)


# =============================================================================
# 5. Missing Agent 1 (Safeguard 3 & Renormalization)
# =============================================================================
def test_missing_agent_1(sample_flow):
    """Scenario 5: Agent 1 missing yields UNKNOWN class and renormalizes weights."""
    a2 = Agent2AnomalyAssessment(
        anomaly_score=0.82,
        anomaly_detected=True,
        evidence=["high egress packet volume"],
    )

    result = process_flow(agent1_result=None, agent2_result=a2, flow_id=sample_flow.flow_id)

    assert result.final_class == "UNKNOWN"
    assert result.evidence_status == EvidenceStatus.PARTIAL_EVIDENCE.value
    assert result.score_breakdown["classifier_score"] is None
    assert result.score_breakdown["effective_weights"]["classifier"] == 0.0
    # Available weights sum to 1.0
    eff_w = result.score_breakdown["effective_weights"]
    assert pytest.approx(sum(eff_w.values()), abs=1e-3) == 1.0
    assert result.confidence_level == ConfidenceLevel.LOW.value
    assert any("missing agent 1" in u.lower() or "classifier unavailable" in u.lower() for u in result.uncertainty)


# =============================================================================
# 6. Missing Agent 2 (Safeguard 4 & Renormalization)
# =============================================================================
def test_missing_agent_2(sample_flow):
    """Scenario 6: Agent 2 missing results in partial classifier triage with SUSPICIOUS assessment."""
    a1 = Agent1ThreatPrediction(
        predicted_class="BRUTE FORCE",
        confidence=0.85,
        probabilities={"BRUTE FORCE": 0.85, "BENIGN": 0.15},
    )

    result = process_flow(agent1_result=a1, agent2_result=None, flow_id=sample_flow.flow_id)

    assert result.final_class == "BRUTE FORCE"
    assert result.assessment == "SUSPICIOUS"  # Uncorroborated single-agent detection
    assert result.score_breakdown["anomaly_score"] is None
    assert result.score_breakdown["effective_weights"]["anomaly"] == 0.0
    assert any("missing agent 2" in u.lower() for u in result.uncertainty)


# =============================================================================
# 7. Both agents missing (Safeguard 5 & INSUFFICIENT_EVIDENCE)
# =============================================================================
def test_both_agents_missing(sample_flow):
    """Scenario 7: Both agents missing yields INSUFFICIENT_EVIDENCE without fabricated score."""
    result = process_flow(agent1_result=None, agent2_result=None, flow_id=sample_flow.flow_id)

    assert result.evidence_status == EvidenceStatus.INSUFFICIENT_EVIDENCE.value
    assert result.fusion_score is None
    assert result.final_class == "UNKNOWN"
    assert result.assessment == "INCONCLUSIVE"
    assert result.risk_level == RiskLevel.UNKNOWN.value
    assert result.confidence_level == ConfidenceLevel.LOW.value
    assert "insufficient evidence" in result.reasoning.lower()


# =============================================================================
# 8. Conflicting evidence handling
# =============================================================================
def test_conflicting_evidence_handling(sample_flow):
    """Scenario 8: Conflicting evidence reduces confidence and populates conflicting_evidence."""
    a1 = {"predicted_class": "BENIGN", "confidence": 0.85}
    a2 = {"anomaly_score": 0.90, "anomaly_detected": True, "evidence": ["abnormal beaconing"]}

    result = process_flow(a1, a2, flow_id="FLOW-CONFLICT-1")

    assert result.agent_agreement is False
    assert result.confidence_level == ConfidenceLevel.LOW.value
    assert len(result.conflicting_evidence) > 0
    assert len(result.uncertainty) > 0


# =============================================================================
# 9. Invalid input handling & strict mode validation
# =============================================================================
def test_invalid_input_handling():
    """Scenario 9: Rejects invalid payloads and raises appropriate exceptions in strict mode."""
    # Invalid payload types
    with pytest.raises(InvalidInputError):
        process_flow(agent1_result="invalid_string_type", flow_id="FLOW-ERR-01")

    with pytest.raises(InvalidInputError):
        process_flow(agent1_result=12345, flow_id="FLOW-ERR-02")

    # Invalid flow context
    with pytest.raises(InvalidInputError):
        process_flow(flow_context="not_a_valid_flow_context")

    # Strict mode missing agent
    with pytest.raises(MissingAgentError):
        process_flow(agent1_result=None, agent2_result={"anomaly_score": 0.5}, strict_mode=True)

    # Strict mode invalid class
    with pytest.raises(SchemaValidationError):
        process_flow(
            agent1_result={"predicted_class": "INVALID_CLASS", "confidence": 0.8},
            agent2_result={"anomaly_score": 0.5, "anomaly_detected": False},
            strict_mode=True,
        )


# =============================================================================
# 10. Correct deterministic fusion score calculation
# =============================================================================
def test_correct_fusion_score_calculation(sample_flow):
    """Scenario 10: Verifies exact weighted score formula (0.50*C + 0.30*A + 0.20*R)."""
    # C = 1 - 0.20 = 0.80
    a1 = Agent1ThreatPrediction(predicted_class="DOS", confidence=0.80, probabilities={"DOS": 0.80, "BENIGN": 0.20})
    # A = 0.60
    a2 = Agent2AnomalyAssessment(anomaly_score=0.60, anomaly_detected=True)
    # R = 1.0 (Agreement on malicious)

    # Expected: 0.50*0.80 + 0.30*0.60 + 0.20*1.0 = 0.40 + 0.18 + 0.20 = 0.78
    result = process_flow(a1, a2, flow_id=sample_flow.flow_id)

    assert pytest.approx(result.fusion_score, abs=1e-4) == 0.78
    assert result.risk_level == RiskLevel.CRITICAL.value  # 0.78 >= 0.75 cutoff


# =============================================================================
# 11. Missing evidence handling without zero-substitution
# =============================================================================
def test_missing_evidence_handling_without_zero_substitution(sample_flow):
    """Scenario 11: Dynamic weight renormalization does not substitute 0 for missing sources."""
    a1 = Agent1ThreatPrediction(predicted_class="PORT SCAN", confidence=0.70)
    # A2 missing: available sources = classifier (0.50), correlation (0.20) -> sum = 0.70
    # Effective weights: classifier = 0.50/0.70 = 0.7143, correlation = 0.20/0.70 = 0.2857
    result = process_flow(a1, None, flow_id=sample_flow.flow_id)

    eff_w = result.score_breakdown["effective_weights"]
    assert eff_w["anomaly"] == 0.0
    assert pytest.approx(eff_w["classifier"], abs=1e-3) == 0.7143
    assert pytest.approx(eff_w["correlation"], abs=1e-3) == 0.2857
    assert pytest.approx(sum(eff_w.values()), abs=1e-3) == 1.0


# =============================================================================
# 12. Explainability output & template-based narrative verification
# =============================================================================
def test_explainability_output(sample_flow):
    """Scenario 12: ThreatExplainer produces transparent, comprehensive explanations."""
    explainer = ThreatExplainer()

    exp = explainer.explain(
        a1_present=True,
        a1_class="DDOS",
        a1_confidence=0.95,
        a1_probabilities={"DDOS": 0.95, "BENIGN": 0.05},
        a1_margin=0.90,
        a1_rule_id="RULE-DDOS-01",
        a2_present=True,
        a2_anomalous=True,
        a2_score=0.90,
        a2_evidence=["massive syn burst", "rate limit exceeded"],
        fusion_score=0.94,
        c_score=0.95,
        a_score=0.90,
        r_score=1.0,
        configured_weights={"classifier": 0.50, "anomaly": 0.30, "correlation": 0.20},
        effective_weights={"classifier": 0.50, "anomaly": 0.30, "correlation": 0.20},
        risk_level=RiskLevel.CRITICAL.value,
        confidence_level=ConfidenceLevel.HIGH.value,
        assessment="MALICIOUS",
        uncertainties=[],
        final_class="DDOS",
    )

    assert isinstance(exp, ExplanationResult)
    assert "DDOS" in exp.agent1_explanation
    assert "RULE-DDOS-01" in exp.agent1_explanation
    assert "anomalous" in exp.agent2_explanation.lower()
    assert "massive syn burst" in exp.agent2_explanation
    assert "0.94" in exp.scoring_explanation
    assert "CRITICAL" in exp.risk_explanation
    assert "DROP" in exp.investigation_recommendation
    assert "CRITICAL" in exp.summary
    assert len(exp.full_reasoning) > 100


# =============================================================================
# 13. Deterministic repeated execution
# =============================================================================
def test_deterministic_repeated_execution(sample_flow):
    """Scenario 13: 100 identical executions produce identical fusion scores and verdicts."""
    a1 = {"predicted_class": "DOS", "confidence": 0.77, "probabilities": {"DOS": 0.77, "BENIGN": 0.23}}
    a2 = {"anomaly_score": 0.65, "anomaly_detected": True, "evidence": ["packet anomaly"]}

    first_result = process_flow(a1, a2, flow_id=sample_flow.flow_id)

    for _ in range(100):
        iter_res = process_flow(a1, a2, flow_id=sample_flow.flow_id)
        assert iter_res.fusion_score == first_result.fusion_score
        assert iter_res.final_class == first_result.final_class
        assert iter_res.risk_level == first_result.risk_level
        assert iter_res.assessment == first_result.assessment
        assert iter_res.reasoning == first_result.reasoning


# =============================================================================
# 14. Complete process_flow execution with dicts, dataclasses & serialization
# =============================================================================
def test_complete_process_flow_execution():
    """Scenario 14: Tests process_flow with raw dicts and verifies serialization."""
    raw_a1 = {
        "predicted_class": "BRUTE FORCE",
        "confidence": 0.88,
        "probabilities": {"BRUTE FORCE": 0.88, "BENIGN": 0.12},
    }
    raw_a2 = {
        "anomaly_score": 0.75,
        "anomaly_detected": True,
        "evidence": ["repeated auth failures"],
    }

    assessment = process_flow(
        agent1_result=raw_a1,
        agent2_result=raw_a2,
        flow_id="FLOW-COMPLETE-14",
    )

    # 1. Check all required Section 7 fields
    d = assessment.to_dict()
    required_keys = [
        "agent_id",
        "flow_id",
        "final_class",
        "assessment",
        "evidence_status",
        "agent_agreement",
        "fusion_score",
        "risk_level",
        "confidence_level",
        "supporting_evidence",
        "conflicting_evidence",
        "uncertainty",
        "score_breakdown",
        "reasoning",
        "investigation_priority",
    ]
    for key in required_keys:
        assert key in d, f"Missing required key: {key}"

    # 2. Check JSON serialization
    json_str = assessment.to_json()
    assert json.loads(json_str) == d

    # 3. Check Block 1 Agent3Output backward compatibility conversion
    a3_out = assessment.to_agent3_output()
    assert a3_out.flow_id == "FLOW-COMPLETE-14"
    assert a3_out.fused_risk_score == assessment.fusion_score
    assert a3_out.verdict.value == assessment.assessment

    # 4. Check dictionary-like subscripting
    assert assessment["final_class"] == "BRUTE FORCE"
    assert assessment["risk_level"] == RiskLevel.CRITICAL.value

