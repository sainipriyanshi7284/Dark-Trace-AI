"""Comprehensive unit tests for Block 4: Intelligent Fusion Scoring Engine."""

import math
import pytest

from cybersentinel.agent3 import (
    A1DetectionResult,
    A2DetectionResult,
    Agent1ThreatPrediction,
    Agent2AnomalyAssessment,
    Agent3FusionInput,
    Agent3Skeleton,
    ConfidenceLevel,
    EvidenceStatus,
    FlowContext,
    FusionConfig,
    FusionResult,
    FusionScorer,
    InvestigationPriority,
    RiskLevel,
    compute_fusion_score,
)


@pytest.fixture
def flow() -> FlowContext:
    return FlowContext(
        flow_id="FLOW-BLK4-001",
        timestamp="2026-10-30T16:30:00Z",
        src_ip="192.168.10.15",
        src_port=49152,
        dst_ip="10.0.0.1",
        dst_port=443,
        protocol="TCP",
    )


@pytest.fixture
def default_scorer() -> FusionScorer:
    return FusionScorer()


# -----------------------------------------------------------------------------
# 1. Both agents strongly indicate malicious traffic
# -----------------------------------------------------------------------------
def test_both_agents_strongly_malicious(default_scorer, flow):
    """Verify consensus when both agents strongly detect attack."""
    a1 = Agent1ThreatPrediction(
        predicted_class="DDOS",
        confidence=0.95,
        probabilities={"DDOS": 0.95, "BENIGN": 0.05},
    )
    a2 = Agent2AnomalyAssessment(
        anomaly_score=0.90,
        anomaly_detected=True,
        evidence=["massive syn burst", "pps threshold exceeded"],
    )

    res = default_scorer.score(flow_context=flow, a1_prediction=a1, a2_assessment=a2)

    # C = 1 - 0.05 = 0.95; A = 0.90; R = 1.0 (agreement malicious)
    # Score = 0.50*0.95 + 0.30*0.90 + 0.20*1.0 = 0.475 + 0.27 + 0.20 = 0.945
    assert res.classifier_score == 0.95
    assert res.anomaly_score_normalized == 0.90
    assert res.correlation_score == 1.0
    assert pytest.approx(res.fusion_score, abs=1e-3) == 0.945
    assert res.final_class == "DDOS"
    assert res.assessment == "MALICIOUS"
    assert res.risk_level == RiskLevel.CRITICAL.value
    assert res.confidence_level == ConfidenceLevel.HIGH.value
    assert res.investigation_priority == InvestigationPriority.CRITICAL.value
    assert res.agent_agreement is True


# -----------------------------------------------------------------------------
# 2. Both agents support benign traffic
# -----------------------------------------------------------------------------
def test_both_agents_support_benign(default_scorer, flow):
    """Verify consensus when both agents report clean baseline traffic."""
    a1 = Agent1ThreatPrediction(
        predicted_class="BENIGN",
        confidence=0.96,
        probabilities={"BENIGN": 0.96, "DOS": 0.04},
    )
    a2 = Agent2AnomalyAssessment(
        anomaly_score=0.04,
        anomaly_detected=False,
        evidence=[],
    )

    res = default_scorer.score(flow_context=flow, a1_prediction=a1, a2_assessment=a2)

    # C = 1 - 0.96 = 0.04; A = 0.04; R = 0.0 (agreement benign)
    # Score = 0.50*0.04 + 0.30*0.04 + 0.20*0.0 = 0.02 + 0.012 = 0.032
    assert res.classifier_score == 0.04
    assert res.anomaly_score_normalized == 0.04
    assert res.correlation_score == 0.0
    assert pytest.approx(res.fusion_score, abs=1e-3) == 0.032
    assert res.final_class == "BENIGN"
    assert res.assessment == "BENIGN"
    assert res.risk_level == RiskLevel.LOW.value
    assert res.confidence_level == ConfidenceLevel.HIGH.value
    assert res.investigation_priority == InvestigationPriority.LOW.value


# -----------------------------------------------------------------------------
# 3. A1 BENIGN + strong A2 anomaly (Safeguard 1)
# -----------------------------------------------------------------------------
def test_a1_benign_strong_a2_anomaly(default_scorer, flow):
    """Verify Safeguard 1: A1 BENIGN + strong A2 anomaly elevates risk to at least HIGH."""
    a1 = Agent1ThreatPrediction(
        predicted_class="BENIGN",
        confidence=0.90,
        probabilities={"BENIGN": 0.90, "PORT SCAN": 0.10},
    )
    a2 = Agent2AnomalyAssessment(
        anomaly_score=0.85,
        anomaly_detected=True,
        evidence=["irregular dns tunneling pattern", "high payload entropy"],
    )

    res = default_scorer.score(flow_context=flow, a1_prediction=a1, a2_assessment=a2)

    # C = 0.10, A = 0.85, R = 0.50 (disagreement)
    # Raw Score = 0.50*0.10 + 0.30*0.85 + 0.20*0.50 = 0.05 + 0.255 + 0.10 = 0.405
    # Raw score falls in MEDIUM (0.405), but Safeguard 1 enforces minimum risk level of HIGH!
    assert res.risk_level == RiskLevel.HIGH.value
    assert res.assessment == "SUSPICIOUS"
    assert res.final_class == "BENIGN"  # Preserves A1 classifier label without inventing an attack
    assert res.agent_agreement is False
    assert res.evidence_status == EvidenceStatus.DISAGREEMENT.value
    assert res.confidence_level == ConfidenceLevel.LOW.value  # Conflict reduces confidence
    assert any("Disagreement" in u for u in res.uncertainty)


# -----------------------------------------------------------------------------
# 4. A1 attack + low A2 anomaly (Safeguard 2)
# -----------------------------------------------------------------------------
def test_a1_attack_low_a2_anomaly(default_scorer, flow):
    """Verify Safeguard 2: Attack prediction from A1 is preserved and not downgraded to BENIGN."""
    a1 = Agent1ThreatPrediction(
        predicted_class="PORT SCAN",
        confidence=0.90,
        probabilities={"PORT SCAN": 0.90, "BENIGN": 0.10},
    )
    a2 = Agent2AnomalyAssessment(
        anomaly_score=0.10,
        anomaly_detected=False,
        evidence=[],
    )

    res = default_scorer.score(flow_context=flow, a1_prediction=a1, a2_assessment=a2)

    # Final class must retain PORT SCAN
    assert res.final_class == "PORT SCAN"
    assert res.assessment != "BENIGN"
    assert res.risk_level in (RiskLevel.HIGH.value, RiskLevel.MEDIUM.value)
    assert res.agent_agreement is False
    assert any("Malicious signature match is preserved" in u for u in res.uncertainty)


# -----------------------------------------------------------------------------
# 5. Missing A1 (Safeguard 3 & Renormalization)
# -----------------------------------------------------------------------------
def test_missing_a1(default_scorer, flow):
    """Verify Safeguard 3: Missing A1 returns UNKNOWN class and renormalizes weights."""
    a2 = Agent2AnomalyAssessment(
        anomaly_score=0.80,
        anomaly_detected=True,
        evidence=["unusual egress volume"],
    )

    res = default_scorer.score(flow_context=flow, a1_prediction=None, a2_assessment=a2)

    assert res.final_class == "UNKNOWN"
    assert res.classifier_score is None
    assert res.anomaly_score_normalized == 0.80
    assert res.correlation_score == 0.5  # Partial evidence
    # Available weights: anomaly (0.30) + correlation (0.20) = 0.50
    # Expected score: (0.30*0.80 + 0.20*0.50) / 0.50 = (0.24 + 0.10) / 0.50 = 0.68
    assert pytest.approx(res.fusion_score, abs=1e-3) == 0.68
    assert res.effective_weights["classifier"] == 0.0
    assert pytest.approx(res.effective_weights["anomaly"], abs=1e-3) == 0.60
    assert pytest.approx(res.effective_weights["correlation"], abs=1e-3) == 0.40
    assert res.confidence_level == ConfidenceLevel.LOW.value


# -----------------------------------------------------------------------------
# 6. Missing A2 (Safeguard 4 & Renormalization)
# -----------------------------------------------------------------------------
def test_missing_a2(default_scorer, flow):
    """Verify Safeguard 4: Missing A2 evaluates on classifier only without substituting 0."""
    a1 = Agent1ThreatPrediction(
        predicted_class="BRUTE FORCE",
        confidence=0.85,
        probabilities={"BRUTE FORCE": 0.85, "BENIGN": 0.15},
    )

    res = default_scorer.score(flow_context=flow, a1_prediction=a1, a2_assessment=None)

    assert res.final_class == "BRUTE FORCE"
    assert res.anomaly_score_normalized is None
    assert res.classifier_score == 0.85
    assert res.correlation_score == 0.5
    # Available weights: classifier (0.50) + correlation (0.20) = 0.70
    # Expected score: (0.50*0.85 + 0.20*0.50) / 0.70 = (0.425 + 0.10) / 0.70 = 0.75
    assert pytest.approx(res.fusion_score, abs=1e-3) == 0.75
    assert res.effective_weights["anomaly"] == 0.0
    assert any("Missing Agent 2" in u for u in res.uncertainty)


# -----------------------------------------------------------------------------
# 7. Both agents missing (Safeguard 5)
# -----------------------------------------------------------------------------
def test_both_agents_missing(default_scorer, flow):
    """Verify Safeguard 5: Both agents missing yields INSUFFICIENT_EVIDENCE with no score."""
    res = default_scorer.score(flow_context=flow, a1_prediction=None, a2_assessment=None)

    assert res.evidence_status == EvidenceStatus.INSUFFICIENT_EVIDENCE.value
    assert res.fusion_score is None
    assert res.final_class == "UNKNOWN"
    assert res.assessment == "INCONCLUSIVE"
    assert res.risk_level == RiskLevel.UNKNOWN.value
    assert res.confidence_level == ConfidenceLevel.LOW.value


# -----------------------------------------------------------------------------
# 8. Dynamic weight renormalization
# -----------------------------------------------------------------------------
def test_dynamic_weight_renormalization(default_scorer, flow):
    """Verify dynamic weight renormalization sums to 1.0 and does not substitute 0."""
    a1 = Agent1ThreatPrediction(predicted_class="DOS", confidence=0.70)
    # A2 missing
    res_a2_missing = default_scorer.score(flow_context=flow, a1_prediction=a1, a2_assessment=None)
    eff_w = res_a2_missing.effective_weights
    assert pytest.approx(sum(eff_w.values()), abs=1e-3) == 1.0
    assert eff_w["anomaly"] == 0.0
    assert eff_w["classifier"] > 0.50  # Renormalized higher


# -----------------------------------------------------------------------------
# 9. Correct fusion score calculation
# -----------------------------------------------------------------------------
def test_correct_fusion_score_calculation(default_scorer, flow):
    """Verify exact weighted sum formula: 0.50*C + 0.30*A + 0.20*R."""
    # C = 0.60, A = 0.40, R = 1.0 (agreement malicious)
    a1 = Agent1ThreatPrediction(predicted_class="DOS", confidence=0.60)
    a2 = Agent2AnomalyAssessment(anomaly_score=0.40, anomaly_detected=True)

    res = default_scorer.score(flow_context=flow, a1_prediction=a1, a2_assessment=a2)
    # Expected: 0.50*0.60 + 0.30*0.40 + 0.20*1.0 = 0.30 + 0.12 + 0.20 = 0.62
    assert pytest.approx(res.fusion_score, abs=1e-4) == 0.62


# -----------------------------------------------------------------------------
# 10. Risk threshold boundaries
# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "score_val,expected_risk",
    [
        (0.24, RiskLevel.LOW.value),
        (0.25, RiskLevel.MEDIUM.value),
        (0.49, RiskLevel.MEDIUM.value),
        (0.50, RiskLevel.HIGH.value),
        (0.74, RiskLevel.HIGH.value),
        (0.75, RiskLevel.CRITICAL.value),
        (1.00, RiskLevel.CRITICAL.value),
    ],
)
def test_risk_threshold_boundaries(score_val, expected_risk, flow):
    """Verify exact threshold boundary values: 0.24, 0.25, 0.49, 0.50, 0.74, 0.75, 1.00."""
    # We configure a custom scorer where classifier weight is 1.0, anomaly=0, correlation=0
    # to test exact boundary mapping directly
    cfg = FusionConfig(classifier_weight=1.0, anomaly_weight=0.0, correlation_weight=0.0)
    scorer = FusionScorer(config=cfg)

    if score_val < 0.25:
        a1 = Agent1ThreatPrediction(predicted_class="BENIGN", confidence=round(1.0 - score_val, 4))
    else:
        a1 = Agent1ThreatPrediction(predicted_class="DOS", confidence=score_val)
    # A2 matching normal so no override safeguard triggers
    a2 = Agent2AnomalyAssessment(anomaly_score=0.0, anomaly_detected=False)

    res = scorer.score(flow_context=flow, a1_prediction=a1, a2_assessment=a2)
    assert res.fusion_score == pytest.approx(score_val, abs=1e-4)
    assert res.risk_level == expected_risk


# -----------------------------------------------------------------------------
# 11. Confidence level mapping
# -----------------------------------------------------------------------------
def test_confidence_level_mapping(default_scorer, flow):
    """Verify HIGH, MEDIUM, and LOW confidence-level mapping logic."""
    # HIGH: Both available, agreement, sufficient confidence & margin
    a1_high = Agent1ThreatPrediction(
        predicted_class="DDOS",
        confidence=0.85,
        probabilities={"DDOS": 0.85, "BENIGN": 0.05, "DOS": 0.10},
    )
    a2_high = Agent2AnomalyAssessment(anomaly_score=0.85, anomaly_detected=True)
    res_high = default_scorer.score(flow_context=flow, a1_prediction=a1_high, a2_assessment=a2_high)
    assert res_high.confidence_level == ConfidenceLevel.HIGH.value

    # MEDIUM: Both available, but low margin or low classifier confidence
    a1_med = Agent1ThreatPrediction(
        predicted_class="DDOS",
        confidence=0.55,  # Low confidence (< 0.60)
        probabilities={"DDOS": 0.55, "BENIGN": 0.45},
    )
    res_med = default_scorer.score(flow_context=flow, a1_prediction=a1_med, a2_assessment=a2_high)
    assert res_med.confidence_level == ConfidenceLevel.MEDIUM.value

    # LOW: Missing agent or sharp disagreement
    res_low = default_scorer.score(flow_context=flow, a1_prediction=None, a2_assessment=a2_high)
    assert res_low.confidence_level == ConfidenceLevel.LOW.value


# -----------------------------------------------------------------------------
# 12. Invalid and non-finite values
# -----------------------------------------------------------------------------
def test_invalid_and_non_finite_values(default_scorer, flow):
    """Verify that NaN and Infinity are rejected and marked unavailable safely."""
    # A1 with NaN confidence
    a1_nan = {"predicted_class": "DOS", "confidence": float("nan")}
    a2_ok = Agent2AnomalyAssessment(anomaly_score=0.8, anomaly_detected=True)

    res = default_scorer.score(flow_context=flow, a1_prediction=a1_nan, a2_assessment=a2_ok)
    # A1 is marked invalid, so scorer runs on A2 only (renormalized)
    assert res.classifier_score is None
    assert res.anomaly_score_normalized == 0.8
    assert res.final_class == "UNKNOWN"


# -----------------------------------------------------------------------------
# 13. Unknown anomaly score convention
# -----------------------------------------------------------------------------
def test_unknown_anomaly_score_convention(flow):
    """Verify that when convention is unknown, anomaly evidence is marked unavailable."""
    cfg = FusionConfig(anomaly_convention_known=False)
    scorer = FusionScorer(config=cfg)

    a1 = Agent1ThreatPrediction(predicted_class="PORT SCAN", confidence=0.85)
    a2 = Agent2AnomalyAssessment(anomaly_score=0.95, anomaly_detected=True)

    res = scorer.score(flow_context=flow, a1_prediction=a1, a2_assessment=a2)
    # Anomaly evidence must be marked unavailable rather than guessed
    assert res.anomaly_score_normalized is None
    assert res.effective_weights["anomaly"] == 0.0
    assert res.classifier_score == 0.85


# -----------------------------------------------------------------------------
# 14. Deterministic repeated execution
# -----------------------------------------------------------------------------
def test_deterministic_repeated_execution(default_scorer, flow):
    """Verify multiple executions on identical inputs yield bitwise identical scores."""
    a1 = Agent1ThreatPrediction(predicted_class="DOS", confidence=0.82)
    a2 = Agent2AnomalyAssessment(anomaly_score=0.76, anomaly_detected=True)

    res1 = default_scorer.score(flow_context=flow, a1_prediction=a1, a2_assessment=a2)
    res2 = default_scorer.score(flow_context=flow, a1_prediction=a1, a2_assessment=a2)

    assert res1.fusion_score == res2.fusion_score
    assert res1.risk_level == res2.risk_level
    assert res1.effective_weights == res2.effective_weights
    assert res1.final_class == res2.final_class


# -----------------------------------------------------------------------------
# 15. Configurable weights and thresholds
# -----------------------------------------------------------------------------
def test_configurable_weights_and_thresholds(flow):
    """Verify custom FusionConfig alters weights and classification cutoffs."""
    custom_cfg = FusionConfig(
        classifier_weight=0.60,
        anomaly_weight=0.20,
        correlation_weight=0.20,
        high_cutoff=0.80,  # Custom higher cutoff for CRITICAL
    )
    scorer = FusionScorer(config=custom_cfg)

    a1 = Agent1ThreatPrediction(predicted_class="DDOS", confidence=0.80)
    a2 = Agent2AnomalyAssessment(anomaly_score=0.80, anomaly_detected=True)

    res = scorer.score(flow_context=flow, a1_prediction=a1, a2_assessment=a2)
    # C=0.80, A=0.80, R=1.0 -> 0.60*0.80 + 0.20*0.80 + 0.20*1.0 = 0.48 + 0.16 + 0.20 = 0.84
    assert res.configured_weights["classifier"] == 0.60
    assert pytest.approx(res.fusion_score, abs=1e-3) == 0.84


# -----------------------------------------------------------------------------
# 16. Final class must never be invented from anomaly evidence
# -----------------------------------------------------------------------------
def test_final_class_never_invented_from_anomaly(default_scorer, flow):
    """Verify that severe anomaly evidence NEVER fabricates a specific attack class."""
    # A1 is missing, but A2 reports massive anomaly
    a2_extreme = Agent2AnomalyAssessment(
        anomaly_score=999.0,
        anomaly_detected=True,
        evidence=["gigantic syn flood rate", "ddos signature pattern"],
    )

    res = default_scorer.score(flow_context=flow, a1_prediction=None, a2_assessment=a2_extreme)
    # Even though A2 evidence mentions DDoS, A3 must NEVER infer attack class without A1
    assert res.final_class == "UNKNOWN"
    assert res.final_class != "DDOS"
    assert res.final_class != "DOS"


# -----------------------------------------------------------------------------
# 17. Pipeline Integration with Agent3Skeleton
# -----------------------------------------------------------------------------
def test_skeleton_pipeline_integration(flow):
    """Verify end-to-end integration of FusionScorer in Agent3Skeleton.process()."""
    skeleton = Agent3Skeleton()
    a1 = Agent1ThreatPrediction(predicted_class="DDOS", confidence=0.92)
    a2 = Agent2AnomalyAssessment(anomaly_score=0.85, anomaly_detected=True, evidence=["burst volume"])
    fusion_input = Agent3FusionInput(flow_context=flow, a1_prediction=a1, a2_assessment=a2)

    output = skeleton.process(fusion_input)

    assert output.flow_id == flow.flow_id
    assert output.verdict.value == "MALICIOUS"
    assert output.fused_risk_score > 0.75
    # Verify Block 4 details are present in Agent3Output.details
    assert "configured_weights" in output.details
    assert "effective_weights" in output.details
    assert output.details["final_class"] == "DDOS"
    assert output.details["risk_level"] == "CRITICAL"
