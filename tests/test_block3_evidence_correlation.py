"""Comprehensive unit tests for Block 3: Evidence Correlation Engine."""

import pytest

from cybersentinel.agent3 import (
    A1DetectionResult,
    A2DetectionResult,
    Agent1ThreatPrediction,
    Agent2AnomalyAssessment,
    Agent3FusionInput,
    CorrelationResult,
    CorrelationScenario,
    EvidenceCorrelator,
    EvidenceStatus,
    FlowContext,
    InvestigationPriority,
    correlate_evidence,
)


@pytest.fixture
def correlator() -> EvidenceCorrelator:
    return EvidenceCorrelator()


@pytest.fixture
def flow_ctx() -> FlowContext:
    return FlowContext(
        flow_id="f-test-blk3",
        timestamp="2026-10-30T16:00:00Z",
        src_ip="10.10.1.5",
        src_port=55123,
        dst_ip="10.10.1.1",
        dst_port=80,
        protocol="TCP",
    )


# -----------------------------------------------------------------------------
# Scenario 1: Both agents support malicious activity
# -----------------------------------------------------------------------------
def test_scenario_1_both_malicious(correlator):
    """Verify Scenario 1: Both agents corroborate malicious attack."""
    a1 = Agent1ThreatPrediction(predicted_class="DOS", confidence=0.92)
    a2 = Agent2AnomalyAssessment(
        anomaly_score=1.45,
        anomaly_detected=True,
        evidence=["packet rate spike 50000pps", "tcp syn flood pattern"],
    )

    res = correlator.correlate(a1, a2)
    assert res.scenario == CorrelationScenario.BOTH_MALICIOUS
    assert res.scenario_index == 1
    assert res.evidence_status == EvidenceStatus.AGREEMENT
    assert res.agent_agreement is True
    assert res.investigation_priority == InvestigationPriority.CRITICAL
    assert len(res.supporting_evidence) >= 2
    assert len(res.conflicting_evidence) == 0
    assert "Multi-agent consensus" in res.correlation_reason


# -----------------------------------------------------------------------------
# Scenario 2: Both agents support benign / normal behaviour
# -----------------------------------------------------------------------------
def test_scenario_2_both_benign(correlator):
    """Verify Scenario 2: Both agents confirm benign/normal behavior."""
    a1 = Agent1ThreatPrediction(predicted_class="BENIGN", confidence=0.95)
    a2 = Agent2AnomalyAssessment(
        anomaly_score=0.08,
        anomaly_detected=False,
        evidence=[],
    )

    res = correlator.correlate(a1, a2)
    assert res.scenario == CorrelationScenario.BOTH_BENIGN
    assert res.scenario_index == 2
    assert res.evidence_status == EvidenceStatus.AGREEMENT
    assert res.agent_agreement is True
    assert res.investigation_priority == InvestigationPriority.LOW
    assert len(res.conflicting_evidence) == 0


# -----------------------------------------------------------------------------
# Scenario 3: A1 predicts BENIGN but A2 detects a strong anomaly
# -----------------------------------------------------------------------------
def test_scenario_3_a1_benign_a2_strong_anomaly(correlator):
    """Verify Scenario 3: Potential zero-day or signature evasion."""
    a1 = Agent1ThreatPrediction(predicted_class="BENIGN", confidence=0.88)
    a2 = Agent2AnomalyAssessment(
        anomaly_score=3.75,
        anomaly_detected=True,
        evidence=["abnormal entropy in payload", "irregular dns tunneling sequence"],
    )

    res = correlator.correlate(a1, a2)
    assert res.scenario == CorrelationScenario.A1_BENIGN_A2_ANOMALY
    assert res.scenario_index == 3
    assert res.evidence_status == EvidenceStatus.DISAGREEMENT
    assert res.agent_agreement is False
    assert res.investigation_priority == InvestigationPriority.HIGH
    assert len(res.conflicting_evidence) > 0
    assert "zero-day" in res.correlation_reason.lower() or "evasion" in res.correlation_reason.lower()


# -----------------------------------------------------------------------------
# Scenario 4: A1 predicts an attack but A2 reports normal behaviour
# -----------------------------------------------------------------------------
def test_scenario_4_a1_attack_a2_normal(correlator):
    """Verify Scenario 4: Known signature match is NOT erased by normal baseline."""
    a1 = Agent1ThreatPrediction(predicted_class="PORT SCAN", confidence=0.91)
    a2 = Agent2AnomalyAssessment(
        anomaly_score=0.12,
        anomaly_detected=False,
        evidence=[],
    )

    res = correlator.correlate(a1, a2)
    assert res.scenario == CorrelationScenario.A1_ATTACK_A2_NORMAL
    assert res.scenario_index == 4
    assert res.evidence_status == EvidenceStatus.DISAGREEMENT
    assert res.agent_agreement is False
    assert res.investigation_priority == InvestigationPriority.HIGH
    assert "A malicious A1 prediction must not be erased" in res.correlation_reason
    assert len(res.supporting_evidence) > 0
    assert len(res.conflicting_evidence) > 0


# -----------------------------------------------------------------------------
# Scenario 5: A1 has low confidence and A2 reports suspicious activity
# -----------------------------------------------------------------------------
def test_scenario_5_a1_low_conf_a2_suspicious(correlator):
    """Verify Scenario 5: Weak A1 confidence with suspicious A2 triggers escalation."""
    a1 = Agent1ThreatPrediction(predicted_class="BENIGN", confidence=0.42)
    a2 = Agent2AnomalyAssessment(
        anomaly_score=0.68,
        anomaly_detected=True,
        evidence=["beaconing heartbeat detected"],
    )

    res = correlator.correlate(a1, a2)
    assert res.scenario == CorrelationScenario.A1_LOW_CONF_A2_SUSPICIOUS
    assert res.scenario_index == 5
    assert res.evidence_status == EvidenceStatus.DISAGREEMENT
    assert res.agent_agreement is False
    assert res.investigation_priority == InvestigationPriority.HIGH
    assert "low confidence" in res.correlation_reason.lower()


# -----------------------------------------------------------------------------
# Scenario 6: Agent 1 is missing
# -----------------------------------------------------------------------------
def test_scenario_6_a1_missing(correlator):
    """Verify Scenario 6: Missing A1 degrades to single-agent A2 and never turns BENIGN."""
    a2 = Agent2AnomalyAssessment(
        anomaly_score=0.88,
        anomaly_detected=True,
        evidence=["unusual egress traffic"],
    )

    res = correlator.correlate(a1_prediction=None, a2_assessment=a2)
    assert res.scenario == CorrelationScenario.A1_MISSING
    assert res.scenario_index == 6
    assert res.evidence_status == EvidenceStatus.PARTIAL_EVIDENCE
    assert res.agent_agreement is None
    assert res.investigation_priority == InvestigationPriority.HIGH
    assert "missing" in res.correlation_reason.lower()
    assert "never be converted to benign" in res.correlation_reason.lower()


# -----------------------------------------------------------------------------
# Scenario 7: Agent 2 is missing
# -----------------------------------------------------------------------------
def test_scenario_7_a2_missing(correlator):
    """Verify Scenario 7: Missing A2 degrades to single-agent A1."""
    a1 = Agent1ThreatPrediction(predicted_class="BRUTE FORCE", confidence=0.89)

    res = correlator.correlate(a1_prediction=a1, a2_assessment=None)
    assert res.scenario == CorrelationScenario.A2_MISSING
    assert res.scenario_index == 7
    assert res.evidence_status == EvidenceStatus.PARTIAL_EVIDENCE
    assert res.agent_agreement is None
    assert res.investigation_priority == InvestigationPriority.CRITICAL
    assert "never be converted to benign" in res.correlation_reason.lower()


# -----------------------------------------------------------------------------
# Scenario 8: Both agents provide incomplete or missing evidence
# -----------------------------------------------------------------------------
def test_scenario_8_both_incomplete(correlator):
    """Verify Scenario 8: Both missing yields insufficient evidence and low priority."""
    res = correlator.correlate(a1_prediction=None, a2_assessment=None)
    assert res.scenario == CorrelationScenario.BOTH_INCOMPLETE
    assert res.scenario_index == 8
    assert res.evidence_status == EvidenceStatus.INSUFFICIENT_EVIDENCE
    assert res.agent_agreement is None
    assert res.investigation_priority == InvestigationPriority.LOW
    assert "insufficient data" in res.correlation_reason.lower()


# -----------------------------------------------------------------------------
# Fusion input & functional interface
# -----------------------------------------------------------------------------
def test_correlate_via_fusion_input(flow_ctx):
    """Verify correlate works with Agent3FusionInput and convenience function."""
    a1 = Agent1ThreatPrediction(predicted_class="DDOS", confidence=0.94)
    a2 = Agent2AnomalyAssessment(anomaly_score=2.1, anomaly_detected=True, evidence=["amplification detected"])
    fusion_in = Agent3FusionInput(flow_context=flow_ctx, a1_prediction=a1, a2_assessment=a2)

    res = correlate_evidence(fusion_input=fusion_in)
    assert res.scenario == CorrelationScenario.BOTH_MALICIOUS
    assert res.evidence_status == EvidenceStatus.AGREEMENT
    assert res.agent_agreement is True

    # Check to_dict serialization
    d = res.to_dict()
    assert d["evidence_status"] == "AGREEMENT"
    assert d["agent_agreement"] is True
    assert d["investigation_priority"] == "CRITICAL"
    assert d["scenario_index"] == 1

