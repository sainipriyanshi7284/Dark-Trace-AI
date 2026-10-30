"""Focused unit and integration tests for CyberSentinel Agent 4 (Policy Engine Foundation).

Tests:
  - All four actions (ALLOW, ALERT, REVIEW, BLOCK).
  - Missing Agent 3 input (safe degradation and strict exception).
  - Invalid JSON string input.
  - Missing and incomplete fields.
  - Low confidence block prevention override.
  - Conflicting evidence override.
  - Insufficient evidence override.
  - Suspicious BENIGN prediction override.
  - Deterministic decisions.
  - Direct integration with Agent 3 output objects, dicts, and to_json() strings.
  - Configurable policy profiles (DEFAULT, STRICT, PERMISSIVE).
  - Decision dictionary and JSON serialization.
"""

import json
import pytest

from cybersentinel.agent3 import (
    Agent3Output,
    Agent3ThreatAssessment,
    FlowContext,
    FusionStatus,
    RecommendedAction,
    Verdict,
    process_flow,
)
from cybersentinel.agent4 import (
    InvalidAssessmentError,
    InvalidJsonError,
    MissingAssessmentError,
    PolicyAction,
    PolicyConfig,
    PolicyDecision,
    PolicyEngine,
    PolicyProfile,
    evaluate_policy,
)


@pytest.fixture
def default_engine() -> PolicyEngine:
    """Fixture providing PolicyEngine initialized with default profile."""
    return PolicyEngine()


# =============================================================================
# 1. All Four Policy Actions
# =============================================================================
def test_action_allow_on_low_risk(default_engine):
    """Verify LOW risk produces ALLOW decision without human review."""
    assessment = {
        "flow_id": "FLOW-ALLOW-001",
        "final_class": "BENIGN",
        "assessment": "BENIGN",
        "risk_level": "LOW",
        "confidence_level": "HIGH",
        "fusion_score": 0.05,
        "evidence_status": "AGREEMENT",
    }
    decision = default_engine.evaluate(assessment)

    assert isinstance(decision, PolicyDecision)
    assert decision.action == PolicyAction.ALLOW
    assert decision.requires_human_review is False
    assert decision.simulated is True
    assert decision.matched_rule == "RULE_BASE_ALLOW_LOW_RISK"
    assert "permitted" in decision.decision_reason.lower()


def test_action_alert_on_medium_risk(default_engine):
    """Verify MEDIUM risk produces ALERT decision for SIEM notification."""
    assessment = {
        "flow_id": "FLOW-ALERT-001",
        "final_class": "PORT SCAN",
        "assessment": "SUSPICIOUS",
        "risk_level": "MEDIUM",
        "confidence_level": "MEDIUM",
        "fusion_score": 0.38,
        "evidence_status": "AGREEMENT",
    }
    decision = default_engine.evaluate(assessment)

    assert decision.action == PolicyAction.ALERT
    assert decision.requires_human_review is False
    assert decision.simulated is True
    assert decision.matched_rule == "RULE_BASE_ALERT_MEDIUM_RISK"
    assert "alert" in decision.decision_reason.lower()


def test_action_review_on_high_risk(default_engine):
    """Verify HIGH risk produces REVIEW decision requiring human analyst review."""
    assessment = {
        "flow_id": "FLOW-REVIEW-001",
        "final_class": "DOS",
        "assessment": "MALICIOUS",
        "risk_level": "HIGH",
        "confidence_level": "HIGH",
        "fusion_score": 0.65,
        "evidence_status": "AGREEMENT",
    }
    decision = default_engine.evaluate(assessment)

    assert decision.action == PolicyAction.REVIEW
    assert decision.requires_human_review is True
    assert decision.simulated is True
    assert decision.matched_rule == "RULE_BASE_REVIEW_HIGH_RISK"
    assert "review" in decision.decision_reason.lower()


def test_action_block_on_critical_risk(default_engine):
    """Verify CRITICAL risk with HIGH confidence produces simulated BLOCK decision."""
    assessment = {
        "flow_id": "FLOW-BLOCK-001",
        "final_class": "DDOS",
        "assessment": "MALICIOUS",
        "risk_level": "CRITICAL",
        "confidence_level": "HIGH",
        "fusion_score": 0.92,
        "evidence_status": "AGREEMENT",
    }
    decision = default_engine.evaluate(assessment)

    assert decision.action == PolicyAction.BLOCK
    assert decision.simulated is True  # Enforce simulation invariant
    assert decision.requires_human_review is False
    assert decision.matched_rule == "RULE_BASE_BLOCK_CRITICAL_RISK"
    assert "block" in decision.decision_reason.lower()


# =============================================================================
# 2. Missing Agent 3 Input Handling
# =============================================================================
def test_missing_agent3_input_safe_degradation(default_engine):
    """Verify missing assessment safely degrades to REVIEW and NEVER produces ALLOW."""
    decision = default_engine.evaluate(None, raise_on_error=False)

    assert decision.action == PolicyAction.REVIEW
    assert decision.action != PolicyAction.ALLOW
    assert decision.requires_human_review is True
    assert decision.matched_rule == "RULE_SAFETY_MISSING_ASSESSMENT"


def test_missing_agent3_input_raises_in_strict_mode(default_engine):
    """Verify missing assessment raises MissingAssessmentError when raise_on_error=True."""
    with pytest.raises(MissingAssessmentError):
        default_engine.evaluate(None, raise_on_error=True)


# =============================================================================
# 3. Invalid JSON String Handling
# =============================================================================
def test_invalid_json_input_safe_degradation(default_engine):
    """Verify malformed JSON safely degrades to REVIEW and NEVER produces ALLOW."""
    malformed_json = '{"flow_id": "F-01", "risk_level": '  # truncated JSON
    decision = default_engine.evaluate(malformed_json, raise_on_error=False)

    assert decision.action == PolicyAction.REVIEW
    assert decision.action != PolicyAction.ALLOW
    assert decision.requires_human_review is True
    assert decision.matched_rule == "RULE_SAFETY_MALFORMED_INPUT"


def test_invalid_json_input_raises_in_strict_mode(default_engine):
    """Verify malformed JSON raises InvalidJsonError when raise_on_error=True."""
    with pytest.raises(InvalidJsonError):
        default_engine.evaluate('not-json-at-all', raise_on_error=True)

    with pytest.raises(InvalidJsonError):
        default_engine.evaluate('', raise_on_error=True)


# =============================================================================
# 4. Missing and Incomplete Fields Handling
# =============================================================================
def test_missing_required_fields_safe_degradation(default_engine):
    """Verify incomplete payload missing required fields degrades safely to REVIEW."""
    # Missing flow_id
    incomplete_1 = {"risk_level": "LOW", "confidence_level": "HIGH"}
    dec_1 = default_engine.evaluate(incomplete_1, raise_on_error=False)
    assert dec_1.action == PolicyAction.REVIEW
    assert dec_1.requires_human_review is True

    # Missing risk_level
    incomplete_2 = {"flow_id": "FLOW-001", "confidence_level": "HIGH"}
    dec_2 = default_engine.evaluate(incomplete_2, raise_on_error=False)
    assert dec_2.action == PolicyAction.REVIEW
    assert dec_2.requires_human_review is True


def test_missing_required_fields_raises_in_strict_mode(default_engine):
    """Verify incomplete payload raises InvalidAssessmentError in strict mode."""
    with pytest.raises(InvalidAssessmentError):
        default_engine.evaluate({}, raise_on_error=True)

    with pytest.raises(InvalidAssessmentError):
        default_engine.evaluate({"flow_id": "FLOW-01"}, raise_on_error=True)


# =============================================================================
# 5. Safety Override: Low Confidence Block Prevention
# =============================================================================
def test_low_confidence_prevents_automatic_block(default_engine):
    """Verify critical threat with LOW confidence is downgraded from BLOCK to REVIEW."""
    low_conf_critical = {
        "flow_id": "FLOW-LOW-CONF-01",
        "final_class": "DDOS",
        "assessment": "MALICIOUS",
        "risk_level": "CRITICAL",
        "confidence_level": "LOW",  # Low confidence!
        "fusion_score": 0.78,
        "evidence_status": "PARTIAL_EVIDENCE",
    }
    decision = default_engine.evaluate(low_conf_critical)

    # Must NOT automatically BLOCK when confidence is low
    assert decision.action == PolicyAction.REVIEW
    assert decision.action != PolicyAction.BLOCK
    assert decision.requires_human_review is True
    assert decision.matched_rule == "RULE_OVERRIDE_LOW_CONFIDENCE_BLOCK_PREVENTION"
    assert "low" in decision.decision_reason.lower()


# =============================================================================
# 6. Safety Override: Conflicting Evidence
# =============================================================================
def test_conflicting_evidence_override(default_engine):
    """Verify evidence divergence between agents overrides ALLOW to REVIEW."""
    conflicting = {
        "flow_id": "FLOW-CONFLICT-01",
        "final_class": "BENIGN",
        "assessment": "BENIGN",
        "risk_level": "LOW",
        "confidence_level": "LOW",
        "evidence_status": "DISAGREEMENT",  # Disagreement!
    }
    decision = default_engine.evaluate(conflicting)

    assert decision.action == PolicyAction.REVIEW
    assert decision.action != PolicyAction.ALLOW
    assert decision.requires_human_review is True
    assert decision.matched_rule == "RULE_OVERRIDE_EVIDENCE_DISAGREEMENT"


# =============================================================================
# 7. Safety Override: Insufficient Evidence
# =============================================================================
def test_insufficient_evidence_override(default_engine):
    """Verify INSUFFICIENT_EVIDENCE or UNKNOWN risk produces REVIEW (never ALLOW)."""
    insufficient = {
        "flow_id": "FLOW-INSUFFICIENT-01",
        "final_class": "UNKNOWN",
        "assessment": "INCONCLUSIVE",
        "risk_level": "UNKNOWN",
        "confidence_level": "LOW",
        "evidence_status": "INSUFFICIENT_EVIDENCE",
        "fusion_score": None,
    }
    decision = default_engine.evaluate(insufficient)

    assert decision.action == PolicyAction.REVIEW
    assert decision.action != PolicyAction.ALLOW
    assert decision.requires_human_review is True
    assert decision.matched_rule == "RULE_OVERRIDE_INSUFFICIENT_EVIDENCE"


# =============================================================================
# 8. Safety Override: Suspicious BENIGN Prediction
# =============================================================================
def test_suspicious_benign_prediction_override(default_engine):
    """Verify classifier BENIGN paired with SUSPICIOUS assessment never receives ALLOW."""
    suspicious_benign = {
        "flow_id": "FLOW-SUSP-BENIGN-01",
        "final_class": "BENIGN",
        "assessment": "SUSPICIOUS",  # Suspicious assessment (e.g. strong anomaly detected)
        "risk_level": "HIGH",
        "confidence_level": "LOW",
        "evidence_status": "DISAGREEMENT",
    }
    decision = default_engine.evaluate(suspicious_benign)

    assert decision.action == PolicyAction.REVIEW
    assert decision.action != PolicyAction.ALLOW
    assert decision.requires_human_review is True
    assert decision.matched_rule in (
        "RULE_OVERRIDE_SUSPICIOUS_BENIGN",
        "RULE_BASE_REVIEW_HIGH_RISK",
        "RULE_OVERRIDE_EVIDENCE_DISAGREEMENT",
    )


def test_suspicious_benign_with_low_risk_override():
    """Verify that even if risk mapping would assign ALLOW, suspicious benign is caught."""
    cfg = PolicyConfig(
        risk_action_mapping={
            "LOW": PolicyAction.ALLOW,
            "MEDIUM": PolicyAction.ALLOW,
            "HIGH": PolicyAction.ALLOW,
            "CRITICAL": PolicyAction.BLOCK,
        }
    )
    engine = PolicyEngine(config=cfg)
    suspicious_benign = {
        "flow_id": "FLOW-EVASION-01",
        "final_class": "BENIGN",
        "assessment": "SUSPICIOUS",
        "risk_level": "MEDIUM",
        "confidence_level": "MEDIUM",
        "evidence_status": "DISAGREEMENT",
    }
    decision = engine.evaluate(suspicious_benign)

    # Must override ALLOW to REVIEW
    assert decision.action == PolicyAction.REVIEW
    assert decision.matched_rule == "RULE_OVERRIDE_SUSPICIOUS_BENIGN"


# =============================================================================
# 9. Deterministic Repeated Execution
# =============================================================================
def test_deterministic_decisions(default_engine):
    """Verify 50 identical evaluations return bit-for-bit identical policy decisions."""
    assessment = {
        "flow_id": "FLOW-DETERMINISTIC-01",
        "final_class": "BRUTE FORCE",
        "assessment": "SUSPICIOUS",
        "risk_level": "MEDIUM",
        "confidence_level": "MEDIUM",
        "fusion_score": 0.42,
        "evidence_status": "AGREEMENT",
    }

    first = default_engine.evaluate(assessment)

    for _ in range(50):
        subsequent = default_engine.evaluate(assessment)
        assert subsequent.action == first.action
        assert subsequent.matched_rule == first.matched_rule
        assert subsequent.requires_human_review == first.requires_human_review
        assert subsequent.policy_profile == first.policy_profile
        assert subsequent.simulated == first.simulated


# =============================================================================
# 10. Interoperability with Agent 3 Outputs
# =============================================================================
def test_integration_with_agent3_threat_assessment_to_json():
    """Verify Agent 4 evaluates directly from Agent 3's assessment.to_json()."""
    # 1. Run Agent 3
    a1 = {"predicted_class": "DDOS", "confidence": 0.95}
    a2 = {"anomaly_score": 0.90, "anomaly_detected": True, "evidence": ["burst"]}
    a3_assessment = process_flow(a1, a2, flow_id="FLOW-A3-A4-01")

    # 2. Get JSON string from Agent 3
    json_str = a3_assessment.to_json()
    assert isinstance(json_str, str)

    # 3. Pass JSON string directly to Agent 4
    decision = evaluate_policy(json_str)

    assert isinstance(decision, PolicyDecision)
    assert decision.flow_id == "FLOW-A3-A4-01"
    assert decision.action == PolicyAction.BLOCK
    assert decision.simulated is True
    assert decision.risk_level == "CRITICAL"


def test_integration_with_agent3_threat_assessment_object():
    """Verify Agent 4 evaluates directly from Agent3ThreatAssessment object."""
    a1 = {"predicted_class": "BENIGN", "confidence": 0.98}
    a2 = {"anomaly_score": 0.02, "anomaly_detected": False}
    a3_assessment = process_flow(a1, a2, flow_id="FLOW-A3-OBJ-01")

    assert isinstance(a3_assessment, Agent3ThreatAssessment)
    decision = evaluate_policy(a3_assessment)

    assert decision.flow_id == "FLOW-A3-OBJ-01"
    assert decision.action == PolicyAction.ALLOW
    assert decision.requires_human_review is False


def test_integration_with_block1_agent3_output():
    """Verify Agent 4 evaluates legacy Block 1 Agent3Output objects compatibly."""
    flow = FlowContext(
        flow_id="FLOW-LEGACY-01",
        timestamp="2026-10-30T17:15:00Z",
        src_ip="10.0.0.1",
        src_port=80,
        dst_ip="10.0.0.2",
        dst_port=443,
        protocol="TCP",
    )
    a3_out = Agent3Output(
        incident_id="inc-12345",
        flow_id="FLOW-LEGACY-01",
        timestamp=flow.timestamp,
        verdict=Verdict.MALICIOUS,
        fused_risk_score=0.88,
        confidence=0.90,
        contributing_agents=["agent_1", "agent_2"],
        fusion_status=FusionStatus.DUAL_AGENT,
        threat_summary="Critical attack detected",
        details={"risk_level": "CRITICAL", "confidence_level": "HIGH", "final_class": "DOS"},
        recommended_policy_action=RecommendedAction.DROP,
        processing_time_ms=1.2,
    )

    decision = evaluate_policy(a3_out)

    assert decision.flow_id == "FLOW-LEGACY-01"
    assert decision.action == PolicyAction.BLOCK
    assert decision.simulated is True


# =============================================================================
# 11. Configurable Operational Profiles
# =============================================================================
def test_strict_operational_profile():
    """Verify STRICT profile escalates HIGH risk to BLOCK and MEDIUM to REVIEW."""
    strict_engine = PolicyEngine(config=PolicyConfig.strict_profile())

    high_risk = {
        "flow_id": "FLOW-STRICT-01",
        "final_class": "DOS",
        "assessment": "MALICIOUS",
        "risk_level": "HIGH",
        "confidence_level": "HIGH",
    }
    dec_high = strict_engine.evaluate(high_risk)
    assert dec_high.action == PolicyAction.BLOCK
    assert dec_high.policy_profile == PolicyProfile.STRICT.value

    medium_risk = {
        "flow_id": "FLOW-STRICT-02",
        "final_class": "PORT SCAN",
        "assessment": "SUSPICIOUS",
        "risk_level": "MEDIUM",
        "confidence_level": "HIGH",
    }
    dec_med = strict_engine.evaluate(medium_risk)
    assert dec_med.action == PolicyAction.REVIEW
    assert dec_med.requires_human_review is True


def test_permissive_operational_profile():
    """Verify PERMISSIVE profile allows MEDIUM risk and alerts on HIGH risk."""
    perm_engine = PolicyEngine(config=PolicyConfig.permissive_profile())

    med_risk = {
        "flow_id": "FLOW-PERM-01",
        "final_class": "PORT SCAN",
        "assessment": "SUSPICIOUS",
        "risk_level": "MEDIUM",
        "confidence_level": "MEDIUM",
    }
    dec_med = perm_engine.evaluate(med_risk)
    assert dec_med.action == PolicyAction.ALLOW

    high_risk = {
        "flow_id": "FLOW-PERM-02",
        "final_class": "DOS",
        "assessment": "MALICIOUS",
        "risk_level": "HIGH",
        "confidence_level": "HIGH",
    }
    dec_high = perm_engine.evaluate(high_risk)
    assert dec_high.action == PolicyAction.ALERT


# =============================================================================
# 12. Decision Serialization and Dictionary Subscripting
# =============================================================================
def test_decision_serialization():
    """Verify PolicyDecision serializes cleanly to dict, JSON, and supports indexing."""
    assessment = {
        "flow_id": "FLOW-SERIAL-01",
        "final_class": "DDOS",
        "assessment": "MALICIOUS",
        "risk_level": "CRITICAL",
        "confidence_level": "HIGH",
    }
    decision = evaluate_policy(assessment)

    # 1. to_dict() contains all required fields
    d = decision.to_dict()
    expected_fields = [
        "agent_id",
        "flow_id",
        "action",
        "policy_profile",
        "risk_level",
        "confidence_level",
        "matched_rule",
        "decision_reason",
        "requires_human_review",
        "simulated",
        "timestamp",
    ]
    for ef in expected_fields:
        assert ef in d, f"Missing field in to_dict: {ef}"

    assert d["agent_id"] == "A4"
    assert d["action"] == "BLOCK"
    assert d["simulated"] is True

    # 2. to_json() produces valid JSON matching to_dict()
    j_str = decision.to_json()
    assert json.loads(j_str) == d

    # 3. Subscripting and get()
    assert decision["flow_id"] == "FLOW-SERIAL-01"
    assert decision["action"] == PolicyAction.BLOCK
    assert decision.get("action") == PolicyAction.BLOCK
    assert decision.get("nonexistent", "fallback") == "fallback"

