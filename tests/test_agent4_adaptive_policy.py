"""Unit and integration tests for CyberSentinel Agent 4 Adaptive Policy Engine.

Tests:
  1. STRICT profile decisions.
  2. BALANCED profile decisions.
  3. CONSERVATIVE profile decisions.
  4. Same assessment under all three profiles showing meaningful differences.
  5. Runtime profile selection on a single engine instance.
  6. Missing assessment handling (safe degradation and strict exception).
  7. Insufficient evidence override.
  8. Conflicting evidence override.
  9. Low confidence block prevention override.
  10. Suspicious BENIGN prediction override.
  11. Deterministic repeated decisions.
  12. Integration with Agent 3 process_flow output.
  13. Invalid profile error handling.
"""

import json
import pytest

from cybersentinel.agent3 import process_flow
from cybersentinel.agent4 import (
    AdaptivePolicyEngine,
    InvalidProfileError,
    MissingAssessmentError,
    PolicyAction,
    PolicyDecision,
    PolicyProfile,
    evaluate_adaptive_policy,
)


@pytest.fixture
def adaptive_engine() -> AdaptivePolicyEngine:
    """Fixture providing AdaptivePolicyEngine initialized with default BALANCED profile."""
    return AdaptivePolicyEngine(default_profile=PolicyProfile.BALANCED)


# =============================================================================
# 1. STRICT Profile Decisions
# =============================================================================
def test_strict_profile_decisions(adaptive_engine):
    """Scenario 1: STRICT profile prioritizes security and early threat escalation."""
    # LOW risk -> ALLOW
    low_flow = {"flow_id": "STRICT-01", "final_class": "BENIGN", "assessment": "BENIGN", "risk_level": "LOW", "confidence_level": "HIGH"}
    dec_low = adaptive_engine.evaluate(low_flow, profile="STRICT")
    assert dec_low.action == PolicyAction.ALLOW
    assert dec_low.policy_profile == "STRICT"

    # MEDIUM risk with attack class -> early threat escalation to REVIEW
    med_attack = {"flow_id": "STRICT-02", "final_class": "PORT SCAN", "assessment": "SUSPICIOUS", "risk_level": "MEDIUM", "confidence_level": "HIGH"}
    dec_med = adaptive_engine.evaluate(med_attack, profile="STRICT")
    assert dec_med.action == PolicyAction.REVIEW
    assert dec_med.requires_human_review is True
    assert "early threat escalation" in dec_med.decision_reason.lower()

    # HIGH risk -> REVIEW
    high_flow = {"flow_id": "STRICT-03", "final_class": "DOS", "assessment": "MALICIOUS", "risk_level": "HIGH", "confidence_level": "HIGH"}
    dec_high = adaptive_engine.evaluate(high_flow, profile="STRICT")
    assert dec_high.action == PolicyAction.REVIEW
    assert dec_high.requires_human_review is True

    # CRITICAL risk with HIGH confidence -> simulated BLOCK
    crit_flow = {"flow_id": "STRICT-04", "final_class": "DDOS", "assessment": "MALICIOUS", "risk_level": "CRITICAL", "confidence_level": "HIGH"}
    dec_crit = adaptive_engine.evaluate(crit_flow, profile="STRICT")
    assert dec_crit.action == PolicyAction.BLOCK
    assert dec_crit.simulated is True


# =============================================================================
# 2. BALANCED Profile Decisions
# =============================================================================
def test_balanced_profile_decisions(adaptive_engine):
    """Scenario 2: BALANCED profile balances security and operational continuity."""
    # LOW risk -> ALLOW
    dec_low = adaptive_engine.evaluate({"flow_id": "BAL-01", "final_class": "BENIGN", "assessment": "BENIGN", "risk_level": "LOW", "confidence_level": "HIGH"}, profile="BALANCED")
    assert dec_low.action == PolicyAction.ALLOW

    # MEDIUM risk -> ALERT (standard alert, not escalated)
    dec_med = adaptive_engine.evaluate({"flow_id": "BAL-02", "final_class": "PORT SCAN", "assessment": "SUSPICIOUS", "risk_level": "MEDIUM", "confidence_level": "HIGH"}, profile="BALANCED")
    assert dec_med.action == PolicyAction.ALERT
    assert dec_med.requires_human_review is False

    # HIGH risk -> REVIEW
    dec_high = adaptive_engine.evaluate({"flow_id": "BAL-03", "final_class": "DOS", "assessment": "MALICIOUS", "risk_level": "HIGH", "confidence_level": "HIGH"}, profile="BALANCED")
    assert dec_high.action == PolicyAction.REVIEW
    assert dec_high.requires_human_review is True

    # CRITICAL risk -> BLOCK
    dec_crit = adaptive_engine.evaluate({"flow_id": "BAL-04", "final_class": "DDOS", "assessment": "MALICIOUS", "risk_level": "CRITICAL", "confidence_level": "HIGH"}, profile="BALANCED")
    assert dec_crit.action == PolicyAction.BLOCK
    assert dec_crit.simulated is True


# =============================================================================
# 3. CONSERVATIVE Profile Decisions
# =============================================================================
def test_conservative_profile_decisions(adaptive_engine):
    """Scenario 3: CONSERVATIVE profile minimizes disruption; requires HIGH confidence & corroboration to block."""
    # LOW risk -> ALLOW
    dec_low = adaptive_engine.evaluate({"flow_id": "CON-01", "final_class": "BENIGN", "assessment": "BENIGN", "risk_level": "LOW", "confidence_level": "HIGH"}, profile="CONSERVATIVE")
    assert dec_low.action == PolicyAction.ALLOW

    # MEDIUM risk -> ALERT
    dec_med = adaptive_engine.evaluate({"flow_id": "CON-02", "final_class": "PORT SCAN", "assessment": "SUSPICIOUS", "risk_level": "MEDIUM", "confidence_level": "HIGH"}, profile="CONSERVATIVE")
    assert dec_med.action == PolicyAction.ALERT

    # HIGH risk -> REVIEW
    dec_high = adaptive_engine.evaluate({"flow_id": "CON-03", "final_class": "DOS", "assessment": "MALICIOUS", "risk_level": "HIGH", "confidence_level": "HIGH"}, profile="CONSERVATIVE")
    assert dec_high.action == PolicyAction.REVIEW

    # CRITICAL risk with MEDIUM confidence -> REVIEW (downgraded to prevent false blocking)
    crit_med_conf = {
        "flow_id": "CON-04",
        "final_class": "DDOS",
        "assessment": "MALICIOUS",
        "risk_level": "CRITICAL",
        "confidence_level": "MEDIUM",  # Not HIGH!
        "evidence_status": "AGREEMENT",
    }
    dec_crit_med = adaptive_engine.evaluate(crit_med_conf, profile="CONSERVATIVE")
    assert dec_crit_med.action == PolicyAction.REVIEW
    assert dec_crit_med.requires_human_review is True
    assert dec_crit_med.matched_rule == "RULE_CONSERVATIVE_DOWNGRADE_UNVERIFIED_BLOCK"

    # CRITICAL risk with HIGH confidence AND corroboration -> BLOCK
    crit_high_conf_corroborated = {
        "flow_id": "CON-05",
        "final_class": "DDOS",
        "assessment": "MALICIOUS",
        "risk_level": "CRITICAL",
        "confidence_level": "HIGH",
        "evidence_status": "AGREEMENT",
        "metadata": {"supporting_evidence": ["signature verified", "anomaly loss 0.95"]},
    }
    dec_crit_high = adaptive_engine.evaluate(crit_high_conf_corroborated, profile="CONSERVATIVE")
    assert dec_crit_high.action == PolicyAction.BLOCK
    assert dec_crit_high.matched_rule == "RULE_CONSERVATIVE_BLOCK_CRITICAL_CORROBORATED"

    # CRITICAL risk with HIGH confidence but WITHOUT supporting evidence -> REVIEW
    crit_high_no_support = {
        "flow_id": "CON-06",
        "final_class": "DDOS",
        "assessment": "MALICIOUS",
        "risk_level": "CRITICAL",
        "confidence_level": "HIGH",
        "evidence_status": "PARTIAL_EVIDENCE",
        "metadata": {"supporting_evidence": []},
    }
    dec_no_support = adaptive_engine.evaluate(crit_high_no_support, profile="CONSERVATIVE")
    assert dec_no_support.action == PolicyAction.REVIEW
    assert dec_no_support.matched_rule == "RULE_CONSERVATIVE_REQUIRE_SUPPORTING_EVIDENCE"


# =============================================================================
# 4. Same Assessment Under All Three Profiles (Meaningful Differences)
# =============================================================================
def test_same_assessment_under_all_three_profiles(adaptive_engine):
    """Scenario 4: Verify same assessment produces meaningfully different decisions across profiles."""
    # Test Case A: Medium risk attack signature
    # STRICT escalates to REVIEW, while BALANCED and CONSERVATIVE assign ALERT
    med_attack_flow = {
        "flow_id": "FLOW-DIFF-01",
        "final_class": "PORT SCAN",
        "assessment": "SUSPICIOUS",
        "risk_level": "MEDIUM",
        "confidence_level": "HIGH",
    }
    dec_strict_a = adaptive_engine.evaluate(med_attack_flow, profile="STRICT")
    dec_bal_a = adaptive_engine.evaluate(med_attack_flow, profile="BALANCED")
    dec_con_a = adaptive_engine.evaluate(med_attack_flow, profile="CONSERVATIVE")

    assert dec_strict_a.action == PolicyAction.REVIEW
    assert dec_bal_a.action == PolicyAction.ALERT
    assert dec_con_a.action == PolicyAction.ALERT

    # Test Case B: Critical risk with MEDIUM confidence
    # STRICT and BALANCED assign BLOCK, but CONSERVATIVE downgrades to REVIEW
    crit_med_flow = {
        "flow_id": "FLOW-DIFF-02",
        "final_class": "DDOS",
        "assessment": "MALICIOUS",
        "risk_level": "CRITICAL",
        "confidence_level": "MEDIUM",
        "evidence_status": "AGREEMENT",
    }
    dec_strict_b = adaptive_engine.evaluate(crit_med_flow, profile="STRICT")
    dec_bal_b = adaptive_engine.evaluate(crit_med_flow, profile="BALANCED")
    dec_con_b = adaptive_engine.evaluate(crit_med_flow, profile="CONSERVATIVE")

    assert dec_strict_b.action == PolicyAction.BLOCK
    assert dec_bal_b.action == PolicyAction.BLOCK
    assert dec_con_b.action == PolicyAction.REVIEW  # Meaningful conservative protection!

    # Test Case C: Conflicting evidence (disagreement) on low-risk flow
    # STRICT & BALANCED escalate to REVIEW, CONSERVATIVE emits ALERT
    disagree_flow = {
        "flow_id": "FLOW-DIFF-03",
        "final_class": "BENIGN",
        "assessment": "BENIGN",
        "risk_level": "LOW",
        "confidence_level": "LOW",
        "evidence_status": "DISAGREEMENT",
    }
    dec_strict_c = adaptive_engine.evaluate(disagree_flow, profile="STRICT")
    dec_bal_c = adaptive_engine.evaluate(disagree_flow, profile="BALANCED")
    dec_con_c = adaptive_engine.evaluate(disagree_flow, profile="CONSERVATIVE")

    assert dec_strict_c.action == PolicyAction.REVIEW
    assert dec_bal_c.action == PolicyAction.REVIEW
    assert dec_con_c.action == PolicyAction.ALERT


# =============================================================================
# 5. Runtime Profile Selection
# =============================================================================
def test_runtime_profile_selection(adaptive_engine):
    """Scenario 5: Verify runtime profile selection switches behavior dynamically."""
    flow = {
        "flow_id": "FLOW-RUN-01",
        "final_class": "BRUTE FORCE",
        "assessment": "SUSPICIOUS",
        "risk_level": "MEDIUM",
        "confidence_level": "HIGH",
    }

    # Default profile is BALANCED -> ALERT
    dec_default = adaptive_engine.evaluate(flow)
    assert dec_default.policy_profile == "BALANCED"
    assert dec_default.action == PolicyAction.ALERT

    # Override at runtime to STRICT -> REVIEW
    dec_strict = adaptive_engine.evaluate(flow, profile="STRICT")
    assert dec_strict.policy_profile == "STRICT"
    assert dec_strict.action == PolicyAction.REVIEW

    # Override at runtime to CONSERVATIVE -> ALERT
    dec_con = adaptive_engine.evaluate(flow, profile="CONSERVATIVE")
    assert dec_con.policy_profile == "CONSERVATIVE"
    assert dec_con.action == PolicyAction.ALERT


# =============================================================================
# 6. Missing Assessment Handling
# =============================================================================
def test_missing_assessment_handling(adaptive_engine):
    """Scenario 6: Missing assessment returns REVIEW (never ALLOW) across all profiles."""
    for prof in ("STRICT", "BALANCED", "CONSERVATIVE"):
        dec = adaptive_engine.evaluate(None, profile=prof, raise_on_error=False)
        assert dec.action == PolicyAction.REVIEW
        assert dec.action != PolicyAction.ALLOW
        assert dec.requires_human_review is True
        assert dec.matched_rule == "RULE_SAFETY_MISSING_ASSESSMENT"

    # With raise_on_error=True
    with pytest.raises(MissingAssessmentError):
        adaptive_engine.evaluate(None, raise_on_error=True)


# =============================================================================
# 7. Insufficient Evidence Override
# =============================================================================
def test_insufficient_evidence_override(adaptive_engine):
    """Scenario 7: INSUFFICIENT_EVIDENCE or UNKNOWN risk forces REVIEW across all profiles."""
    insufficient = {
        "flow_id": "FLOW-INSUF-01",
        "final_class": "UNKNOWN",
        "assessment": "INCONCLUSIVE",
        "risk_level": "UNKNOWN",
        "confidence_level": "LOW",
        "evidence_status": "INSUFFICIENT_EVIDENCE",
    }
    for prof in ("STRICT", "BALANCED", "CONSERVATIVE"):
        dec = adaptive_engine.evaluate(insufficient, profile=prof)
        assert dec.action == PolicyAction.REVIEW
        assert dec.action != PolicyAction.ALLOW
        assert dec.requires_human_review is True
        assert dec.matched_rule == "RULE_OVERRIDE_INSUFFICIENT_EVIDENCE"


# =============================================================================
# 8. Conflicting Evidence Override
# =============================================================================
def test_conflicting_evidence_override(adaptive_engine):
    """Scenario 8: Conflicting evidence overrides ALLOW to REVIEW or ALERT."""
    conflicting = {
        "flow_id": "FLOW-CONFLICT-01",
        "final_class": "BENIGN",
        "assessment": "BENIGN",
        "risk_level": "LOW",
        "confidence_level": "LOW",
        "evidence_status": "DISAGREEMENT",
    }
    # In STRICT -> REVIEW
    dec_strict = adaptive_engine.evaluate(conflicting, profile="STRICT")
    assert dec_strict.action == PolicyAction.REVIEW

    # In BALANCED -> REVIEW
    dec_bal = adaptive_engine.evaluate(conflicting, profile="BALANCED")
    assert dec_bal.action == PolicyAction.REVIEW

    # In CONSERVATIVE -> ALERT
    dec_con = adaptive_engine.evaluate(conflicting, profile="CONSERVATIVE")
    assert dec_con.action == PolicyAction.ALERT


# =============================================================================
# 9. Low Confidence Block Prevention
# =============================================================================
def test_low_confidence_prevents_automatic_block(adaptive_engine):
    """Scenario 9: Low confidence assessments must not automatically result in BLOCK."""
    low_conf_crit = {
        "flow_id": "FLOW-LOW-CONF-01",
        "final_class": "DDOS",
        "assessment": "MALICIOUS",
        "risk_level": "CRITICAL",
        "confidence_level": "LOW",  # Low confidence
        "evidence_status": "AGREEMENT",
    }
    for prof in ("STRICT", "BALANCED", "CONSERVATIVE"):
        dec = adaptive_engine.evaluate(low_conf_crit, profile=prof)
        assert dec.action != PolicyAction.BLOCK
        assert dec.action == PolicyAction.REVIEW
        assert dec.requires_human_review is True


# =============================================================================
# 10. Suspicious BENIGN Prediction Override
# =============================================================================
def test_suspicious_benign_prediction_override(adaptive_engine):
    """Scenario 10: Suspicious BENIGN predictions must never automatically receive ALLOW."""
    suspicious_benign = {
        "flow_id": "FLOW-SUSP-01",
        "final_class": "BENIGN",
        "assessment": "SUSPICIOUS",
        "risk_level": "HIGH",
        "confidence_level": "LOW",
        "evidence_status": "DISAGREEMENT",
    }
    for prof in ("STRICT", "BALANCED", "CONSERVATIVE"):
        dec = adaptive_engine.evaluate(suspicious_benign, profile=prof)
        assert dec.action != PolicyAction.ALLOW
        assert dec.action == PolicyAction.REVIEW
        assert dec.requires_human_review is True


# =============================================================================
# 11. Deterministic Repeated Decisions
# =============================================================================
def test_deterministic_repeated_decisions(adaptive_engine):
    """Scenario 11: 50 repeated evaluations yield identical policy actions and rules."""
    assessment = {
        "flow_id": "FLOW-REPEAT-01",
        "final_class": "DOS",
        "assessment": "MALICIOUS",
        "risk_level": "HIGH",
        "confidence_level": "HIGH",
    }
    first = adaptive_engine.evaluate(assessment, profile="STRICT")

    for _ in range(50):
        subsequent = adaptive_engine.evaluate(assessment, profile="STRICT")
        assert subsequent.action == first.action
        assert subsequent.matched_rule == first.matched_rule
        assert subsequent.decision_reason == first.decision_reason
        assert subsequent.requires_human_review == first.requires_human_review


# =============================================================================
# 12. Integration with Agent 3 process_flow
# =============================================================================
def test_integration_with_agent3_process_flow():
    """Scenario 12: Verify full pipeline from Agent 3 process_flow to AdaptivePolicyEngine."""
    a1 = {"predicted_class": "DDOS", "confidence": 0.95}
    a2 = {"anomaly_score": 0.90, "anomaly_detected": True, "evidence": ["massive burst"]}
    a3_res = process_flow(a1, a2, flow_id="FLOW-PIPE-A3A4")

    # Evaluate directly with convenience function
    dec = evaluate_adaptive_policy(a3_res, profile="BALANCED")
    assert dec.flow_id == "FLOW-PIPE-A3A4"
    assert dec.action == PolicyAction.BLOCK
    assert dec.simulated is True
    assert dec.policy_profile == "BALANCED"


# =============================================================================
# 13. Invalid Profile Error Handling
# =============================================================================
def test_invalid_profile_raises_error(adaptive_engine):
    """Scenario 13: Requesting an unknown profile raises InvalidProfileError."""
    with pytest.raises(InvalidProfileError):
        adaptive_engine.evaluate({"flow_id": "F1", "risk_level": "LOW", "confidence_level": "HIGH"}, profile="INVALID_PROFILE")

