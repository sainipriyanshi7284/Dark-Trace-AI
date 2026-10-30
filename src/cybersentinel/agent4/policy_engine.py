"""Core policy decision engine for CyberSentinel Agent 4.

Translates Agent 3 threat fusion assessments into calibrated, safe, and explainable
enforcement actions: ALLOW, ALERT, REVIEW, or BLOCK (simulated).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union

from cybersentinel.agent4.contract import (
    PolicyAction,
    PolicyDecision,
    PolicyProfile,
    ValidatedThreatAssessment,
    parse_assessment_input,
)
from cybersentinel.agent4.exceptions import (
    InvalidAssessmentError,
    PolicyConfigurationError,
    PolicyExecutionError,
    PolicyInputError,
)
from cybersentinel.agent4.policy_config import PolicyConfig

logger = logging.getLogger(__name__)


class PolicyEngine:
    """CyberSentinel Agent 4 Core Policy Engine.

    Evaluates upstream threat assessments against configurable risk profiles and
    applies strict safety overrides to prevent catastrophic false actions.

    Safety Invariants:
      1. Missing or malformed input must NEVER automatically result in ALLOW.
      2. BLOCK decisions are strictly SIMULATED (no real firewall operations).
      3. INSUFFICIENT_EVIDENCE must force REVIEW.
      4. Low confidence prevents automatic BLOCK.
      5. Suspicious BENIGN predictions are intercepted and never permitted blindly.
    """

    def __init__(self, config: Optional[PolicyConfig] = None) -> None:
        """Initialize the policy engine with optional custom configuration."""
        self.config = config or PolicyConfig.default_profile()
        self.config.validate()
        logger.info("Initialized PolicyEngine with profile: %s", self.config.policy_profile.value)

    def evaluate(
        self,
        assessment: Any,
        raise_on_error: bool = False,
    ) -> PolicyDecision:
        """Evaluate an Agent 3 assessment and determine the enforcement policy decision.

        Args:
            assessment: Agent 3 assessment (object, dict, or JSON string).
            raise_on_error: If True, raises exceptions on malformed or missing input.
                            If False, executes safe degradation to REVIEW (never ALLOW).

        Returns:
            PolicyDecision: Structured policy decision with audit fields.
        """
        now_ts = datetime.now(timezone.utc).isoformat()

        # ---------------------------------------------------------------------
        # 1. Ingest and Validate Assessment Input
        # ---------------------------------------------------------------------
        validated, err_msg = parse_assessment_input(assessment, raise_on_error=raise_on_error)

        if validated is None:
            # Safe Fallback: Missing or malformed input MUST NEVER result in ALLOW
            flow_id = "UNKNOWN"
            if isinstance(assessment, dict):
                flow_id = str(assessment.get("flow_id") or "UNKNOWN")
            elif hasattr(assessment, "flow_id"):
                flow_id = str(getattr(assessment, "flow_id", "UNKNOWN"))

            matched_rule = "RULE_SAFETY_MISSING_ASSESSMENT" if assessment is None else "RULE_SAFETY_MALFORMED_INPUT"
            reason = (
                f"Missing or malformed assessment payload ({err_msg or 'Input is None'}). "
                f"Defaulting safely to {self.config.malformed_input_action.value} (never ALLOW)."
            )

            return PolicyDecision(
                agent_id="A4",
                flow_id=flow_id,
                action=self.config.malformed_input_action,
                policy_profile=self.config.policy_profile.value,
                risk_level="UNKNOWN",
                confidence_level="LOW",
                matched_rule=matched_rule,
                decision_reason=reason,
                requires_human_review=True,
                simulated=self.config.simulated_enforcement,
                timestamp=now_ts,
            )

        # ---------------------------------------------------------------------
        # 2. Safety Override: Insufficient Evidence or Unknown Risk
        # ---------------------------------------------------------------------
        if self.config.override_insufficient_evidence and (
            validated.evidence_status == "INSUFFICIENT_EVIDENCE"
            or validated.risk_level == "UNKNOWN"
            or validated.assessment == "INCONCLUSIVE"
        ):
            return PolicyDecision(
                agent_id="A4",
                flow_id=validated.flow_id,
                action=PolicyAction.REVIEW,
                policy_profile=self.config.policy_profile.value,
                risk_level=validated.risk_level,
                confidence_level=validated.confidence_level,
                matched_rule="RULE_OVERRIDE_INSUFFICIENT_EVIDENCE",
                decision_reason=(
                    f"Insufficient evidence available (status: {validated.evidence_status}, "
                    f"risk: {validated.risk_level}). Escalating safely to human review."
                ),
                requires_human_review=True,
                simulated=self.config.simulated_enforcement,
                timestamp=now_ts,
                metadata=validated.metadata,
            )

        # ---------------------------------------------------------------------
        # 3. Base Risk-Action Mapping
        # ---------------------------------------------------------------------
        base_action = self.config.risk_action_mapping.get(validated.risk_level, PolicyAction.REVIEW)
        action = base_action
        matched_rule = f"RULE_BASE_{base_action.value}_{validated.risk_level}_RISK"
        decision_reason = (
            f"Base policy for {validated.risk_level} risk level selected action {base_action.value}."
        )
        requires_human_review = (action == PolicyAction.REVIEW)

        # ---------------------------------------------------------------------
        # 4. Safety Override: Suspicious BENIGN Prediction
        # ---------------------------------------------------------------------
        # If classifier predicted BENIGN, but fusion assessed SUSPICIOUS/MALICIOUS,
        # or elevated risk, do NOT permit blind ALLOW.
        is_suspicious_benign = (
            validated.final_class == "BENIGN"
            and (
                validated.assessment in ("SUSPICIOUS", "MALICIOUS")
                or validated.risk_level in ("HIGH", "CRITICAL", "MEDIUM")
            )
        )
        if self.config.override_suspicious_benign and is_suspicious_benign and action == PolicyAction.ALLOW:
            action = self.config.suspicious_benign_action
            matched_rule = "RULE_OVERRIDE_SUSPICIOUS_BENIGN"
            decision_reason = (
                f"Traffic predicted as BENIGN, but flagged as {validated.assessment} with "
                f"{validated.risk_level} risk by fusion engine (potential evasion/zero-day). "
                f"Overriding ALLOW to {action.value}."
            )
            requires_human_review = (action == PolicyAction.REVIEW)
            return PolicyDecision(
                agent_id="A4",
                flow_id=validated.flow_id,
                action=action,
                policy_profile=self.config.policy_profile.value,
                risk_level=validated.risk_level,
                confidence_level=validated.confidence_level,
                matched_rule=matched_rule,
                decision_reason=decision_reason,
                requires_human_review=requires_human_review,
                simulated=self.config.simulated_enforcement,
                timestamp=now_ts,
                metadata=validated.metadata,
            )

        # ---------------------------------------------------------------------
        # 5. Safety Override: Significant Evidence Disagreement
        # ---------------------------------------------------------------------
        if self.config.override_evidence_disagreement and validated.evidence_status == "DISAGREEMENT":
            if action == PolicyAction.ALLOW:
                action = self.config.disagreement_action
                matched_rule = "RULE_OVERRIDE_EVIDENCE_DISAGREEMENT"
                decision_reason = (
                    "Significant evidence divergence detected between upstream agents. "
                    f"Overriding ALLOW to {action.value} for analyst inspection."
                )
                requires_human_review = (action == PolicyAction.REVIEW)
                return PolicyDecision(
                    agent_id="A4",
                    flow_id=validated.flow_id,
                    action=action,
                    policy_profile=self.config.policy_profile.value,
                    risk_level=validated.risk_level,
                    confidence_level=validated.confidence_level,
                    matched_rule=matched_rule,
                    decision_reason=decision_reason,
                    requires_human_review=requires_human_review,
                    simulated=self.config.simulated_enforcement,
                    timestamp=now_ts,
                    metadata=validated.metadata,
                )

        # ---------------------------------------------------------------------
        # 6. Safety Override: Low Confidence Block Prevention
        # ---------------------------------------------------------------------
        if self.config.override_low_confidence_block and action == PolicyAction.BLOCK and validated.confidence_level == "LOW":
            action = self.config.low_confidence_fallback_action
            matched_rule = "RULE_OVERRIDE_LOW_CONFIDENCE_BLOCK_PREVENTION"
            decision_reason = (
                f"Critical risk indicated ({validated.risk_level}), but confidence level is LOW. "
                f"Automatic simulated BLOCK prevented; downgraded to {action.value} for manual verification."
            )
            requires_human_review = (action == PolicyAction.REVIEW)
            return PolicyDecision(
                agent_id="A4",
                flow_id=validated.flow_id,
                action=action,
                policy_profile=self.config.policy_profile.value,
                risk_level=validated.risk_level,
                confidence_level=validated.confidence_level,
                matched_rule=matched_rule,
                decision_reason=decision_reason,
                requires_human_review=requires_human_review,
                simulated=self.config.simulated_enforcement,
                timestamp=now_ts,
                metadata=validated.metadata,
            )

        # ---------------------------------------------------------------------
        # 7. Final Base Decision Formatting
        # ---------------------------------------------------------------------
        if action == PolicyAction.ALLOW:
            decision_reason = (
                f"Verified low security risk ({validated.risk_level}) with {validated.confidence_level} "
                f"confidence. Flow permitted under {self.config.policy_profile.value} policy profile."
            )
            requires_human_review = False
        elif action == PolicyAction.ALERT:
            decision_reason = (
                f"Moderate security risk ({validated.risk_level}) with {validated.confidence_level} "
                f"confidence. Automated security alert emitted for SIEM monitoring."
            )
            requires_human_review = False
        elif action == PolicyAction.REVIEW:
            decision_reason = (
                f"Elevated security risk ({validated.risk_level}) with {validated.confidence_level} "
                f"confidence. Escalated to Tier-2 SOC security analyst for manual review."
            )
            requires_human_review = True
        elif action == PolicyAction.BLOCK:
            decision_reason = (
                f"Critical security risk ({validated.risk_level}) corroborated with {validated.confidence_level} "
                f"confidence (attack class: {validated.final_class}). Automated simulated BLOCK policy engaged."
            )
            requires_human_review = False

        return PolicyDecision(
            agent_id="A4",
            flow_id=validated.flow_id,
            action=action,
            policy_profile=self.config.policy_profile.value,
            risk_level=validated.risk_level,
            confidence_level=validated.confidence_level,
            matched_rule=matched_rule,
            decision_reason=decision_reason,
            requires_human_review=requires_human_review,
            simulated=self.config.simulated_enforcement,
            timestamp=now_ts,
            metadata=validated.metadata,
        )


def evaluate_policy(
    assessment: Any,
    config: Optional[PolicyConfig] = None,
    raise_on_error: bool = False,
) -> PolicyDecision:
    """Convenience functional interface for evaluating Agent 4 policy decisions.

    Args:
        assessment: Threat assessment payload (object, dict, or JSON string).
        config: Optional custom PolicyConfig configuration.
        raise_on_error: If True, raises exceptions on invalid inputs instead of returning safe REVIEW.

    Returns:
        PolicyDecision: Structured policy decision with audit fields.
    """
    engine = PolicyEngine(config=config)
    return engine.evaluate(assessment, raise_on_error=raise_on_error)
