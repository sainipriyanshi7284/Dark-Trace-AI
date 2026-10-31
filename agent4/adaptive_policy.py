"""Adaptive policy engine supporting dynamic operational profiles for CyberSentinel Agent 4.

Profiles:
  - STRICT: Prioritizes security and early threat escalation.
  - BALANCED: Balances security protection and operational disruption.
  - CONSERVATIVE: Minimizes unnecessary blocking; requires HIGH confidence and corroborating evidence to block.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union

from cybersentinel.agent4.audit_log import PolicyAuditLogger
from cybersentinel.agent4.contract import (
    PolicyAction,
    PolicyDecision,
    PolicyProfile,
    ValidatedThreatAssessment,
    parse_assessment_input,
)
from cybersentinel.agent4.exceptions import (
    InvalidProfileError,
    PolicyConfigurationError,
    PolicyExecutionError,
    PolicyInputError,
)
from cybersentinel.agent4.policy_config import PolicyConfig

logger = logging.getLogger(__name__)


class AdaptivePolicyEngine:
    """Adaptive Multi-Profile Policy Engine for CyberSentinel Agent 4.

    Evaluates Agent 3 threat assessments under dynamically selected operational
    profiles (STRICT, BALANCED, CONSERVATIVE) with transparent explainability and
    optional audit logging.
    """

    def __init__(
        self,
        default_profile: Union[str, PolicyProfile] = PolicyProfile.BALANCED,
        config: Optional[PolicyConfig] = None,
        audit_logger: Optional[PolicyAuditLogger] = None,
    ) -> None:
        """Initialize AdaptivePolicyEngine.

        Args:
            default_profile: Operational profile to use when not specified at runtime.
            config: Optional base PolicyConfig instance.
            audit_logger: Optional PolicyAuditLogger instance for automated audit trail.
        """
        self.default_profile = self._normalize_profile(default_profile)
        self.config = config
        self.audit_logger = audit_logger
        logger.info("Initialized AdaptivePolicyEngine (default_profile=%s)", self.default_profile.value)

    @staticmethod
    def _normalize_profile(profile: Union[str, PolicyProfile]) -> PolicyProfile:
        """Convert input string or enum into a validated PolicyProfile."""
        if isinstance(profile, PolicyProfile):
            return profile
        raw = str(profile).strip().upper()
        if raw in ("STRICT",):
            return PolicyProfile.STRICT
        elif raw in ("BALANCED", "DEFAULT"):
            return PolicyProfile.BALANCED
        elif raw in ("CONSERVATIVE", "PERMISSIVE"):
            return PolicyProfile.CONSERVATIVE
        else:
            raise InvalidProfileError(
                f"Unknown policy profile '{profile}'. Supported profiles: STRICT, BALANCED, CONSERVATIVE."
            )

    def evaluate(
        self,
        assessment: Any,
        profile: Optional[Union[str, PolicyProfile]] = None,
        raise_on_error: bool = False,
    ) -> PolicyDecision:
        """Evaluate an assessment under the specified operational profile.

        Args:
            assessment: Agent 3 threat assessment (object, dict, or JSON string).
            profile: Profile to apply (STRICT, BALANCED, CONSERVATIVE). If omitted,
                     uses default_profile.
            raise_on_error: If True, raises exceptions on missing/malformed inputs.
                            If False, safely degrades to REVIEW (never ALLOW).

        Returns:
            PolicyDecision: Structured policy decision with explainability audit fields.
        """
        now_ts = datetime.now(timezone.utc).isoformat()
        active_profile = self._normalize_profile(profile) if profile else self.default_profile
        prof_name = active_profile.value

        # ---------------------------------------------------------------------
        # 1. Ingest and Validate Assessment Input
        # ---------------------------------------------------------------------
        validated, err_msg = parse_assessment_input(assessment, raise_on_error=raise_on_error)

        if validated is None:
            flow_id = "UNKNOWN"
            if isinstance(assessment, dict):
                flow_id = str(assessment.get("flow_id") or "UNKNOWN")
            elif hasattr(assessment, "flow_id"):
                flow_id = str(getattr(assessment, "flow_id", "UNKNOWN"))

            matched_rule = (
                "RULE_SAFETY_MISSING_ASSESSMENT" if assessment is None else "RULE_SAFETY_MALFORMED_INPUT"
            )
            reason = (
                f"Missing or malformed assessment payload ({err_msg or 'Input is None'}). "
                f"Defaulting safely to REVIEW (never ALLOW) under {prof_name} profile."
            )

            decision = PolicyDecision(
                agent_id="A4",
                flow_id=flow_id,
                action=PolicyAction.REVIEW,
                policy_profile=prof_name,
                risk_level="UNKNOWN",
                confidence_level="LOW",
                evidence_status="INSUFFICIENT_EVIDENCE",
                matched_rule=matched_rule,
                decision_reason=reason,
                requires_human_review=True,
                simulated=True,
                timestamp=now_ts,
            )
            if self.audit_logger:
                self.audit_logger.append_record(decision, fusion_score=None)
            return decision

        # ---------------------------------------------------------------------
        # 2. Safety Override: Insufficient Evidence or Unknown Risk
        # ---------------------------------------------------------------------
        if (
            validated.evidence_status == "INSUFFICIENT_EVIDENCE"
            or validated.risk_level == "UNKNOWN"
            or validated.assessment == "INCONCLUSIVE"
        ):
            decision = PolicyDecision(
                agent_id="A4",
                flow_id=validated.flow_id,
                action=PolicyAction.REVIEW,
                policy_profile=prof_name,
                risk_level=validated.risk_level,
                confidence_level=validated.confidence_level,
                evidence_status=validated.evidence_status,
                matched_rule="RULE_OVERRIDE_INSUFFICIENT_EVIDENCE",
                decision_reason=(
                    f"Insufficient evidence provided by upstream agents (status: {validated.evidence_status}, "
                    f"risk: {validated.risk_level}). Escalating safely to human review under {prof_name} profile."
                ),
                requires_human_review=True,
                simulated=True,
                timestamp=now_ts,
                metadata=validated.metadata,
            )
            if self.audit_logger:
                self.audit_logger.append_record(decision, fusion_score=validated.fusion_score)
            return decision

        # ---------------------------------------------------------------------
        # 3. Profile-Specific Policy Evaluation
        # ---------------------------------------------------------------------
        if active_profile == PolicyProfile.STRICT:
            decision = self._evaluate_strict(validated, prof_name, now_ts)
        elif active_profile == PolicyProfile.CONSERVATIVE:
            decision = self._evaluate_conservative(validated, prof_name, now_ts)
        else:  # BALANCED
            decision = self._evaluate_balanced(validated, prof_name, now_ts)

        # ---------------------------------------------------------------------
        # 4. Audit Logging Integration
        # ---------------------------------------------------------------------
        if self.audit_logger:
            self.audit_logger.append_record(decision, fusion_score=validated.fusion_score)

        return decision

    def _evaluate_strict(
        self,
        val: ValidatedThreatAssessment,
        prof_name: str,
        now_ts: str,
    ) -> PolicyDecision:
        """Evaluate under STRICT profile: early threat escalation, sensitive containment."""
        # 1. Low-confidence block prevention
        if val.risk_level == "CRITICAL" and val.confidence_level == "LOW":
            return PolicyDecision(
                agent_id="A4",
                flow_id=val.flow_id,
                action=PolicyAction.REVIEW,
                policy_profile=prof_name,
                risk_level=val.risk_level,
                confidence_level=val.confidence_level,
                evidence_status=val.evidence_status,
                matched_rule="RULE_STRICT_LOW_CONFIDENCE_BLOCK_PREVENTION",
                decision_reason=(
                    "Critical risk indicated, but confidence is LOW. Automatic simulated BLOCK prevented; "
                    "downgraded to REVIEW for manual analyst verification under STRICT profile."
                ),
                requires_human_review=True,
                simulated=True,
                timestamp=now_ts,
                metadata=val.metadata,
            )

        # 2. Conflicting evidence escalation to REVIEW
        if val.evidence_status == "DISAGREEMENT":
            return PolicyDecision(
                agent_id="A4",
                flow_id=val.flow_id,
                action=PolicyAction.REVIEW,
                policy_profile=prof_name,
                risk_level=val.risk_level,
                confidence_level=val.confidence_level,
                evidence_status=val.evidence_status,
                matched_rule="RULE_STRICT_OVERRIDE_CONFLICTING_EVIDENCE",
                decision_reason=(
                    "Significant evidence divergence detected between upstream agents. "
                    "Escalating flow to REVIEW under STRICT security profile."
                ),
                requires_human_review=True,
                simulated=True,
                timestamp=now_ts,
                metadata=val.metadata,
            )

        # 3. Suspicious BENIGN prediction escalation
        is_suspicious_benign = (
            val.final_class == "BENIGN"
            and (
                val.assessment in ("SUSPICIOUS", "MALICIOUS")
                or val.risk_level in ("HIGH", "CRITICAL", "MEDIUM")
            )
        )
        if is_suspicious_benign:
            return PolicyDecision(
                agent_id="A4",
                flow_id=val.flow_id,
                action=PolicyAction.REVIEW,
                policy_profile=prof_name,
                risk_level=val.risk_level,
                confidence_level=val.confidence_level,
                evidence_status=val.evidence_status,
                matched_rule="RULE_STRICT_ESCALATE_SUSPICIOUS_BENIGN",
                decision_reason=(
                    f"Traffic predicted as BENIGN, but flagged as {val.assessment} with "
                    f"{val.risk_level} risk by fusion engine (potential evasion/zero-day). "
                    "Escalating to REVIEW under STRICT profile."
                ),
                requires_human_review=True,
                simulated=True,
                timestamp=now_ts,
                metadata=val.metadata,
            )

        # 4. Early threat escalation at MEDIUM risk
        # In STRICT profile, any detected attack signature or suspicious assessment at MEDIUM risk is escalated to REVIEW
        if val.risk_level == "MEDIUM" and (
            val.final_class != "BENIGN"
            or val.assessment in ("SUSPICIOUS", "MALICIOUS")
            or val.investigation_priority in ("HIGH", "CRITICAL")
        ):
            return PolicyDecision(
                agent_id="A4",
                flow_id=val.flow_id,
                action=PolicyAction.REVIEW,
                policy_profile=prof_name,
                risk_level=val.risk_level,
                confidence_level=val.confidence_level,
                evidence_status=val.evidence_status,
                matched_rule="RULE_STRICT_ESCALATE_SUSPICIOUS_THREAT",
                decision_reason=(
                    f"Early threat escalation: attack indicator ({val.final_class}) assessed at "
                    f"MEDIUM risk escalated from ALERT to REVIEW under STRICT profile."
                ),
                requires_human_review=True,
                simulated=True,
                timestamp=now_ts,
                metadata=val.metadata,
            )

        # 5. Base mappings
        if val.risk_level == "CRITICAL":
            return PolicyDecision(
                agent_id="A4",
                flow_id=val.flow_id,
                action=PolicyAction.BLOCK,
                policy_profile=prof_name,
                risk_level=val.risk_level,
                confidence_level=val.confidence_level,
                evidence_status=val.evidence_status,
                matched_rule="RULE_BASE_BLOCK_CRITICAL_RISK",
                decision_reason=(
                    f"Critical risk verified with {val.confidence_level} confidence (attack: {val.final_class}). "
                    "Simulated BLOCK engaged under STRICT profile."
                ),
                requires_human_review=False,
                simulated=True,
                timestamp=now_ts,
                metadata=val.metadata,
            )
        elif val.risk_level == "HIGH":
            return PolicyDecision(
                agent_id="A4",
                flow_id=val.flow_id,
                action=PolicyAction.REVIEW,
                policy_profile=prof_name,
                risk_level=val.risk_level,
                confidence_level=val.confidence_level,
                evidence_status=val.evidence_status,
                matched_rule="RULE_BASE_REVIEW_HIGH_RISK",
                decision_reason=f"High risk ({val.risk_level}). Escalated to SOC analyst under STRICT profile.",
                requires_human_review=True,
                simulated=True,
                timestamp=now_ts,
                metadata=val.metadata,
            )
        elif val.risk_level == "MEDIUM":
            return PolicyDecision(
                agent_id="A4",
                flow_id=val.flow_id,
                action=PolicyAction.ALERT,
                policy_profile=prof_name,
                risk_level=val.risk_level,
                confidence_level=val.confidence_level,
                evidence_status=val.evidence_status,
                matched_rule="RULE_BASE_ALERT_MEDIUM_RISK",
                decision_reason=f"Moderate risk ({val.risk_level}). SIEM alert generated under STRICT profile.",
                requires_human_review=False,
                simulated=True,
                timestamp=now_ts,
                metadata=val.metadata,
            )
        else:  # LOW
            return PolicyDecision(
                agent_id="A4",
                flow_id=val.flow_id,
                action=PolicyAction.ALLOW,
                policy_profile=prof_name,
                risk_level=val.risk_level,
                confidence_level=val.confidence_level,
                evidence_status=val.evidence_status,
                matched_rule="RULE_BASE_ALLOW_LOW_RISK",
                decision_reason=f"Verified low risk ({val.risk_level}). Flow permitted under STRICT profile.",
                requires_human_review=False,
                simulated=True,
                timestamp=now_ts,
                metadata=val.metadata,
            )

    def _evaluate_balanced(
        self,
        val: ValidatedThreatAssessment,
        prof_name: str,
        now_ts: str,
    ) -> PolicyDecision:
        """Evaluate under BALANCED profile: standard balanced security posture."""
        # 1. Base action mapping
        if val.risk_level == "CRITICAL":
            action = PolicyAction.BLOCK
            matched_rule = "RULE_BASE_BLOCK_CRITICAL_RISK"
        elif val.risk_level == "HIGH":
            action = PolicyAction.REVIEW
            matched_rule = "RULE_BASE_REVIEW_HIGH_RISK"
        elif val.risk_level == "MEDIUM":
            action = PolicyAction.ALERT
            matched_rule = "RULE_BASE_ALERT_MEDIUM_RISK"
        else:
            action = PolicyAction.ALLOW
            matched_rule = "RULE_BASE_ALLOW_LOW_RISK"

        # 2. Suspicious BENIGN override on ALLOW
        is_suspicious_benign = (
            val.final_class == "BENIGN"
            and (
                val.assessment in ("SUSPICIOUS", "MALICIOUS")
                or val.risk_level in ("HIGH", "CRITICAL", "MEDIUM")
            )
        )
        if is_suspicious_benign and action == PolicyAction.ALLOW:
            return PolicyDecision(
                agent_id="A4",
                flow_id=val.flow_id,
                action=PolicyAction.REVIEW,
                policy_profile=prof_name,
                risk_level=val.risk_level,
                confidence_level=val.confidence_level,
                evidence_status=val.evidence_status,
                matched_rule="RULE_OVERRIDE_SUSPICIOUS_BENIGN",
                decision_reason=(
                    f"Traffic predicted as BENIGN, but flagged as {val.assessment} with "
                    f"{val.risk_level} risk by fusion engine (potential evasion/zero-day). "
                    "Overriding ALLOW to REVIEW under BALANCED profile."
                ),
                requires_human_review=True,
                simulated=True,
                timestamp=now_ts,
                metadata=val.metadata,
            )

        # 3. Disagreement override on ALLOW
        if val.evidence_status == "DISAGREEMENT" and action == PolicyAction.ALLOW:
            return PolicyDecision(
                agent_id="A4",
                flow_id=val.flow_id,
                action=PolicyAction.REVIEW,
                policy_profile=prof_name,
                risk_level=val.risk_level,
                confidence_level=val.confidence_level,
                evidence_status=val.evidence_status,
                matched_rule="RULE_OVERRIDE_EVIDENCE_DISAGREEMENT",
                decision_reason=(
                    "Significant evidence divergence detected between upstream agents. "
                    "Overriding ALLOW to REVIEW for SOC inspection under BALANCED profile."
                ),
                requires_human_review=True,
                simulated=True,
                timestamp=now_ts,
                metadata=val.metadata,
            )

        # 4. Low-confidence block prevention
        if action == PolicyAction.BLOCK and val.confidence_level == "LOW":
            return PolicyDecision(
                agent_id="A4",
                flow_id=val.flow_id,
                action=PolicyAction.REVIEW,
                policy_profile=prof_name,
                risk_level=val.risk_level,
                confidence_level=val.confidence_level,
                evidence_status=val.evidence_status,
                matched_rule="RULE_OVERRIDE_LOW_CONFIDENCE_BLOCK_PREVENTION",
                decision_reason=(
                    f"Critical risk indicated ({val.risk_level}), but confidence level is LOW. "
                    "Automatic simulated BLOCK prevented; downgraded to REVIEW for manual verification under BALANCED profile."
                ),
                requires_human_review=True,
                simulated=True,
                timestamp=now_ts,
                metadata=val.metadata,
            )

        # Formulate base decision reason
        if action == PolicyAction.ALLOW:
            reason = f"Verified low risk ({val.risk_level}). Flow permitted under BALANCED profile."
        elif action == PolicyAction.ALERT:
            reason = f"Moderate security risk ({val.risk_level}). Alert emitted under BALANCED profile."
        elif action == PolicyAction.REVIEW:
            reason = f"Elevated security risk ({val.risk_level}). Escalated to SOC analyst under BALANCED profile."
        else:
            reason = (
                f"Critical security risk ({val.risk_level}) corroborated with {val.confidence_level} "
                f"confidence (attack class: {val.final_class}). Automated simulated BLOCK engaged."
            )

        return PolicyDecision(
            agent_id="A4",
            flow_id=val.flow_id,
            action=action,
            policy_profile=prof_name,
            risk_level=val.risk_level,
            confidence_level=val.confidence_level,
            evidence_status=val.evidence_status,
            matched_rule=matched_rule,
            decision_reason=reason,
            requires_human_review=(action == PolicyAction.REVIEW),
            simulated=True,
            timestamp=now_ts,
            metadata=val.metadata,
        )

    def _evaluate_conservative(
        self,
        val: ValidatedThreatAssessment,
        prof_name: str,
        now_ts: str,
    ) -> PolicyDecision:
        """Evaluate under CONSERVATIVE profile: minimize unnecessary blocking."""
        # 1. Suspicious BENIGN override on ALLOW
        is_suspicious_benign = (
            val.final_class == "BENIGN"
            and (
                val.assessment in ("SUSPICIOUS", "MALICIOUS")
                or val.risk_level in ("HIGH", "CRITICAL", "MEDIUM")
            )
        )
        if is_suspicious_benign:
            return PolicyDecision(
                agent_id="A4",
                flow_id=val.flow_id,
                action=PolicyAction.REVIEW,
                policy_profile=prof_name,
                risk_level=val.risk_level,
                confidence_level=val.confidence_level,
                evidence_status=val.evidence_status,
                matched_rule="RULE_OVERRIDE_SUSPICIOUS_BENIGN",
                decision_reason=(
                    f"Traffic predicted as BENIGN, but flagged as {val.assessment} with "
                    f"{val.risk_level} risk by fusion engine (potential evasion/zero-day). "
                    "Overriding ALLOW to REVIEW under CONSERVATIVE profile."
                ),
                requires_human_review=True,
                simulated=True,
                timestamp=now_ts,
                metadata=val.metadata,
            )

        # 2. Conflicting evidence on ALLOW
        if val.evidence_status == "DISAGREEMENT":
            return PolicyDecision(
                agent_id="A4",
                flow_id=val.flow_id,
                action=PolicyAction.ALERT,
                policy_profile=prof_name,
                risk_level=val.risk_level,
                confidence_level=val.confidence_level,
                evidence_status=val.evidence_status,
                matched_rule="RULE_CONSERVATIVE_DISAGREEMENT_ALERT",
                decision_reason=(
                    "Evidence divergence detected between upstream agents. "
                    "Emitting security ALERT under CONSERVATIVE profile."
                ),
                requires_human_review=False,
                simulated=True,
                timestamp=now_ts,
                metadata=val.metadata,
            )

        # 3. CRITICAL risk blocking conditions in CONSERVATIVE profile:
        # "CRITICAL risk → REVIEW when confidence is not HIGH."
        # "CRITICAL risk with HIGH confidence and supporting evidence → BLOCK."
        if val.risk_level == "CRITICAL":
            if val.confidence_level != "HIGH":
                return PolicyDecision(
                    agent_id="A4",
                    flow_id=val.flow_id,
                    action=PolicyAction.REVIEW,
                    policy_profile=prof_name,
                    risk_level=val.risk_level,
                    confidence_level=val.confidence_level,
                    evidence_status=val.evidence_status,
                    matched_rule="RULE_CONSERVATIVE_DOWNGRADE_UNVERIFIED_BLOCK",
                    decision_reason=(
                        f"Critical risk indicated ({val.risk_level}), but confidence is {val.confidence_level} "
                        "(not HIGH). Downgrading BLOCK to REVIEW to minimize false disruption under CONSERVATIVE profile."
                    ),
                    requires_human_review=True,
                    simulated=True,
                    timestamp=now_ts,
                    metadata=val.metadata,
                )

            # Check supporting evidence
            supporting_list = val.metadata.get("supporting_evidence", [])
            has_corroboration = (
                val.evidence_status == "AGREEMENT"
                or (isinstance(supporting_list, list) and len(supporting_list) > 0)
            )

            if has_corroboration:
                return PolicyDecision(
                    agent_id="A4",
                    flow_id=val.flow_id,
                    action=PolicyAction.BLOCK,
                    policy_profile=prof_name,
                    risk_level=val.risk_level,
                    confidence_level=val.confidence_level,
                    evidence_status=val.evidence_status,
                    matched_rule="RULE_CONSERVATIVE_BLOCK_CRITICAL_CORROBORATED",
                    decision_reason=(
                        f"Critical risk corroborated with HIGH confidence and supporting evidence (attack: {val.final_class}). "
                        "Automated simulated BLOCK engaged under CONSERVATIVE profile."
                    ),
                    requires_human_review=False,
                    simulated=True,
                    timestamp=now_ts,
                    metadata=val.metadata,
                )
            else:
                return PolicyDecision(
                    agent_id="A4",
                    flow_id=val.flow_id,
                    action=PolicyAction.REVIEW,
                    policy_profile=prof_name,
                    risk_level=val.risk_level,
                    confidence_level=val.confidence_level,
                    evidence_status=val.evidence_status,
                    matched_rule="RULE_CONSERVATIVE_REQUIRE_SUPPORTING_EVIDENCE",
                    decision_reason=(
                        "Critical risk indicated with HIGH confidence, but corroborating multi-agent supporting "
                        "evidence is absent. Downgrading BLOCK to REVIEW under CONSERVATIVE profile."
                    ),
                    requires_human_review=True,
                    simulated=True,
                    timestamp=now_ts,
                    metadata=val.metadata,
                )

        # 4. Other base mappings for CONSERVATIVE
        if val.risk_level == "HIGH":
            return PolicyDecision(
                agent_id="A4",
                flow_id=val.flow_id,
                action=PolicyAction.REVIEW,
                policy_profile=prof_name,
                risk_level=val.risk_level,
                confidence_level=val.confidence_level,
                evidence_status=val.evidence_status,
                matched_rule="RULE_BASE_REVIEW_HIGH_RISK",
                decision_reason=f"High risk ({val.risk_level}). Escalated to SOC analyst under CONSERVATIVE profile.",
                requires_human_review=True,
                simulated=True,
                timestamp=now_ts,
                metadata=val.metadata,
            )
        elif val.risk_level == "MEDIUM":
            return PolicyDecision(
                agent_id="A4",
                flow_id=val.flow_id,
                action=PolicyAction.ALERT,
                policy_profile=prof_name,
                risk_level=val.risk_level,
                confidence_level=val.confidence_level,
                evidence_status=val.evidence_status,
                matched_rule="RULE_BASE_ALERT_MEDIUM_RISK",
                decision_reason=f"Moderate risk ({val.risk_level}). SIEM alert emitted under CONSERVATIVE profile.",
                requires_human_review=False,
                simulated=True,
                timestamp=now_ts,
                metadata=val.metadata,
            )
        else:  # LOW
            return PolicyDecision(
                agent_id="A4",
                flow_id=val.flow_id,
                action=PolicyAction.ALLOW,
                policy_profile=prof_name,
                risk_level=val.risk_level,
                confidence_level=val.confidence_level,
                evidence_status=val.evidence_status,
                matched_rule="RULE_BASE_ALLOW_LOW_RISK",
                decision_reason=f"Verified low risk ({val.risk_level}). Flow permitted under CONSERVATIVE profile.",
                requires_human_review=False,
                simulated=True,
                timestamp=now_ts,
                metadata=val.metadata,
            )


def evaluate_adaptive_policy(
    assessment: Any,
    profile: Union[str, PolicyProfile] = "BALANCED",
    audit_logger: Optional[PolicyAuditLogger] = None,
    raise_on_error: bool = False,
) -> PolicyDecision:
    """Convenience functional interface for evaluating adaptive policy decisions.

    Args:
        assessment: Threat assessment payload (object, dict, or JSON string).
        profile: Operational policy profile ('STRICT', 'BALANCED', 'CONSERVATIVE').
        audit_logger: Optional PolicyAuditLogger instance.
        raise_on_error: If True, raises exceptions on invalid inputs instead of returning safe REVIEW.

    Returns:
        PolicyDecision: Structured policy decision.
    """
    engine = AdaptivePolicyEngine(default_profile=profile, audit_logger=audit_logger)
    return engine.evaluate(assessment, profile=profile, raise_on_error=raise_on_error)

