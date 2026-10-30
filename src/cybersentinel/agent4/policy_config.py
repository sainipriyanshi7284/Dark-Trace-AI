"""Policy configuration and threshold specifications for CyberSentinel Agent 4.

Separates policy thresholds, action mappings, and safety overrides from evaluation logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from cybersentinel.agent4.contract import PolicyAction, PolicyProfile
from cybersentinel.agent4.exceptions import PolicyConfigurationError


@dataclass
class PolicyConfig:
    """Configurable policy thresholds, action mappings, and safety overrides.

    Attributes:
        policy_profile: Operational profile name (DEFAULT, STRICT, PERMISSIVE).
        risk_action_mapping: Mapping of risk levels (LOW, MEDIUM, HIGH, CRITICAL) to PolicyActions.
        override_insufficient_evidence: If True, forces REVIEW when evidence is insufficient or unknown.
        override_evidence_disagreement: If True, overrides ALLOW when agents disagree.
        disagreement_action: Action to assign on evidence disagreement (default: REVIEW).
        override_low_confidence_block: If True, prevents automatic BLOCK when confidence is LOW.
        low_confidence_fallback_action: Action assigned when BLOCK is downgraded due to low confidence (default: REVIEW).
        override_suspicious_benign: If True, prevents ALLOW when BENIGN class is paired with suspicious/high-risk flags.
        suspicious_benign_action: Action assigned when suspicious BENIGN is intercepted (default: REVIEW).
        malformed_input_action: Fallback action when input is missing or malformed (default: REVIEW, never ALLOW).
        simulated_enforcement: True ensuring all BLOCK decisions remain simulated only.
    """
    policy_profile: PolicyProfile = PolicyProfile.DEFAULT
    risk_action_mapping: Dict[str, PolicyAction] = field(
        default_factory=lambda: {
            "LOW": PolicyAction.ALLOW,
            "MEDIUM": PolicyAction.ALERT,
            "HIGH": PolicyAction.REVIEW,
            "CRITICAL": PolicyAction.BLOCK,
        }
    )
    override_insufficient_evidence: bool = True
    override_evidence_disagreement: bool = True
    disagreement_action: PolicyAction = PolicyAction.REVIEW
    override_low_confidence_block: bool = True
    low_confidence_fallback_action: PolicyAction = PolicyAction.REVIEW
    override_suspicious_benign: bool = True
    suspicious_benign_action: PolicyAction = PolicyAction.REVIEW
    malformed_input_action: PolicyAction = PolicyAction.REVIEW
    simulated_enforcement: bool = True

    def validate(self) -> None:
        """Validate configuration settings."""
        valid_risks = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        for r in valid_risks:
            if r not in self.risk_action_mapping:
                raise PolicyConfigurationError(f"Missing risk mapping for '{r}'.")
            action = self.risk_action_mapping[r]
            if not isinstance(action, PolicyAction):
                try:
                    self.risk_action_mapping[r] = PolicyAction(action)
                except ValueError as exc:
                    raise PolicyConfigurationError(f"Invalid policy action '{action}' for risk '{r}'.") from exc

        # Ensure fallback actions are never ALLOW
        if self.malformed_input_action == PolicyAction.ALLOW:
            raise PolicyConfigurationError("malformed_input_action must never be ALLOW.")

    @classmethod
    def default_profile(cls) -> PolicyConfig:
        """Default balanced operational profile."""
        return cls(policy_profile=PolicyProfile.DEFAULT)

    @classmethod
    def strict_profile(cls) -> PolicyConfig:
        """Strict operational posture profile with aggressive containment."""
        return cls(
            policy_profile=PolicyProfile.STRICT,
            risk_action_mapping={
                "LOW": PolicyAction.ALLOW,
                "MEDIUM": PolicyAction.REVIEW,
                "HIGH": PolicyAction.BLOCK,
                "CRITICAL": PolicyAction.BLOCK,
            },
            override_insufficient_evidence=True,
            override_evidence_disagreement=True,
            disagreement_action=PolicyAction.REVIEW,
            override_low_confidence_block=True,
            low_confidence_fallback_action=PolicyAction.REVIEW,
            override_suspicious_benign=True,
            suspicious_benign_action=PolicyAction.REVIEW,
            malformed_input_action=PolicyAction.REVIEW,
        )

    @classmethod
    def permissive_profile(cls) -> PolicyConfig:
        """Permissive operational posture profile prioritizing continuity."""
        return cls(
            policy_profile=PolicyProfile.PERMISSIVE,
            risk_action_mapping={
                "LOW": PolicyAction.ALLOW,
                "MEDIUM": PolicyAction.ALLOW,
                "HIGH": PolicyAction.ALERT,
                "CRITICAL": PolicyAction.BLOCK,
            },
            override_insufficient_evidence=True,
            override_evidence_disagreement=True,
            disagreement_action=PolicyAction.ALERT,
            override_low_confidence_block=True,
            low_confidence_fallback_action=PolicyAction.ALERT,
            override_suspicious_benign=True,
            suspicious_benign_action=PolicyAction.ALERT,
            malformed_input_action=PolicyAction.REVIEW,
        )

