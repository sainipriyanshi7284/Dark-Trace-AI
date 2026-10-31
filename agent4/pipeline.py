"""End-to-end integration pipeline connecting Agent 3 (Fusion) and Agent 4 (Policy Enforcement).

Enables single-step execution from raw upstream detections (Agent 1 & Agent 2)
through validation, correlation, fusion scoring, explainability, adaptive policy
enforcement, and compliance audit logging.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from cybersentinel.agent3 import process_flow
from cybersentinel.agent3.schemas import Agent3ThreatAssessment
from cybersentinel.agent4.adaptive_policy import AdaptivePolicyEngine
from cybersentinel.agent4.audit_log import PolicyAuditLogger
from cybersentinel.agent4.contract import PolicyAction, PolicyDecision, PolicyProfile

logger = logging.getLogger(__name__)


@dataclass
class EnforcementResult:
    """Consolidated end-to-end result emitted by the CyberSentinel defense pipeline."""
    flow_id: str
    threat_assessment: Dict[str, Any]
    policy_decision: PolicyDecision
    profile: str
    action: PolicyAction
    risk_level: str
    confidence_level: str
    simulated: bool
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize complete enforcement result to dictionary."""
        return {
            "flow_id": self.flow_id,
            "threat_assessment": self.threat_assessment,
            "policy_decision": self.policy_decision.to_dict(),
            "profile": self.profile,
            "action": self.action.value,
            "risk_level": self.risk_level,
            "confidence_level": self.confidence_level,
            "simulated": self.simulated,
            "timestamp": self.timestamp,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize complete enforcement result to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


class CyberSentinelPipeline:
    """Unified multi-agent defense orchestrator linking Agent 3 and Agent 4."""

    def __init__(
        self,
        engine: Optional[AdaptivePolicyEngine] = None,
        audit_logger: Optional[PolicyAuditLogger] = None,
        default_profile: Union[str, PolicyProfile] = PolicyProfile.BALANCED,
    ) -> None:
        """Initialize the pipeline with engine, optional audit logger, and default profile.

        Args:
            engine: Optional AdaptivePolicyEngine instance.
            audit_logger: Optional PolicyAuditLogger instance.
            default_profile: Default policy profile (STRICT, BALANCED, CONSERVATIVE).
        """
        self.audit_logger = audit_logger
        self.engine = engine or AdaptivePolicyEngine(
            default_profile=default_profile, audit_logger=audit_logger
        )
        self.default_profile = self.engine._normalize_profile(default_profile)

    def process_and_enforce(
        self,
        a1_data: Any,
        a2_data: Any,
        flow_id: Optional[str] = None,
        profile: Optional[Union[str, PolicyProfile]] = None,
        raise_on_error: bool = False,
    ) -> EnforcementResult:
        """Process upstream detections through Agent 3 and enforce adaptive policy via Agent 4.

        Args:
            a1_data: Agent 1 threat prediction (dict or Agent1ThreatPrediction).
            a2_data: Agent 2 anomaly assessment (dict or Agent2AnomalyAssessment).
            flow_id: Optional correlated network flow ID.
            profile: Optional policy profile override.
            raise_on_error: If True, raises exceptions on validation failure.

        Returns:
            EnforcementResult: Unified threat assessment and policy enforcement decision.
        """
        active_prof = (
            self.engine._normalize_profile(profile).value
            if profile
            else self.default_profile.value
        )

        # 1. Execute Agent 3 Fusion Pipeline
        a3_output = process_flow(
            agent1_result=a1_data,
            agent2_result=a2_data,
            flow_id=flow_id,
            strict_mode=raise_on_error,
        )

        # 2. Extract assessment data
        threat_assessment_dict: Dict[str, Any]
        if hasattr(a3_output, "threat_assessment") and a3_output.threat_assessment:
            threat_assessment_dict = a3_output.threat_assessment.to_dict()
        elif hasattr(a3_output, "to_dict"):
            threat_assessment_dict = a3_output.to_dict()
        else:
            threat_assessment_dict = {"flow_id": flow_id or "UNKNOWN"}

        # 3. Evaluate Adaptive Policy via Agent 4
        decision = self.engine.evaluate(
            assessment=threat_assessment_dict,
            profile=active_prof,
            raise_on_error=raise_on_error,
        )

        resolved_flow_id = decision.flow_id

        return EnforcementResult(
            flow_id=resolved_flow_id,
            threat_assessment=threat_assessment_dict,
            policy_decision=decision,
            profile=active_prof,
            action=decision.action,
            risk_level=decision.risk_level,
            confidence_level=decision.confidence_level,
            simulated=decision.simulated,
        )

    def process_batch(
        self,
        batch: Sequence[Union[Tuple[Any, Any], Tuple[Any, Any, Optional[str]]]],
        profile: Optional[Union[str, PolicyProfile]] = None,
    ) -> List[EnforcementResult]:
        """Process a sequence of detections in batch.

        Args:
            batch: Sequence of tuples (a1_data, a2_data) or (a1_data, a2_data, flow_id).
            profile: Optional policy profile override.

        Returns:
            List[EnforcementResult]: List of enforcement outcomes.
        """
        results: List[EnforcementResult] = []
        for item in batch:
            if len(item) == 2:
                a1, a2 = item
                fid = None
            else:
                a1, a2, fid = item[0], item[1], item[2]
            results.append(
                self.process_and_enforce(a1, a2, flow_id=fid, profile=profile)
            )
        return results


def process_and_enforce_flow(
    a1_data: Any,
    a2_data: Any,
    flow_id: Optional[str] = None,
    profile: Union[str, PolicyProfile] = PolicyProfile.BALANCED,
    audit_logger: Optional[PolicyAuditLogger] = None,
    raise_on_error: bool = False,
) -> EnforcementResult:
    """Convenience function executing the complete CyberSentinel defense pipeline for a flow.

    Args:
        a1_data: Agent 1 detection output.
        a2_data: Agent 2 detection output.
        flow_id: Optional network flow ID.
        profile: Active policy profile (STRICT, BALANCED, CONSERVATIVE).
        audit_logger: Optional PolicyAuditLogger instance.
        raise_on_error: Whether to raise exceptions on malformed input.

    Returns:
        EnforcementResult: Unified assessment and simulated enforcement decision.
    """
    pipeline = CyberSentinelPipeline(
        audit_logger=audit_logger, default_profile=profile
    )
    return pipeline.process_and_enforce(
        a1_data=a1_data,
        a2_data=a2_data,
        flow_id=flow_id,
        profile=profile,
        raise_on_error=raise_on_error,
    )
