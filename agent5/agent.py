"""Agent 5: Adaptive Defense Agent for CyberSentinel.

Responsible for creating and managing temporary simulated defense policies with
strict future-flow enforcement and auditable lifecycle transitions.

Core Requirements & Invariants:
1. Mandatory Evaluation Order:
   - For every incoming flow, check active policies FIRST.
   - If a matching active BLOCK policy exists:
     - Return BLOCK immediately with valid applied_policy_id.
     - Do not analyze the blocked flow to create new policies.
   - If an active ALLOW policy exists:
     - Return ALLOW immediately (empty applied_policy_id per organizer schema).
   - If no policy matches:
     - Flow is processed by upstream agents (A1, A2, A3, A4).
     - Agent 5 decides whether to activate a temporary policy for FUTURE records.
     - Record ALLOW for the current flow (it is never blocked by the policy it activates).
2. Strict Future-Flow Enforcement:
   - Policies apply only to flows arriving AFTER the triggering record.
   - Policies expire at the configured record boundary (default: 20 subsequent records).
   - Once expired, policies stop affecting records.
   - Triggering record is NEVER blocked by the policy it creates.
3. Scored Interface:
   - Supports `scope_type = "SOURCE_IP"` and `policy_action` (BLOCK, ALLOW).
   - Default BLOCK duration: 20 subsequent records, configurable.
   - Strict simulation only; never modifies actual host/system firewalls.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from cybersentinel.agent5.audit_log import DefenseAuditLogger
from cybersentinel.agent5.contract import (
    Agent5Config,
    DefensePolicy,
    PolicyActionType,
    PolicyLifecycleState,
    PolicyScopeType,
    ReplayDecision,
)

logger = logging.getLogger(__name__)


class AdaptiveDefenseAgent:
    """Agent 5: Stateful Adaptive Defense Agent managing temporary simulated policies."""

    def __init__(
        self,
        config: Optional[Agent5Config] = None,
        audit_logger: Optional[DefenseAuditLogger] = None,
    ) -> None:
        """Initialize AdaptiveDefenseAgent."""
        self.config = config or Agent5Config()
        self.audit_logger = audit_logger or DefenseAuditLogger()
        self.policies: Dict[str, DefensePolicy] = {}
        self._next_policy_num: int = 1
        logger.info(
            "Initialized AdaptiveDefenseAgent (default_duration=%d records, min_conf=%.2f)",
            self.config.default_block_duration_records,
            self.config.min_threat_confidence,
        )

    def reset(self) -> None:
        """Reset policy engine state for a clean replay session."""
        self.policies.clear()
        self.audit_logger.clear()
        self._next_policy_num = 1
        logger.debug("AdaptiveDefenseAgent state reset.")

    def _generate_policy_id(self) -> str:
        """Generate unique sequential policy ID (e.g. POL-0001)."""
        pid = f"POL-{self._next_policy_num:04d}"
        self._next_policy_num += 1
        return pid

    def update_policy_states(self, current_seq: int, current_record_id: str) -> None:
        """Update lifecycle state of all managed policies up to current replay sequence.

        Transitions active policies to EXPIRED when current_seq exceeds expires_after_seq.
        """
        for policy in self.policies.values():
            if policy.state == PolicyLifecycleState.ACTIVE:
                if current_seq > policy.expires_after_seq:
                    policy.state = PolicyLifecycleState.EXPIRED
                    self.audit_logger.log_event(
                        event_type="POLICY_EXPIRED",
                        policy_id=policy.policy_id,
                        record_id=current_record_id,
                        seq=current_seq,
                        scope_type=policy.scope_type,
                        scope_value=policy.scope_value,
                        action=policy.policy_action,
                        details={
                            "expires_after_seq": policy.expires_after_seq,
                            "expires_after_record_id": policy.expires_after_record_id,
                            "final_hit_count": policy.hit_count,
                        },
                    )
                    logger.info(
                        "Policy %s expired at seq %d (target: %s=%s)",
                        policy.policy_id,
                        current_seq,
                        policy.scope_type,
                        policy.scope_value,
                    )

    def check_active_policies(
        self,
        flow: Union[Dict[str, Any], Any],
        current_seq: int,
        current_record_id: str,
    ) -> Optional[ReplayDecision]:
        """Check whether incoming flow matches any currently active simulated defense policy.

        MANDATORY FIRST STEP:
          - Evaluated BEFORE upstream classification analysis.
          - If a matching active policy exists: returns decision immediately (BLOCK or ALLOW).
          - If no policy matches: returns None.

        Args:
            flow: Incoming flow record.
            current_seq: 1-based chronological replay sequence number.
            current_record_id: Official unique record ID (e.g. 'F000001').

        Returns:
            ReplayDecision if matched, or None if no active policy applies.
        """
        if hasattr(flow, "to_dict") and callable(flow.to_dict):
            raw_flow = flow.to_dict()
        elif isinstance(flow, dict):
            raw_flow = flow
        elif hasattr(flow, "__dataclass_fields__"):
            from dataclasses import asdict
            raw_flow = asdict(flow)
        else:
            raw_flow = {
                "source_ip": getattr(flow, "source_ip", None) or getattr(flow, "src_ip", None),
                "destination_ip": getattr(flow, "destination_ip", None) or getattr(flow, "dst_ip", None),
            }

        # 1. Update policy expiration boundaries first
        self.update_policy_states(current_seq, current_record_id)

        # 2. Check each currently active policy
        for policy in self.policies.values():
            if policy.state == PolicyLifecycleState.ACTIVE and policy.is_active_for(current_seq):
                if policy.matches(raw_flow):
                    policy.hit_count += 1
                    reason = (
                        f"Enforced simulated {policy.policy_action} via active policy {policy.policy_id} "
                        f"targeting {policy.scope_type}={policy.scope_value} "
                        f"(activated_after={policy.activated_after_record_id}, "
                        f"expires_after={policy.expires_after_record_id})"
                    )

                    self.audit_logger.log_event(
                        event_type="POLICY_APPLIED",
                        policy_id=policy.policy_id,
                        record_id=current_record_id,
                        seq=current_seq,
                        scope_type=policy.scope_type,
                        scope_value=policy.scope_value,
                        action=policy.policy_action,
                        details={"hit_count": policy.hit_count, "decision_reason": reason},
                    )

                    applied_id = (
                        policy.policy_id
                        if (policy.policy_action == PolicyActionType.BLOCK.value or policy.policy_action == "BLOCK")
                        else ""
                    )

                    decision = ReplayDecision(
                        record_id=current_record_id,
                        action=policy.policy_action,
                        applied_policy_id=applied_id,
                        decision_reason=reason,
                    )
                    decision.validate()
                    return decision

        return None

    def activate_temporary_policy(
        self,
        scope_value: str,
        scope_type: str = "SOURCE_IP",
        policy_action: str = "BLOCK",
        duration_records: Optional[int] = None,
        current_seq: int = 0,
        current_record_id: str = "",
        trigger_reason: str = "",
        expiry_record_id_resolver: Optional[Callable[[int], str]] = None,
    ) -> DefensePolicy:
        """Explicitly create and activate a temporary simulated defense policy.

        Supports both temporary BLOCK and ALLOW policies.
        Simulation only; does not modify host firewall or OS network stack.

        Args:
            scope_value: Target identifier (e.g. Source IP).
            scope_type: Scope dimension ('SOURCE_IP', 'DESTINATION_IP', 'SRC_DST_PAIR').
            policy_action: Policy action ('BLOCK' or 'ALLOW').
            duration_records: Lifespan in subsequent records (defaults to config default: 20).
            current_seq: Replay sequence number of triggering record.
            current_record_id: Identifier of triggering record.
            trigger_reason: Justification string.
            expiry_record_id_resolver: Optional mapping function for expiry record ID.

        Returns:
            Activated DefensePolicy.
        """
        duration = (
            int(duration_records)
            if duration_records is not None
            else self.config.default_block_duration_records
        )
        expires_seq = current_seq + duration

        if expiry_record_id_resolver is not None:
            try:
                expires_record_id = expiry_record_id_resolver(expires_seq)
            except Exception:
                expires_record_id = f"SEQ_{expires_seq}"
        else:
            expires_record_id = f"SEQ_{expires_seq}"

        policy_id = self._generate_policy_id()
        policy = DefensePolicy(
            policy_id=policy_id,
            activated_after_record_id=current_record_id,
            activated_after_seq=current_seq,
            scope_type=scope_type,
            scope_value=str(scope_value).strip(),
            expires_after_record_id=expires_record_id,
            expires_after_seq=expires_seq,
            policy_action=policy_action.upper(),
            trigger_reason=trigger_reason,
            state=PolicyLifecycleState.ACTIVE,
        )

        self.policies[policy_id] = policy

        # Log policy creation and activation in audit trail
        self.audit_logger.log_event(
            event_type="POLICY_CREATED",
            policy_id=policy_id,
            record_id=current_record_id,
            seq=current_seq,
            scope_type=policy.scope_type,
            scope_value=policy.scope_value,
            action=policy.policy_action,
            details={
                "activated_after_record_id": current_record_id,
                "expires_after_record_id": expires_record_id,
                "expires_after_seq": expires_seq,
                "duration_records": duration,
                "trigger_reason": trigger_reason,
            },
        )
        self.audit_logger.log_event(
            event_type="POLICY_ACTIVATED",
            policy_id=policy_id,
            record_id=current_record_id,
            seq=current_seq,
            scope_type=policy.scope_type,
            scope_value=policy.scope_value,
            action=policy.policy_action,
            details={
                "effective_from_seq": current_seq + 1,
                "expires_after_seq": expires_seq,
                "duration_records": duration,
            },
        )

        logger.info(
            "Activated policy %s (%s) targeting %s=%s for %d subsequent records (expires after %s)",
            policy_id,
            policy.policy_action,
            policy.scope_type,
            policy.scope_value,
            duration,
            expires_record_id,
        )

        return policy

    def evaluate_and_activate_policy(
        self,
        flow: Union[Dict[str, Any], Any],
        a1_result: Optional[Any],
        a2_result: Optional[Any],
        a3_result: Optional[Any],
        a4_result: Optional[Any],
        current_seq: int,
        current_record_id: str,
        expiry_record_id_resolver: Optional[Callable[[int], str]] = None,
        duration_records: Optional[int] = None,
    ) -> Optional[DefensePolicy]:
        """Evaluate flow evidence and conditionally activate a new simulated defense policy.

        MANDATORY INVARIANTS:
          - Only invoked when flow was NOT blocked by an existing policy.
          - Activated policy applies strictly to FUTURE records (seq > current_seq).
          - Triggering record (current_seq) is NEVER blocked by this policy.
          - Default duration: 20 subsequent records (or configurable via parameter/config).

        Args:
            flow: Raw flow record.
            a1_result: Agent 1 supervised threat prediction.
            a2_result: Agent 2 anomaly assessment.
            a3_result: Agent 3 fused triage assessment.
            a4_result: Agent 4 temporal correlation outcome.
            current_seq: 1-based chronological replay sequence number.
            current_record_id: Official record ID.
            expiry_record_id_resolver: Optional callable mapping sequence number to record ID.
            duration_records: Optional duration override in subsequent records.

        Returns:
            Newly created DefensePolicy, or None if defense criteria not met.
        """
        if hasattr(flow, "to_dict") and callable(flow.to_dict):
            raw_flow = flow.to_dict()
        elif isinstance(flow, dict):
            raw_flow = flow
        elif hasattr(flow, "__dataclass_fields__"):
            from dataclasses import asdict
            raw_flow = asdict(flow)
        else:
            raw_flow = {
                "source_ip": getattr(flow, "source_ip", None) or getattr(flow, "src_ip", None),
                "destination_ip": getattr(flow, "destination_ip", None) or getattr(flow, "dst_ip", None),
            }

        src_ip = raw_flow.get("source_ip") or raw_flow.get("src_ip") or raw_flow.get("Source IP")
        if not src_ip or str(src_ip).strip() in ("UNKNOWN", "", "None"):
            return None

        src_ip = str(src_ip).strip()

        # 1. Check if an active policy for this source IP already exists
        if self.config.prevent_overlapping_policies:
            for p in self.policies.values():
                if p.state == PolicyLifecycleState.ACTIVE and p.is_active_for(current_seq + 1):
                    if p.scope_type == PolicyScopeType.SOURCE_IP.value and p.scope_value == src_ip:
                        logger.debug(
                            "Source IP %s already covered by active policy %s; skipping duplicate.",
                            src_ip,
                            p.policy_id,
                        )
                        return None

        # 2. Extract detection evidence
        # A1 supervised classification check
        a1_attack = False
        a1_class = "BENIGN"
        a1_conf = 0.0
        if a1_result is not None:
            if hasattr(a1_result, "predicted_class"):
                a1_class = str(a1_result.predicted_class).upper().replace(" ", "_")
                a1_conf = float(getattr(a1_result, "confidence", 0.0))
            elif isinstance(a1_result, dict):
                a1_class = str(a1_result.get("predicted_class", "BENIGN")).upper().replace(" ", "_")
                a1_conf = float(a1_result.get("confidence", 0.0))

            if a1_class in ("DOS", "DDOS", "PORT_SCAN", "BRUTE_FORCE") and a1_conf >= self.config.min_threat_confidence:
                a1_attack = True

        # A3 fused verdict check
        a3_malicious = False
        a3_risk = 0.0
        if a3_result is not None:
            if hasattr(a3_result, "verdict"):
                verd = getattr(a3_result.verdict, "value", str(a3_result.verdict))
                a3_risk = float(getattr(a3_result, "fused_risk_score", 0.0))
                if verd.upper() == "MALICIOUS" or a3_risk >= self.config.min_fused_risk_score:
                    a3_malicious = True
            elif isinstance(a3_result, dict):
                verd = str(a3_result.get("verdict", "")).upper()
                a3_risk = float(a3_result.get("fused_risk_score", 0.0))
                if verd == "MALICIOUS" or a3_risk >= self.config.min_fused_risk_score:
                    a3_malicious = True

        # A4 temporal reinforcement check
        a4_campaign_active = False
        a4_group_id = ""
        a4_member_count = 1
        if a4_result is not None:
            if hasattr(a4_result, "assigned_group_id") and a4_result.assigned_group_id:
                a4_group_id = a4_result.assigned_group_id
                summary = getattr(a4_result, "group_summary", {}) or {}
                a4_member_count = summary.get("member_count", 1)
                if a4_member_count >= 2:
                    a4_campaign_active = True
            elif isinstance(a4_result, dict) and a4_result.get("assigned_group_id"):
                a4_group_id = a4_result["assigned_group_id"]
                summary = a4_result.get("group_summary") or {}
                a4_member_count = summary.get("member_count", 1)
                if a4_member_count >= 2:
                    a4_campaign_active = True

        # 3. Decision Criteria for Policy Activation
        trigger_policy = False
        activation_reason = ""

        if a1_attack and a3_malicious:
            trigger_policy = True
            activation_reason = (
                f"High-confidence threat confirmed by A1 ({a1_class}, conf={a1_conf:.2f}) "
                f"and A3 triage fusion (risk={a3_risk:.2f})."
            )
        elif a1_attack:
            trigger_policy = True
            activation_reason = (
                f"Definitive supervised attack detected by A1 ({a1_class}, conf={a1_conf:.2f})."
            )
        elif self.config.enable_temporal_reinforcement and a4_campaign_active and (a1_class != "BENIGN" or a3_malicious):
            trigger_policy = True
            activation_reason = (
                f"Temporal correlation group {a4_group_id} confirmed recurring attack campaign "
                f"({a4_member_count} member flows observed from {src_ip})."
            )

        if not trigger_policy:
            return None

        # 4. Formulate and activate the policy
        duration = duration_records if duration_records is not None else self.config.default_block_duration_records
        return self.activate_temporary_policy(
            scope_value=src_ip,
            scope_type=PolicyScopeType.SOURCE_IP.value,
            policy_action=PolicyActionType.BLOCK.value,
            duration_records=duration,
            current_seq=current_seq,
            current_record_id=current_record_id,
            trigger_reason=activation_reason,
            expiry_record_id_resolver=expiry_record_id_resolver,
        )

    def record_allow_decision(
        self,
        record_id: str,
        reason: str = "Traffic allowed (no active blocking policy matched)",
    ) -> ReplayDecision:
        """Construct standard ALLOW replay decision with empty applied_policy_id."""
        decision = ReplayDecision(
            record_id=record_id,
            action=PolicyActionType.ALLOW.value,
            applied_policy_id="",
            decision_reason=reason,
        )
        decision.validate()
        return decision

    def get_policy(self, policy_id: str) -> Optional[DefensePolicy]:
        """Retrieve policy by policy ID."""
        return self.policies.get(policy_id)

    def get_all_policies(self) -> List[DefensePolicy]:
        """Return all created policies."""
        return list(self.policies.values())

    def get_active_policies(self) -> List[DefensePolicy]:
        """Return all currently active policies."""
        return [p for p in self.policies.values() if p.state == PolicyLifecycleState.ACTIVE]
