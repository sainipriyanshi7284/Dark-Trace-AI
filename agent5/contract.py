"""Interface contracts and data models for CyberSentinel Agent 5 (Adaptive Defense).

Defines:
  - PolicyScopeType: Supported scope dimensions (SOURCE_IP, DESTINATION_IP, SRC_DST_PAIR).
  - PolicyActionType: Supported policy enforcement actions (BLOCK, ALLOW).
  - PolicyLifecycleState: State transitions (PENDING, ACTIVE, EXPIRED, REVOKED).
  - DefensePolicy: Structured model of an active or historical defense policy.
  - ReplayDecision: Standardized replay enforcement decision for every test record.
  - Agent5Config: Configurable policy thresholds, durations, and operational settings.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class PolicyScopeType(str, Enum):
    """Scope dimension for policy targeting."""
    SOURCE_IP = "SOURCE_IP"
    DESTINATION_IP = "DESTINATION_IP"
    SRC_DST_PAIR = "SRC_DST_PAIR"


class PolicyActionType(str, Enum):
    """Simulated defense policy action.

    NOTICE:
      All actions remain strictly simulated. No actual firewall modifications
      or real network disruption occur.
    """
    BLOCK = "BLOCK"
    ALLOW = "ALLOW"


class PolicyLifecycleState(str, Enum):
    """Operational lifecycle state of a temporary defense policy."""
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


@dataclass
class DefensePolicy:
    """Represents a temporary, stateful defense policy managed by Agent 5.

    Attributes:
        policy_id: Unique policy identifier (e.g. 'POL-0001').
        activated_after_record_id: The specific record ID whose analysis triggered this policy.
        activated_after_seq: Replay sequence number of the triggering record.
        scope_type: Target dimension, strictly 'SOURCE_IP' for Day 2 scored interface.
        scope_value: Target identifier (e.g. '172.16.0.1').
        expires_after_record_id: Replay record ID boundary where the policy expires.
        expires_after_seq: Replay sequence number boundary where the policy expires.
        policy_action: Enforced defense action, strictly 'BLOCK'.
        trigger_reason: Human-readable justification for policy creation.
        state: Current lifecycle state (PENDING, ACTIVE, EXPIRED, REVOKED).
        hit_count: Number of times this policy successfully matched and blocked later flows.
        created_at_iso: UTC ISO timestamp of policy creation.
    """
    policy_id: str
    activated_after_record_id: str
    activated_after_seq: int
    scope_type: str = "SOURCE_IP"
    scope_value: str = ""
    expires_after_record_id: str = ""
    expires_after_seq: int = 0
    policy_action: str = "BLOCK"
    trigger_reason: str = ""
    state: PolicyLifecycleState = PolicyLifecycleState.ACTIVE
    hit_count: int = 0
    created_at_iso: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def is_active_for(self, seq: int) -> bool:
        """Evaluate if the policy is actively enforceable at sequence `seq`.

        Invariants:
          - A policy becomes active strictly AFTER the triggering record: seq > activated_after_seq.
          - It applies to all matching records up to and including the expiry boundary: seq <= expires_after_seq.
          - Once seq > expires_after_seq, the policy is expired and must never block.
          - The triggering record (seq == activated_after_seq) is NEVER blocked by its own policy.
        """
        if self.state == PolicyLifecycleState.REVOKED:
            return False
        if seq <= self.activated_after_seq:
            return False
        if seq > self.expires_after_seq:
            return False
        return True

    def matches(self, flow: Dict[str, Any]) -> bool:
        """Check if incoming flow metadata falls within the policy's scope."""
        if not self.scope_value:
            return False

        if self.scope_type == PolicyScopeType.SOURCE_IP.value or self.scope_type == "SOURCE_IP":
            flow_src = (
                flow.get("source_ip")
                or flow.get("src_ip")
                or flow.get("Source IP")
                or ""
            )
            return str(flow_src).strip() == self.scope_value.strip()

        elif self.scope_type == PolicyScopeType.DESTINATION_IP.value or self.scope_type == "DESTINATION_IP":
            flow_dst = (
                flow.get("destination_ip")
                or flow.get("dst_ip")
                or flow.get("Destination IP")
                or ""
            )
            return str(flow_dst).strip() == self.scope_value.strip()

        elif self.scope_type == PolicyScopeType.SRC_DST_PAIR.value or self.scope_type == "SRC_DST_PAIR":
            flow_src = flow.get("source_ip") or flow.get("src_ip") or ""
            flow_dst = flow.get("destination_ip") or flow.get("dst_ip") or ""
            pair = f"{str(flow_src).strip()}|{str(flow_dst).strip()}"
            return pair == self.scope_value.strip()

        return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert policy to clean dictionary matching organizer schema requirements."""
        return {
            "policy_id": self.policy_id,
            "activated_after_record_id": self.activated_after_record_id,
            "scope_type": self.scope_type,
            "scope_value": self.scope_value,
            "expires_after_record_id": self.expires_after_record_id,
            "policy_action": self.policy_action,
            "trigger_reason": self.trigger_reason,
            "state": self.state.value if isinstance(self.state, Enum) else str(self.state),
            "hit_count": self.hit_count,
        }


@dataclass
class ReplayDecision:
    """Final simulated replay enforcement decision for an individual network flow.

    Invariants:
      - BLOCK must reference a valid, active, and applicable policy ID.
      - ALLOW must have an empty applied_policy_id ("").
      - Every test record receives exactly one replay decision.
    """
    record_id: str
    action: str  # "ALLOW" or "BLOCK"
    applied_policy_id: str = ""
    decision_reason: str = ""

    def validate(self) -> None:
        """Validate required replay decision contract rules."""
        if not self.record_id:
            raise ValueError("record_id must not be empty in ReplayDecision")
        if self.action not in ("ALLOW", "BLOCK"):
            raise ValueError(f"action must be ALLOW or BLOCK, got: {self.action}")
        if self.action == "ALLOW" and self.applied_policy_id != "":
            raise ValueError(f"ALLOW decisions must have empty applied_policy_id, got '{self.applied_policy_id}'")
        if self.action == "BLOCK" and not self.applied_policy_id:
            raise ValueError("BLOCK decisions must specify a valid non-empty applied_policy_id")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary matching organizer replay.csv contract."""
        return {
            "record_id": self.record_id,
            "action": self.action,
            "applied_policy_id": self.applied_policy_id,
            "active_policy_id": self.applied_policy_id,  # Template alias compatibility
            "decision_reason": self.decision_reason,
        }


@dataclass
class Agent5Config:
    """Operational settings and thresholds for Agent 5 Adaptive Defense.

    Attributes:
        default_block_duration_records: Number of future records a policy remains active.
            Default: 20 records.
        min_threat_confidence: Minimum Agent 1 confidence to trigger policy creation.
            Default: 0.80.
        min_fused_risk_score: Minimum Agent 3 fused risk score to trigger policy creation.
            Default: 0.70.
        enable_temporal_reinforcement: If True, triggers policy activation when Agent 4
            detects a multi-flow campaign (>= 2 suspicious flows from the same source).
            Default: True.
        prevent_overlapping_policies: If True, avoids generating duplicate active policies
            for an already blocked source IP until the active policy expires.
            Default: True.
    """
    default_block_duration_records: int = 20
    min_threat_confidence: float = 0.80
    min_fused_risk_score: float = 0.70
    enable_temporal_reinforcement: bool = True
    prevent_overlapping_policies: bool = True
