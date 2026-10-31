"""Interface contracts and data models for CyberSentinel Temporal Correlation Agent.

Defines:
  - TemporalGroup: Stateful group tracking correlated suspicious network flows.
  - TemporalCorrelationConfig: Configurable parameters for temporal windows, thresholds, and correlation heuristics.
  - TemporalCorrelationResult: Standardized output per evaluated network flow.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class TemporalGroup:
    """Represents a cluster of temporally, spatially, and behaviorally correlated suspicious flows.

    Attributes:
        group_id: Unique sequential group identifier (e.g. 'TG-0001').
        member_record_ids: Chronological list of member flow record IDs.
        first_seen: Timestamp string of the first observed member flow.
        last_seen: Timestamp string of the most recent observed member flow.
        first_seen_epoch: Unix epoch seconds of first member flow.
        last_seen_epoch: Unix epoch seconds of most recent member flow.
        first_seen_seq: Replay sequence number of first member flow.
        last_seen_seq: Replay sequence number of most recent member flow.
        member_count: Total number of suspicious flows in this group.
        observed_source_ips: List of unique source IP addresses observed in the group.
        observed_destination_ips: List of unique destination IP addresses observed.
        observed_ports: List of unique destination ports targeted.
        observed_protocols: List of unique network protocols observed (e.g., 'TCP', 'UDP').
        attack_categories: Unique attack classes identified across members.
        supporting_evidence: Traceable list of evidence strings linking members to original records.
        correlation_reason: Descriptive rationale for correlating these flows.
    """
    group_id: str
    member_record_ids: List[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    first_seen_epoch: float = 0.0
    last_seen_epoch: float = 0.0
    first_seen_seq: int = 1
    last_seen_seq: int = 1
    member_count: int = 0
    observed_source_ips: List[str] = field(default_factory=list)
    observed_destination_ips: List[str] = field(default_factory=list)
    observed_ports: List[int] = field(default_factory=list)
    observed_protocols: List[str] = field(default_factory=list)
    attack_categories: List[str] = field(default_factory=list)
    supporting_evidence: List[str] = field(default_factory=list)
    correlation_reason: str = ""

    def add_flow(
        self,
        record_id: str,
        timestamp_str: str,
        epoch: float,
        seq: int,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        dst_port: Optional[int] = None,
        protocol: Optional[str] = None,
        attack_category: Optional[str] = None,
        evidence_summary: str = "",
        reason: str = "",
    ) -> None:
        """Add an observed suspicious flow to this temporal group."""
        if record_id in self.member_record_ids:
            return  # Idempotent: avoid duplicate record additions

        self.member_record_ids.append(record_id)
        self.member_count = len(self.member_record_ids)
        self.last_seen = timestamp_str or self.last_seen or str(seq)
        self.last_seen_epoch = epoch
        self.last_seen_seq = seq

        if not self.first_seen:
            self.first_seen = timestamp_str or str(seq)
            self.first_seen_epoch = epoch
            self.first_seen_seq = seq

        if src_ip and src_ip not in self.observed_source_ips and src_ip != "UNKNOWN":
            self.observed_source_ips.append(src_ip)
        if dst_ip and dst_ip not in self.observed_destination_ips and dst_ip != "UNKNOWN":
            self.observed_destination_ips.append(dst_ip)
        if dst_port is not None and dst_port not in self.observed_ports:
            self.observed_ports.append(dst_port)
        if protocol and protocol not in self.observed_protocols and protocol != "UNKNOWN":
            self.observed_protocols.append(protocol.upper())
        if attack_category and attack_category not in self.attack_categories and attack_category != "BENIGN":
            self.attack_categories.append(attack_category)

        if evidence_summary:
            self.supporting_evidence.append(evidence_summary)
        if reason and not self.correlation_reason:
            self.correlation_reason = reason

    def to_dict(self) -> Dict[str, Any]:
        """Convert group to clean serializable dictionary."""
        return {
            "group_id": self.group_id,
            "member_record_ids": list(self.member_record_ids),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "member_count": self.member_count,
            "observed_source_ips": list(self.observed_source_ips),
            "observed_destination_ips": list(self.observed_destination_ips),
            "observed_ports": list(self.observed_ports),
            "observed_protocols": list(self.observed_protocols),
            "attack_categories": list(self.attack_categories),
            "supporting_evidence": list(self.supporting_evidence),
            "correlation_reason": self.correlation_reason,
        }


@dataclass
class TemporalCorrelationConfig:
    """Configuration settings for Agent 4 Temporal Correlation.

    Attributes:
        window_seconds: Maximum time difference in seconds between consecutive
            flows to be considered part of the same campaign. Default: 120.0s (2 minutes).
        window_records: Fallback maximum sequence record distance when timestamps
            are unavailable, missing, or constant. Default: 30 records.
        min_suspicious_confidence: Minimum Agent 1 confidence to consider a flow suspicious. Default: 0.50.
        min_anomaly_score: Minimum Agent 2 anomaly score to consider a flow suspicious. Default: 0.50.
        group_same_src_dst: Allow grouping flows sharing identical Source and Destination IPs. Default: True.
        group_same_src_multi_dst: Allow grouping flows sharing the same Source IP targeting
            multiple destinations (e.g. horizontal scanning / sweeps). Default: True.
        group_coordinated_target: Allow grouping flows targeting the same Destination IP & Port
            with identical attack category across sources (e.g. coordinated DDoS). Default: True.
        group_same_protocol: Require protocol compatibility when evaluating endpoint correlation. Default: True.
        max_group_duration_seconds: Maximum overall lifespan of an active campaign group in seconds.
            Default: 3600.0s (1 hour). Prevents indefinite growth of a single group.
        enforce_strict_ascending: Enforce strictly ascending sequence numbers without out-of-order leakage. Default: True.
    """
    window_seconds: float = 120.0
    window_records: int = 30
    min_suspicious_confidence: float = 0.50
    min_anomaly_score: float = 0.50
    group_same_src_dst: bool = True
    group_same_src_multi_dst: bool = True
    group_coordinated_target: bool = True
    group_same_protocol: bool = True
    max_group_duration_seconds: float = 3600.0
    enforce_strict_ascending: bool = True


@dataclass
class TemporalCorrelationResult:
    """Output produced by Agent 4 for an individual evaluated network flow.

    Attributes:
        flow_id: Identifier of the evaluated flow.
        is_suspicious: Whether the flow was deemed suspicious based on A1-A3 evidence.
        assigned_group_id: Unique group ID if clustered into a temporal group, or None if benign.
        group_summary: Full snapshot dictionary of the assigned temporal group (if any).
        active_groups_count: Number of currently active temporal groups in Agent 4 state.
        correlation_reason: Explanation of the grouping or pass-through decision.
    """
    flow_id: str
    is_suspicious: bool
    assigned_group_id: Optional[str] = None
    group_summary: Optional[Dict[str, Any]] = None
    active_groups_count: int = 0
    correlation_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return asdict(self)

