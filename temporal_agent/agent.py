"""Agent 4: Temporal Correlation Agent for CyberSentinel.

Responsible for identifying relationships between suspicious network flows observed
over time in strict chronological replay order.

Key Invariants:
1. Process strictly in ascending sequence order without future-data leakage.
2. Ingest flow context and suspicious evidence from upstream agents (A1, A2, A3).
3. Group related suspicious flows using source IP, destination IP, ports, protocol, and time window.
4. Maintain group IDs, membership, and traceable evidence.
5. Benign flows are never grouped.
6. Handle missing, malformed, or ambiguous network metadata safely.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import logging
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from cybersentinel.temporal_agent.contract import (
    TemporalCorrelationConfig,
    TemporalCorrelationResult,
    TemporalGroup,
)

logger = logging.getLogger(__name__)


def parse_timestamp_to_epoch(ts: Any, default_epoch: float = 0.0) -> float:
    """Parse various timestamp representations into Unix epoch seconds.

    Supports:
    - Numeric epoch timestamps (int/float in seconds or milliseconds).
    - ISO 8601 strings (e.g., "2017-07-04T00:49:08Z", "2026-10-31 12:00:00").
    - Relative offset strings (e.g., "00:49.8", "02:14.1").
    - Missing or invalid timestamps (gracefully returns default_epoch).

    Args:
        ts: Raw timestamp input.
        default_epoch: Fallback epoch value if parsing fails.

    Returns:
        float: Seconds since Unix epoch.
    """
    if ts is None:
        return default_epoch

    if isinstance(ts, (int, float)):
        val = float(ts)
        return val / 1000.0 if val > 1e11 else val

    ts_str = str(ts).strip()
    if not ts_str:
        return default_epoch

    # Numeric string
    try:
        val = float(ts_str)
        return val / 1000.0 if val > 1e11 else val
    except ValueError:
        pass

    # Time offset string like "00:49.8" or "14:46.4" (MM:SS.s)
    match_offset = re.match(r"^(\d+):(\d+)(?:\.(\d+))?$", ts_str)
    if match_offset:
        mins = float(match_offset.group(1))
        secs = float(match_offset.group(2))
        frac = float("0." + match_offset.group(3)) if match_offset.group(3) else 0.0
        return mins * 60.0 + secs + frac

    # ISO 8601 or standard datetime formats
    iso_formats = [
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ]
    clean_ts = ts_str.replace("Z", "+00:00")
    for fmt in iso_formats:
        try:
            dt = datetime.strptime(clean_ts, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            continue

    logger.debug("Could not parse timestamp '%s', using default: %s", ts_str, default_epoch)
    return default_epoch


class TemporalCorrelationAgent:
    """Agent 4: Stateful Temporal Correlation Coordinator for CyberSentinel.

    Maintains a rolling window of suspicious network flows to identify ongoing campaigns,
    distributed attacks, port scans, and repeated host targeting over time.

    Invariants:
    1. Operates strictly incrementally: flow N is evaluated using only flows 1..N.
    2. Strictly ascending sequence order: rejects out-of-order sequence flows when configured.
    3. Never uses future flow records or hidden ground truth labels.
    4. Benign flows are never grouped into suspicious temporal groups.
    5. Groups related flows using source IP, destination IP, ports, protocol, and time window.
    6. Maintains group IDs, membership, and traceable evidence.
    """

    def __init__(self, config: Optional[TemporalCorrelationConfig] = None) -> None:
        """Initialize TemporalCorrelationAgent with configurable parameters."""
        self.config = config or TemporalCorrelationConfig()
        self.groups: Dict[str, TemporalGroup] = {}
        self.flow_history: List[Dict[str, Any]] = []
        self.record_to_group: Dict[str, str] = {}
        self._next_group_num: int = 1
        self._last_processed_seq: Optional[int] = None
        logger.info(
            "Initialized TemporalCorrelationAgent (window_seconds=%.1fs, window_records=%d)",
            self.config.window_seconds,
            self.config.window_records,
        )

    def reset(self) -> None:
        """Reset internal memory and state for a fresh replay session."""
        self.groups.clear()
        self.flow_history.clear()
        self.record_to_group.clear()
        self._next_group_num = 1
        self._last_processed_seq = None
        logger.debug("TemporalCorrelationAgent memory reset.")

    def _generate_group_id(self) -> str:
        """Generate a unique sequential temporal group identifier."""
        gid = f"TG-{self._next_group_num:04d}"
        self._next_group_num += 1
        return gid

    def is_flow_suspicious(
        self,
        a1_result: Optional[Any],
        a2_result: Optional[Any],
        a3_result: Optional[Any],
    ) -> Tuple[bool, str, Optional[str]]:
        """Determine whether a flow is suspicious based solely on available A1, A2, and A3 evidence.

        Args:
            a1_result: Supervised prediction from Agent 1 (or None).
            a2_result: Anomaly assessment from Agent 2 (or None).
            a3_result: Fused triage assessment from Agent 3 (or None).

        Returns:
            Tuple of (is_suspicious, rationale_string, detected_attack_category)
        """
        # 1. Inspect Agent 1
        a1_threat = False
        a1_class = "BENIGN"
        a1_conf = 0.0
        if a1_result is not None:
            if hasattr(a1_result, "predicted_class"):
                a1_class = str(a1_result.predicted_class).upper().replace(" ", "_")
                a1_conf = float(getattr(a1_result, "confidence", 0.0))
            elif isinstance(a1_result, dict):
                a1_class = str(a1_result.get("predicted_class", "BENIGN")).upper().replace(" ", "_")
                a1_conf = float(a1_result.get("confidence", 0.0))

            if a1_class not in ("BENIGN", "NORMAL") and a1_conf >= self.config.min_suspicious_confidence:
                a1_threat = True

        # 2. Inspect Agent 2
        a2_anomaly = False
        a2_score = 0.0
        if a2_result is not None:
            if hasattr(a2_result, "anomaly_detected"):
                a2_anomaly = bool(a2_result.anomaly_detected)
                a2_score = float(getattr(a2_result, "anomaly_score", 0.0))
            elif isinstance(a2_result, dict):
                a2_anomaly = bool(a2_result.get("anomaly_detected", False) or a2_result.get("is_anomaly", False))
                a2_score = float(a2_result.get("anomaly_score", 0.0))

            if a2_score >= self.config.min_anomaly_score:
                a2_anomaly = True

        # 3. Inspect Agent 3
        a3_malicious_or_suspicious = False
        a3_verdict = ""
        a3_risk = 0.0
        if a3_result is not None:
            if hasattr(a3_result, "verdict"):
                verd = getattr(a3_result.verdict, "value", str(a3_result.verdict))
                a3_verdict = verd.upper()
                a3_risk = float(getattr(a3_result, "fused_risk_score", 0.0))
            elif isinstance(a3_result, dict):
                a3_verdict = str(a3_result.get("verdict", "")).upper()
                a3_risk = float(a3_result.get("fused_risk_score", 0.0))

            if a3_verdict in ("MALICIOUS", "SUSPICIOUS") or a3_risk >= 0.60:
                a3_malicious_or_suspicious = True

        # Evidence Synthesis for Suspicion
        if a1_threat and a3_malicious_or_suspicious:
            return True, f"A1={a1_class}(conf={a1_conf:.2f}), A3={a3_verdict}(risk={a3_risk:.2f})", a1_class
        if a1_threat:
            return True, f"A1={a1_class}(conf={a1_conf:.2f})", a1_class
        if a3_malicious_or_suspicious:
            cat = a1_class if a1_class not in ("BENIGN", "NORMAL") else "SUSPICIOUS_ACTIVITY"
            return True, f"A3={a3_verdict}(risk={a3_risk:.2f})", cat
        if a2_anomaly:
            return True, f"A2_ANOMALY(score={a2_score:.2f})", "BEHAVIORAL_ANOMALY"

        return False, "BENIGN_FLOW", None

    def _find_matching_group(
        self,
        epoch: float,
        seq: int,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        dst_port: Optional[int],
        protocol: Optional[str],
        attack_category: Optional[str],
    ) -> Tuple[Optional[TemporalGroup], str]:
        """Search existing active temporal groups for a correlation match within the time window.

        Evaluates endpoint dimensions (source IP, destination IP, ports, protocol) and temporal proximity.

        Args:
            epoch: Timestamp in Unix epoch seconds for current flow.
            seq: Replay sequence number for current flow.
            src_ip: Source IP address.
            dst_ip: Destination IP address.
            dst_port: Destination port.
            protocol: Protocol string (e.g., 'TCP', 'UDP').
            attack_category: Attack category from upstream detection.

        Returns:
            Tuple of (matched_group_or_none, correlation_reason_string)
        """
        valid_src = src_ip and src_ip not in ("UNKNOWN", "", "None")
        valid_dst = dst_ip and dst_ip not in ("UNKNOWN", "", "None")
        norm_proto = str(protocol).upper() if protocol and protocol not in ("UNKNOWN", "", "None") else None

        for group in reversed(list(self.groups.values())):
            # 1. Temporal Window Check
            time_diff = abs(epoch - group.last_seen_epoch) if (epoch > 0.0 and group.last_seen_epoch > 0.0) else 0.0
            seq_diff = abs(seq - group.last_seen_seq)

            # Max duration check: campaign shouldn't exceed max configured lifespan
            campaign_duration = abs(epoch - group.first_seen_epoch) if (epoch > 0.0 and group.first_seen_epoch > 0.0) else 0.0
            if campaign_duration > self.config.max_group_duration_seconds:
                continue

            # Check if within window (either time-based or sequence-based fallback)
            is_within_time = (epoch > 0.0 and group.last_seen_epoch > 0.0 and time_diff <= self.config.window_seconds)
            is_within_seq = (seq_diff <= self.config.window_records)

            if not (is_within_time or is_within_seq):
                continue

            # Protocol matching compatibility
            proto_matches = True
            if self.config.group_same_protocol and norm_proto and group.observed_protocols:
                proto_matches = (norm_proto in group.observed_protocols)

            # 2. Endpoint Correlation Rules
            # Rule A: Shared Source and Destination IP (Targeted host campaign)
            if self.config.group_same_src_dst and valid_src and valid_dst:
                if src_ip in group.observed_source_ips and dst_ip in group.observed_destination_ips:
                    if proto_matches:
                        reason = (
                            f"TARGETED_HOST_CAMPAIGN: Source {src_ip} repeatedly targeting {dst_ip} "
                            f"(proto={norm_proto or 'ANY'}, dt={time_diff:.1f}s, dseq={seq_diff})"
                        )
                        return group, reason

            # Rule B: Same Source IP targeting multiple destinations / ports (Port scan or sweep)
            if self.config.group_same_src_multi_dst and valid_src:
                if src_ip in group.observed_source_ips:
                    same_port = dst_port is not None and dst_port in group.observed_ports
                    same_attack = attack_category and attack_category in group.attack_categories
                    is_scan_or_sweep = attack_category in ("PORT_SCAN", "PORT SCAN", "BRUTE_FORCE", "BRUTE FORCE")

                    if proto_matches and (same_port or same_attack or is_scan_or_sweep):
                        reason = (
                            f"SOURCE_SWEEP_OR_SCAN: Source {src_ip} conducting distributed scan/sweep "
                            f"(attack={attack_category}, port={dst_port}, proto={norm_proto or 'ANY'}, dt={time_diff:.1f}s)"
                        )
                        return group, reason

            # Rule C: Coordinated Target DDoS (Multiple sources targeting same destination IP & port)
            if self.config.group_coordinated_target and valid_dst and dst_port is not None:
                if dst_ip in group.observed_destination_ips and dst_port in group.observed_ports:
                    if attack_category and attack_category in ("DDOS", "DOS"):
                        if attack_category in group.attack_categories or "DDOS" in group.attack_categories or "DOS" in group.attack_categories:
                            if proto_matches:
                                reason = (
                                    f"COORDINATED_TARGET_ATTACK: Coordinated {attack_category} targeting "
                                    f"{dst_ip}:{dst_port} (proto={norm_proto or 'ANY'}, dt={time_diff:.1f}s)"
                                )
                                return group, reason

        return None, ""

    def process_flow(
        self,
        flow: Union[Dict[str, Any], Any],
        a1_result: Optional[Any] = None,
        a2_result: Optional[Any] = None,
        a3_result: Optional[Any] = None,
        seq: Optional[int] = None,
    ) -> TemporalCorrelationResult:
        """Process a single network flow in chronological replay sequence.

        Enforces strict ascending sequence order and preserves group evidence.

        Args:
            flow: Flow dictionary or FlowContext object with routing metadata.
            a1_result: Optional Agent 1 prediction output.
            a2_result: Optional Agent 2 anomaly assessment output.
            a3_result: Optional Agent 3 fused assessment output.
            seq: Optional explicit replay sequence index (1-based).

        Returns:
            TemporalCorrelationResult: Structured outcome detailing group membership.

        Raises:
            ValueError: If strict ascending sequence is violated and sequence order decreases.
        """
        # 1. Normalize flow metadata safely
        if hasattr(flow, "to_dict") and callable(flow.to_dict):
            raw_flow = flow.to_dict()
        elif isinstance(flow, dict):
            raw_flow = flow
        elif hasattr(flow, "__dataclass_fields__"):
            raw_flow = asdict(flow)
        else:
            raw_flow = {
                "flow_id": getattr(flow, "flow_id", None) or getattr(flow, "record_id", None),
                "record_id": getattr(flow, "record_id", None) or getattr(flow, "flow_id", None),
                "timestamp": getattr(flow, "timestamp", None),
                "source_ip": getattr(flow, "src_ip", None) or getattr(flow, "source_ip", None),
                "destination_ip": getattr(flow, "dst_ip", None) or getattr(flow, "destination_ip", None),
                "src_port": getattr(flow, "src_port", None) or getattr(flow, "source_port", None),
                "dst_port": getattr(flow, "dst_port", None) or getattr(flow, "destination_port", None),
                "protocol": getattr(flow, "protocol", None),
            }

        flow_id = str(
            raw_flow.get("flow_id")
            or raw_flow.get("record_id")
            or raw_flow.get("Flow ID")
            or f"FLOW_{len(self.flow_history) + 1}"
        )

        current_seq = int(seq if seq is not None else raw_flow.get("seq", len(self.flow_history) + 1))

        # Enforce strict ascending sequence order without future-data or back-in-time leakage
        if self.config.enforce_strict_ascending and self._last_processed_seq is not None:
            if current_seq < self._last_processed_seq:
                raise ValueError(
                    f"Strict ascending sequence order violation: received sequence {current_seq} "
                    f"after previous sequence {self._last_processed_seq}."
                )

        self._last_processed_seq = current_seq

        # Handle duplicate record IDs safely (idempotent replay)
        if flow_id in self.record_to_group:
            existing_gid = self.record_to_group[flow_id]
            existing_grp = self.groups.get(existing_gid)
            return TemporalCorrelationResult(
                flow_id=flow_id,
                is_suspicious=True,
                assigned_group_id=existing_gid,
                group_summary=existing_grp.to_dict() if existing_grp else None,
                active_groups_count=len(self.groups),
                correlation_reason="DUPLICATE_FLOW_ID_ALREADY_MEMBER",
            )

        timestamp_raw = raw_flow.get("timestamp") or raw_flow.get("time_offset") or raw_flow.get("Timestamp")
        timestamp_str = str(timestamp_raw) if timestamp_raw is not None else ""
        epoch = parse_timestamp_to_epoch(timestamp_raw, default_epoch=float(current_seq))

        src_ip = raw_flow.get("src_ip") or raw_flow.get("source_ip") or raw_flow.get("Source IP")
        dst_ip = raw_flow.get("dst_ip") or raw_flow.get("destination_ip") or raw_flow.get("Destination IP")
        dst_port_raw = raw_flow.get("dst_port") or raw_flow.get("destination_port") or raw_flow.get("Destination Port")
        protocol_raw = raw_flow.get("protocol") or raw_flow.get("Protocol") or "TCP"
        protocol = str(protocol_raw).upper().strip() if protocol_raw is not None else "TCP"

        try:
            dst_port = int(dst_port_raw) if dst_port_raw is not None else None
        except (ValueError, TypeError):
            dst_port = None

        # 2. Determine Suspiciousness
        is_suspicious, rationale, attack_category = self.is_flow_suspicious(a1_result, a2_result, a3_result)

        # Store in historical log
        history_entry = {
            "flow_id": flow_id,
            "seq": current_seq,
            "timestamp": timestamp_str,
            "epoch": epoch,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "is_suspicious": is_suspicious,
            "attack_category": attack_category,
        }
        self.flow_history.append(history_entry)

        # 3. If Benign, do NOT group
        if not is_suspicious:
            return TemporalCorrelationResult(
                flow_id=flow_id,
                is_suspicious=False,
                assigned_group_id=None,
                group_summary=None,
                active_groups_count=len(self.groups),
                correlation_reason="BENIGN_FLOW_NOT_GROUPED",
            )

        # 4. Search for existing matching group within temporal window & endpoint dimensions
        matched_group, match_reason = self._find_matching_group(
            epoch=epoch,
            seq=current_seq,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            attack_category=attack_category,
        )

        evidence_str = (
            f"Record {flow_id} (seq={current_seq}, proto={protocol}, "
            f"endpoints={src_ip or 'UNKNOWN'}->{dst_ip or 'UNKNOWN'}:{dst_port or 'ANY'}): {rationale}"
        )

        if matched_group is not None:
            # Update existing group
            matched_group.add_flow(
                record_id=flow_id,
                timestamp_str=timestamp_str,
                epoch=epoch,
                seq=current_seq,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                attack_category=attack_category,
                evidence_summary=evidence_str,
                reason=match_reason,
            )
            self.record_to_group[flow_id] = matched_group.group_id
            return TemporalCorrelationResult(
                flow_id=flow_id,
                is_suspicious=True,
                assigned_group_id=matched_group.group_id,
                group_summary=matched_group.to_dict(),
                active_groups_count=len(self.groups),
                correlation_reason=match_reason,
            )
        else:
            # Create a brand new group
            gid = self._generate_group_id()
            new_reason = (
                f"NEW_SUSPICIOUS_CAMPAIGN: Initial flow {flow_id} identified as {attack_category or 'SUSPICIOUS'} "
                f"from {src_ip or 'UNKNOWN'} targeting {dst_ip or 'UNKNOWN'}:{dst_port or 'ANY'} ({protocol})"
            )
            new_group = TemporalGroup(
                group_id=gid,
                member_record_ids=[flow_id],
                first_seen=timestamp_str or str(current_seq),
                last_seen=timestamp_str or str(current_seq),
                first_seen_epoch=epoch,
                last_seen_epoch=epoch,
                first_seen_seq=current_seq,
                last_seen_seq=current_seq,
                member_count=1,
                observed_source_ips=[src_ip] if src_ip and src_ip != "UNKNOWN" else [],
                observed_destination_ips=[dst_ip] if dst_ip and dst_ip != "UNKNOWN" else [],
                observed_ports=[dst_port] if dst_port is not None else [],
                observed_protocols=[protocol] if protocol and protocol != "UNKNOWN" else [],
                attack_categories=[attack_category] if attack_category and attack_category != "BENIGN" else [],
                supporting_evidence=[evidence_str],
                correlation_reason=new_reason,
            )
            self.groups[gid] = new_group
            self.record_to_group[flow_id] = gid

            return TemporalCorrelationResult(
                flow_id=flow_id,
                is_suspicious=True,
                assigned_group_id=gid,
                group_summary=new_group.to_dict(),
                active_groups_count=len(self.groups),
                correlation_reason=new_reason,
            )

    def get_group(self, group_id: str) -> Optional[TemporalGroup]:
        """Retrieve a temporal group by its unique group ID."""
        return self.groups.get(group_id)

    def get_all_groups(self) -> List[TemporalGroup]:
        """Return all created temporal groups."""
        return list(self.groups.values())

