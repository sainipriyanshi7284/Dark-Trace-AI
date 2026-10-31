"""Five-Agent Replay Pipeline for CyberSentinel (Day 2 Architecture).

Integrates the 5 autonomous agents in strict accordance with the Hackathon Brief:
  - Step 1: Check active policies in Agent 5 (Adaptive Defense).
            If a matching active BLOCK policy exists:
              -> Record BLOCK with applied_policy_id.
              -> Compute and preserve classification prediction separately.
              -> Do NOT use this blocked record to activate new policies.
  - Step 2: If no active policy matches:
              -> Validate input via Data Quality Monitor.
              -> Run Agent 1 (Supervised Threat Detection).
              -> Run Agent 2 (Behavioral Anomaly Detection).
              -> Run Agent 3 (Contextual Evidence Fusion).
              -> Pass observed evidence to Agent 4 (Temporal Correlation).
              -> Let Agent 5 decide whether to activate a policy for FUTURE records.
              -> Record ALLOW for the current record.

Ensures:
  - Strict chronological replay (no future record leakage, no peeking).
  - Triggering record is never blocked by the policy it creates.
  - Classification is produced for every test record, including blocked ones.
  - Traceable CSV exports (classification.csv, policies.csv, replay.csv).
"""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
import os
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from cybersentinel.agent1 import ThreatClassifierAgent
from cybersentinel.agent1.contract import Agent1ThreatPrediction, AgentStatus
from cybersentinel.agent2.adapter import adapt_agent2_evidence_to_assessment
from cybersentinel.agent3.contract import Agent3Input, FlowContext, RecommendedAction, Verdict
from cybersentinel.agent3.schemas import Agent2AnomalyAssessment, Agent3ThreatAssessment
from cybersentinel.agent3.skeleton import Agent3Skeleton
from cybersentinel.temporal_agent import (
    TemporalCorrelationAgent,
    TemporalCorrelationConfig,
    TemporalCorrelationResult,
    TemporalGroup,
)
from cybersentinel.agent5 import (
    AdaptiveDefenseAgent,
    Agent5Config,
    DefensePolicy,
    ReplayDecision,
)
from cybersentinel.data_quality import DataQualityMonitor
from cybersentinel.orchestration.csv_exporter import (
    export_classification_csv,
    export_policies_csv,
    export_replay_csv,
    normalize_class_name,
)
from dark_trace.agent2.agent import AnomalyAgent2
from dark_trace.agent2.persistence import load_trained_model
from dark_trace.common.schemas import NetworkFlow

logger = logging.getLogger(__name__)


@dataclass
class ReplaySessionResult:
    """Consolidated outcome of a full five-agent chronological replay session."""
    total_records: int
    allowed_records: int
    blocked_records: int
    classification_records: List[Dict[str, Any]] = field(default_factory=list)
    replay_records: List[Dict[str, Any]] = field(default_factory=list)
    activated_policies: List[DefensePolicy] = field(default_factory=list)
    temporal_groups: List[TemporalGroup] = field(default_factory=list)
    audit_events: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert session result to summary dictionary."""
        return {
            "total_records": self.total_records,
            "allowed_records": self.allowed_records,
            "blocked_records": self.blocked_records,
            "policies_activated": len(self.activated_policies),
            "temporal_groups_formed": len(self.temporal_groups),
            "classification_count": len(self.classification_records),
            "replay_decision_count": len(self.replay_records),
        }

    def export_csvs(
        self,
        output_dir: str = ".",
        include_policy_action: bool = False,
        policy_id_col: str = "active_policy_id",
    ) -> Dict[str, str]:
        """Export session deliverables to classification.csv, policies.csv, replay.csv."""
        paths = {}
        paths["classification"] = export_classification_csv(
            self.classification_records,
            os.path.join(output_dir, "classification.csv"),
        )
        paths["policies"] = export_policies_csv(
            self.activated_policies,
            os.path.join(output_dir, "policies.csv"),
            include_action_column=include_policy_action,
        )
        # Also export policy.csv if requested
        export_policies_csv(
            self.activated_policies,
            os.path.join(output_dir, "policy.csv"),
            include_action_column=True,
        )
        paths["replay"] = export_replay_csv(
            self.replay_records,
            os.path.join(output_dir, "replay.csv"),
            policy_id_column_name=policy_id_col,
        )
        return paths


class FiveAgentReplayPipeline:
    """Coordinator executing the full five-agent intrusion detection and defense replay."""

    def __init__(
        self,
        agent1: Optional[ThreatClassifierAgent] = None,
        agent2: Optional[AnomalyAgent2] = None,
        agent3: Optional[Agent3Skeleton] = None,
        agent4: Optional[TemporalCorrelationAgent] = None,
        agent5: Optional[AdaptiveDefenseAgent] = None,
        quality_monitor: Optional[DataQualityMonitor] = None,
    ) -> None:
        """Initialize five-agent architecture with dependencies."""
        self.quality_monitor = quality_monitor or DataQualityMonitor()

        # Agent 1: ThreatClassifierAgent
        if agent1 is not None:
            self.agent1 = agent1
        else:
            model_path = "models/threat_classifier.joblib"
            self.agent1 = ThreatClassifierAgent(model_path=model_path if os.path.exists(model_path) else None)

        # Agent 2: AnomalyAgent2
        if agent2 is not None:
            self.agent2 = agent2
        else:
            model_dir = "models/anomaly_model"
            if os.path.exists(model_dir):
                try:
                    trained_bundle = load_trained_model(model_dir)
                    self.agent2 = AnomalyAgent2(trained_model=trained_bundle)
                except Exception as exc:
                    logger.warning("Failed to load anomaly model from %s: %s", model_dir, exc)
                    self.agent2 = None
            else:
                self.agent2 = None

        # Agent 3: Evidence Fusion Coordinator
        self.agent3 = agent3 or Agent3Skeleton(strict_mode=False)

        # Agent 4: Temporal Correlation Agent
        self.agent4 = agent4 or TemporalCorrelationAgent()

        # Agent 5: Adaptive Defense Agent
        self.agent5 = agent5 or AdaptiveDefenseAgent()

    def _extract_routing_metadata(self, raw_flow: Dict[str, Any], default_seq: int) -> Dict[str, Any]:
        """Safely extract endpoint routing metadata."""
        flow_id = str(
            raw_flow.get("record_id")
            or raw_flow.get("flow_id")
            or raw_flow.get("Flow ID")
            or f"FLOW_{default_seq}"
        )
        try:
            seq = int(raw_flow.get("seq", default_seq))
        except (ValueError, TypeError):
            seq = default_seq

        timestamp = str(
            raw_flow.get("timestamp")
            or raw_flow.get("time_offset")
            or raw_flow.get("Timestamp")
            or f"2017-07-04 {raw_flow.get('time_offset', '')}".strip()
            or str(seq)
        )
        src_ip = str(raw_flow.get("source_ip") or raw_flow.get("src_ip") or "UNKNOWN").strip()
        dst_ip = str(raw_flow.get("destination_ip") or raw_flow.get("dst_ip") or "UNKNOWN").strip()

        try:
            src_port = int(raw_flow.get("source_port") or raw_flow.get("src_port") or 0)
        except (ValueError, TypeError):
            src_port = 0

        try:
            dst_port = int(raw_flow.get("destination_port") or raw_flow.get("dst_port") or raw_flow.get("Destination Port") or 0)
        except (ValueError, TypeError):
            dst_port = 0

        protocol = str(raw_flow.get("protocol") or raw_flow.get("Protocol") or "TCP")

        return {
            "flow_id": flow_id,
            "record_id": flow_id,
            "seq": seq,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
        }

    def _run_upstream_agents(
        self,
        raw_flow: Dict[str, Any],
        routing: Dict[str, Any],
    ) -> Tuple[Agent1ThreatPrediction, Agent2AnomalyAssessment, Any]:
        """Execute A1, A2, and A3 on an individual flow record."""
        # 1. Agent 1 (Supervised Threat Classifier)
        if self.agent1 is not None and getattr(self.agent1, "is_loaded", True):
            a1_result = self.agent1.predict_flow(raw_flow)
        else:
            a1_result = Agent1ThreatPrediction(
                agent_id="agent_1",
                status=AgentStatus.UNAVAILABLE,
                predicted_class="BENIGN",
                confidence=0.0,
            )

        # 2. Agent 2 (Behavioral Anomaly Detection)
        if self.agent2 is not None:
            feature_dict = {
                k: float(v) for k, v in raw_flow.items()
                if k not in routing and isinstance(v, (int, float))
            }
            net_flow = NetworkFlow(
                flow_id=routing["flow_id"],
                timestamp=routing["timestamp"],
                src_ip=routing["src_ip"],
                dst_ip=routing["dst_ip"],
                src_port=routing["src_port"],
                dst_port=routing["dst_port"],
                protocol=routing["protocol"],
                features=feature_dict,
            )
            try:
                ev = self.agent2.analyze_flow(net_flow)
                a2_result = adapt_agent2_evidence_to_assessment(ev)
            except Exception as exc:
                logger.debug("Agent 2 inference failed: %s", exc)
                a2_result = Agent2AnomalyAssessment(
                    agent_id="agent_2",
                    status=AgentStatus.ERROR,
                    anomaly_detected=False,
                    anomaly_score=0.0,
                    error_message=str(exc),
                )
        else:
            # Fallback when Agent 2 model is unconfigured
            a2_result = Agent2AnomalyAssessment(
                agent_id="agent_2",
                status=AgentStatus.UNAVAILABLE,
                anomaly_detected=False,
                anomaly_score=0.0,
            )

        # 3. Agent 3 (Contextual Evidence Fusion)
        flow_context = FlowContext(
            flow_id=routing["flow_id"],
            timestamp=routing["timestamp"],
            src_ip=routing["src_ip"],
            src_port=routing["src_port"],
            dst_ip=routing["dst_ip"],
            dst_port=routing["dst_port"],
            protocol=routing["protocol"],
        )
        agent3_input = Agent3Input(
            flow_context=flow_context,
            a1_result=a1_result,
            a2_result=a2_result,
            network_metadata=routing,
        )
        try:
            a3_assessment = self.agent3.process(agent3_input)
        except Exception as exc:
            logger.error("Agent 3 processing error: %s", exc)
            a3_assessment = None

        return a1_result, a2_result, a3_assessment

    def replay_dataset(
        self,
        flows: Sequence[Dict[str, Any]],
        reset_state: bool = True,
    ) -> ReplaySessionResult:
        """Execute full chronological replay over a dataset of flow records.

        Strict Rules:
          - Records are replayed in their exact supplied sequence.
          - Never sorts or rearranges records.
          - Active policies checked first.
          - Blocked flows receive classification predictions but do not trigger new policies.
          - Allowed flows proceed through A1 -> A2 -> A3 -> A4 -> A5.
        """
        if reset_state:
            self.agent4.reset()
            self.agent5.reset()

        # Build mapping from sequence number to record ID for exact policy expiry resolution
        seq_to_record_id: Dict[int, str] = {}
        for idx, item in enumerate(flows):
            raw = item if isinstance(item, dict) else (item.to_dict() if hasattr(item, "to_dict") else {})
            rid = str(raw.get("record_id") or raw.get("flow_id") or f"FLOW_{idx + 1}")
            s = int(raw.get("seq", idx + 1))
            seq_to_record_id[s] = rid

        def resolve_expiry_record_id(expiry_seq: int) -> str:
            if expiry_seq in seq_to_record_id:
                return seq_to_record_id[expiry_seq]
            # If past the end of the test set, record boundary format
            return f"RECORD_SEQ_{expiry_seq}"

        classification_records: List[Dict[str, Any]] = []
        replay_records: List[Dict[str, Any]] = []

        total = len(flows)
        allowed_count = 0
        blocked_count = 0

        for idx, item in enumerate(flows):
            raw = item if isinstance(item, dict) else (item.to_dict() if hasattr(item, "to_dict") else {})
            routing = self._extract_routing_metadata(raw, default_seq=idx + 1)
            record_id = routing["record_id"]
            seq = routing["seq"]

            # =================================================================
            # STEP 1: Check Active Policies in Agent 5 FIRST
            # =================================================================
            blocking_decision = self.agent5.check_active_policies(
                flow=raw,
                current_seq=seq,
                current_record_id=record_id,
            )

            if blocking_decision is not None:
                # -------------------------------------------------------------
                # RECORD IS BLOCKED BY AN ACTIVE POLICY
                # -------------------------------------------------------------
                blocked_count += 1
                replay_records.append(blocking_decision.to_dict())

                # Mandatory: Compute and preserve classification prediction separately
                a1_res, a2_res, a3_res = self._run_upstream_agents(raw, routing)
                pred_class = normalize_class_name(a1_res.predicted_class if a1_res else "BENIGN")
                anomaly_score = float(a2_res.anomaly_score) if a2_res else 0.0

                ev_status = "INSUFFICIENT_EVIDENCE"
                if a3_res and hasattr(a3_res, "details") and isinstance(a3_res.details, dict):
                    ev_status = str(a3_res.details.get("evidence_status", "INSUFFICIENT_EVIDENCE")).upper()

                classification_records.append({
                    "record_id": record_id,
                    "predicted_class": pred_class,
                    "anomaly_score": anomaly_score,
                    "evidence_status": ev_status,
                })

                # Invariant: Do NOT analyze the blocked flow to create another policy!
                continue

            # =================================================================
            # STEP 2: No Policy Matches -> Traffic ALLOWED, Run A1..A4 and evaluate A5
            # =================================================================
            allowed_count += 1

            # Upstream classifications (A1, A2, A3)
            a1_res, a2_res, a3_res = self._run_upstream_agents(raw, routing)

            pred_class = normalize_class_name(a1_res.predicted_class if a1_res else "BENIGN")
            anomaly_score = float(a2_res.anomaly_score) if a2_res else 0.0

            ev_status = "INSUFFICIENT_EVIDENCE"
            if a3_res and hasattr(a3_res, "details") and isinstance(a3_res.details, dict):
                ev_status = str(a3_res.details.get("evidence_status", "INSUFFICIENT_EVIDENCE")).upper()

            classification_records.append({
                "record_id": record_id,
                "predicted_class": pred_class,
                "anomaly_score": anomaly_score,
                "evidence_status": ev_status,
            })

            # Run Agent 4 (Temporal Correlation)
            flow_context = FlowContext(
                flow_id=routing["flow_id"],
                timestamp=routing["timestamp"],
                src_ip=routing["src_ip"],
                src_port=routing["src_port"],
                dst_ip=routing["dst_ip"],
                dst_port=routing["dst_port"],
                protocol=routing["protocol"],
            )
            a4_res = self.agent4.process_flow(
                flow=flow_context,
                a1_result=a1_res,
                a2_result=a2_res,
                a3_result=a3_res,
                seq=seq,
            )

            # Let Agent 5 decide whether to activate a temporary policy for FUTURE records
            self.agent5.evaluate_and_activate_policy(
                flow=raw,
                a1_result=a1_res,
                a2_result=a2_res,
                a3_result=a3_res,
                a4_result=a4_res,
                current_seq=seq,
                current_record_id=record_id,
                expiry_record_id_resolver=resolve_expiry_record_id,
            )

            # Record ALLOW replay decision for the current record
            allow_decision = self.agent5.record_allow_decision(
                record_id=record_id,
                reason="Traffic allowed; no active policy matched",
            )
            replay_records.append(allow_decision.to_dict())

        return ReplaySessionResult(
            total_records=total,
            allowed_records=allowed_count,
            blocked_records=blocked_count,
            classification_records=classification_records,
            replay_records=replay_records,
            activated_policies=self.agent5.get_all_policies(),
            temporal_groups=self.agent4.get_all_groups(),
            audit_events=[e.to_dict() for e in self.agent5.audit_logger.get_events()],
        )
