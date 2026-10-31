"""Central Orchestration Pipeline for CyberSentinel / Dark-Trace-AI.

Unifies and coordinates the 5 core modules in strict sequence:
  STEP 1: Ingestion & Metadata Partitioning
  STEP 2: Sensor & Data Quality Health Monitor (Feature E)
  STEP 3: Agent 1 - Supervised Threat Classification
  STEP 4: Agent 2 - Behavioral Anomaly Detection & Threat Intel
  STEP 5: Agent 3 - Evidence Fusion & Alert Correlation
  STEP 6: Agent 4 - Adaptive Policy Enforcement & Simulation
  STEP 7: Consolidated Structured Outcome Production
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Sequence, Union

from cybersentinel.agent1 import ThreatClassifierAgent
from cybersentinel.agent2 import (
    AnomalyAgent2,
    adapt_agent2_evidence_to_assessment,
)
from cybersentinel.agent3 import (
    Agent3Skeleton,
    AgentStatus,
    FlowContext,
    Verdict,
)
from cybersentinel.agent3.contract import Agent3Input
from cybersentinel.agent4 import (
    PolicyAction,
    PolicyDecision,
    PolicyEngine,
)
from cybersentinel.data_quality import (
    DataQualityMonitor,
    FlowQualityReport,
    QualityStatus,
)
from cybersentinel.orchestration.contracts import (
    BatchProcessingSummary,
    FlowProcessingResult,
)
from dark_trace.common.schemas import NetworkFlow

logger = logging.getLogger(__name__)


def _sanitize_string(val: Any, default: str = "") -> str:
    """Safely sanitize string representation."""
    if val is None:
        return default
    return str(val).strip()


def _sanitize_port(val: Any, default: int = 0) -> int:
    """Safely extract valid port integer."""
    try:
        p = int(val)
        return p if 0 <= p <= 65535 else default
    except (TypeError, ValueError):
        return default


class CyberSentinelPipeline:
    """Central orchestration coordinator executing the end-to-end CyberSentinel pipeline."""

    def __init__(
        self,
        quality_monitor: Optional[DataQualityMonitor] = None,
        agent1: Optional[ThreatClassifierAgent] = None,
        agent2: Optional[AnomalyAgent2] = None,
        agent3: Optional[Agent3Skeleton] = None,
        policy_engine: Optional[PolicyEngine] = None,
        strict_quality: bool = True,
    ) -> None:
        """Initialize pipeline with components.

        All components default to initialized instances if not explicitly injected.
        """
        self.quality_monitor = quality_monitor or DataQualityMonitor()
        self.agent1 = agent1 or ThreatClassifierAgent()
        self.agent2 = agent2  # May be None if unsupervised model bundle not loaded
        self.agent3 = agent3 or Agent3Skeleton(strict_mode=False)
        self.policy_engine = policy_engine or PolicyEngine()
        self.strict_quality = strict_quality

    def _extract_routing_metadata(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """Extract and preserve routing context from flow record."""
        # Standardize candidates
        flow_id = (
            flow.get("flow_id")
            or flow.get("record_id")
            or flow.get("Flow ID")
            or flow.get("id")
            or "UNKNOWN_FLOW"
        )
        timestamp = (
            flow.get("timestamp")
            or flow.get("Timestamp")
            or flow.get("time")
            or datetime.now(timezone.utc).isoformat()
        )
        src_ip = flow.get("src_ip") or flow.get("Source IP") or "10.0.0.1"
        dst_ip = flow.get("dst_ip") or flow.get("Destination IP") or "192.168.1.1"
        src_port = _sanitize_port(flow.get("src_port") or flow.get("Source Port"), default=40000)
        dst_port = _sanitize_port(
            flow.get("dst_port") or flow.get("Destination Port") or flow.get("Dest Port"),
            default=443
        )
        protocol = flow.get("protocol") or flow.get("Protocol") or "TCP"

        return {
            "flow_id": str(flow_id),
            "timestamp": str(timestamp),
            "src_ip": str(src_ip),
            "dst_ip": str(dst_ip),
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": str(protocol),
        }

    def process_flow(self, flow: Union[Dict[str, Any], Any]) -> FlowProcessingResult:
        """Execute full end-to-end pipeline on an individual network flow.

        Args:
            flow: Raw dictionary, pandas Series, or NetworkFlow object.

        Returns:
            FlowProcessingResult containing artifacts from all modules.
        """
        processing_errors: List[str] = []

        # =====================================================================
        # STEP 1: Ingestion & Metadata Partitioning
        # =====================================================================
        if hasattr(flow, "to_dict") and callable(flow.to_dict):
            raw_record = flow.to_dict()
        elif isinstance(flow, dict):
            raw_record = dict(flow)
        elif isinstance(flow, NetworkFlow):
            raw_record = {
                "flow_id": flow.flow_id,
                "timestamp": flow.timestamp,
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "src_port": flow.src_port,
                "dst_port": flow.dst_port,
                "protocol": flow.protocol,
                **flow.features,
            }
        else:
            return FlowProcessingResult(
                flow_id="MALFORMED_INPUT",
                data_quality_report={"quality_status": "CRITICAL", "quality_score": 0.0},
                final_status="CRITICAL_INPUT_ERROR",
                action="REVIEW",
                processing_errors=[f"Unsupported input type '{type(flow).__name__}'"],
            )

        routing_metadata = self._extract_routing_metadata(raw_record)
        flow_id = routing_metadata["flow_id"]

        # =====================================================================
        # STEP 2: Data Quality Health Monitor
        # =====================================================================
        try:
            validated_record, quality_report, is_safe_downstream = self.quality_monitor.validate_flow(raw_record)
        except Exception as exc:
            err_msg = f"Data Quality Monitor failure: {exc}"
            logger.error(err_msg)
            processing_errors.append(err_msg)
            quality_report = FlowQualityReport(
                flow_id=flow_id,
                quality_score=0.0,
                quality_status=QualityStatus.CRITICAL.value,
                issues=[err_msg],
                is_safe_downstream=False,
            )
            validated_record = raw_record
            is_safe_downstream = False

        # CRITICAL RULE: If flow has critical data quality problems, do not blindly pass
        if not is_safe_downstream or quality_report.is_critical:
            reasons = "; ".join(quality_report.issues[:3]) if quality_report.issues else "Quality score below threshold"
            decision_quarantine = PolicyDecision(
                agent_id="A4",
                flow_id=str(flow_id),
                action=PolicyAction.REVIEW,
                matched_rule="RULE_DATA_QUALITY_QUARANTINE",
                decision_reason=f"Data quality critical degradation (score: {quality_report.quality_score}). Issues: {reasons}",
                requires_human_review=True,
                simulated=True,
            )
            return FlowProcessingResult(
                flow_id=flow_id,
                data_quality_report=quality_report.to_dict(),
                agent1_result=None,
                agent2_result=None,
                agent3_assessment=None,
                agent4_policy_decision=decision_quarantine.to_dict(),
                final_status="CRITICAL_QUALITY_FAILURE",
                action="REVIEW",
                processing_errors=processing_errors + quality_report.issues,
                metadata=routing_metadata,
            )

        # =====================================================================
        # STEP 3: Agent 1 (Supervised Threat Classification)
        # =====================================================================
        agent1_result = None
        try:
            if self.agent1 is not None and getattr(self.agent1, "is_loaded", True):
                agent1_result = self.agent1.predict_flow(validated_record)
        except Exception as exc:
            err_msg = f"Agent 1 classification error: {exc}"
            logger.warning(err_msg)
            processing_errors.append(err_msg)

        # =====================================================================
        # STEP 4: Agent 2 (Behavioral Anomaly & Threat Intel)
        # =====================================================================
        agent2_result = None
        try:
            if self.agent2 is not None:
                # Prepare compatible NetworkFlow payload
                feature_dict = {
                    k: float(v) for k, v in validated_record.items()
                    if k not in routing_metadata and isinstance(v, (int, float))
                }
                net_flow = NetworkFlow(
                    flow_id=flow_id,
                    timestamp=routing_metadata["timestamp"],
                    src_ip=routing_metadata["src_ip"],
                    dst_ip=routing_metadata["dst_ip"],
                    src_port=routing_metadata["src_port"],
                    dst_port=routing_metadata["dst_port"],
                    protocol=routing_metadata["protocol"],
                    features=feature_dict,
                )
                evidence = self.agent2.analyze_flow(net_flow)
                agent2_result = adapt_agent2_evidence_to_assessment(evidence)
        except Exception as exc:
            err_msg = f"Agent 2 anomaly detection error: {exc}"
            logger.warning(err_msg)
            processing_errors.append(err_msg)

        # =====================================================================
        # STEP 5: Agent 3 (Evidence Fusion & Correlation)
        # =====================================================================
        agent3_assessment = None
        try:
            flow_context = FlowContext(
                flow_id=flow_id,
                timestamp=routing_metadata["timestamp"],
                src_ip=routing_metadata["src_ip"],
                src_port=routing_metadata["src_port"],
                dst_ip=routing_metadata["dst_ip"],
                dst_port=routing_metadata["dst_port"],
                protocol=routing_metadata["protocol"],
                packet_count=int(validated_record.get("Total Fwd Packets", 1)),
                byte_count=int(validated_record.get("Total Length of Fwd Packets", 0)),
            )

            agent3_input = Agent3Input(
                flow_context=flow_context,
                a1_result=agent1_result,
                a2_result=agent2_result,
                network_metadata=routing_metadata,
            )
            agent3_assessment = self.agent3.process(agent3_input)
        except Exception as exc:
            err_msg = f"Agent 3 evidence fusion error: {exc}"
            logger.error(err_msg)
            processing_errors.append(err_msg)

        # =====================================================================
        # STEP 6: Agent 4 (Policy Enforcement & Simulation)
        # =====================================================================
        policy_decision = None
        try:
            if agent3_assessment is not None:
                policy_decision = self.policy_engine.evaluate(agent3_assessment)
            else:
                # Fallback policy when Agent 3 fails
                policy_decision = PolicyDecision(
                    agent_id="A4",
                    flow_id=flow_id,
                    action=PolicyAction.REVIEW,
                    matched_rule="FALLBACK_AGENT3_UNAVAILABLE",
                    decision_reason="Upstream evidence fusion assessment was unavailable.",
                    requires_human_review=True,
                    simulated=True,
                )
        except Exception as exc:
            err_msg = f"Agent 4 policy evaluation error: {exc}"
            logger.error(err_msg)
            processing_errors.append(err_msg)
            policy_decision = PolicyDecision(
                agent_id="A4",
                flow_id=flow_id,
                action=PolicyAction.REVIEW,
                matched_rule="POLICY_EXECUTION_FAILURE_SAFEGUARD",
                decision_reason=f"Policy engine encountered an exception: {exc}",
                requires_human_review=True,
                simulated=True,
            )

        # Ensure BLOCK action remains simulated
        if policy_decision and hasattr(policy_decision, "simulated"):
            policy_decision.simulated = True

        final_action = policy_decision.action.value if hasattr(policy_decision.action, "value") else str(policy_decision.action)

        # =====================================================================
        # STEP 7: Final Structured Output
        # =====================================================================
        final_status = "SUCCESS"
        if processing_errors:
            final_status = "DEGRADED"
        elif quality_report.quality_status == QualityStatus.WARNING.value:
            final_status = "DATA_QUALITY_WARNING"

        return FlowProcessingResult(
            flow_id=flow_id,
            data_quality_report=quality_report.to_dict(),
            agent1_result=agent1_result.to_dict() if agent1_result else None,
            agent2_result=agent2_result.to_dict() if agent2_result else None,
            agent3_assessment=agent3_assessment.to_dict() if agent3_assessment else None,
            agent4_policy_decision=policy_decision.to_dict() if policy_decision else None,
            final_status=final_status,
            action=final_action,
            processing_errors=processing_errors,
            metadata=routing_metadata,
        )

    def process_batch(
        self,
        flows: Union[Any, Sequence[Dict[str, Any]]]
    ) -> BatchProcessingSummary:
        """Process a batch of network flows with isolated failure handling.

        Requirements:
        - Independent flow IDs.
        - One failed flow does not halt the entire batch.
        - Returns batch summary counts (ALLOW, ALERT, REVIEW, BLOCK, errors).
        """
        if flows is None:
            return BatchProcessingSummary()

        if hasattr(flows, "to_dict") and callable(flows.to_dict):
            flow_records = flows.to_dict(orient="records")
        elif isinstance(flows, (list, tuple)):
            flow_records = list(flows)
        else:
            flow_records = [flows]

        summary = BatchProcessingSummary(total_flows=len(flow_records))

        for item in flow_records:
            try:
                res = self.process_flow(item)
            except Exception as exc:
                logger.error("Unhandled exception processing flow: %s", exc)
                res = FlowProcessingResult(
                    flow_id=_sanitize_string(item.get("flow_id") if isinstance(item, dict) else "ERROR_FLOW"),
                    data_quality_report={"quality_status": "CRITICAL", "quality_score": 0.0},
                    final_status="UNHANDLED_EXCEPTION",
                    action="REVIEW",
                    processing_errors=[f"Unhandled pipeline exception: {exc}"],
                )

            summary.results.append(res)

            # Accumulate counts
            act = res.action.upper()
            if act == "ALLOW":
                summary.allow_count += 1
            elif act == "ALERT":
                summary.alert_count += 1
            elif act == "BLOCK":
                summary.block_count += 1
            else:
                summary.review_count += 1

            if res.processing_errors or "ERROR" in res.final_status:
                summary.error_count += 1

            q_status = res.data_quality_report.get("quality_status")
            if res.final_status == "CRITICAL_QUALITY_FAILURE" or q_status == QualityStatus.CRITICAL.value:
                summary.quality_critical_count += 1
            elif q_status == QualityStatus.WARNING.value:
                summary.quality_warning_count += 1

        return summary

