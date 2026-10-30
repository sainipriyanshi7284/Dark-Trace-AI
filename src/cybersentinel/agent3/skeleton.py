"""Minimal module skeleton for Agent 3 (Contextual Fusion & Triage).

This module contains the skeleton class and entry point conforming to the
provisional interface contract. Detailed fusion algorithms and policy engine
integration will be implemented in subsequent development blocks.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from cybersentinel.agent3.contract import (
    A1DetectionResult,
    A2DetectionResult,
    Agent3Input,
    Agent3Output,
    AgentStatus,
    FlowContext,
    FusionStatus,
    RecommendedAction,
    Verdict,
)
from cybersentinel.agent3.exceptions import (
    Agent3Error,
    InvalidInputError,
    MissingAgentError,
)

logger = logging.getLogger(__name__)


class Agent3Skeleton:
    """Minimal skeleton for Agent 3 in CyberSentinel.

    Responsibilities:
      - Validates incoming flow context and detection payloads from A1 and A2.
      - Handles missing or delayed upstream agent detections gracefully.
      - Dispatches to fusion pipeline (stubbed for future blocks).
      - Produces normalized Agent3Output consumed by downstream Policy Engine.
    """

    def __init__(self, strict_mode: bool = False) -> None:
        """Initialize Agent 3 skeleton.

        Args:
            strict_mode: If True, requires both A1 and A2 to be present.
                         If False, enables graceful single-agent fallback.
        """
        self.strict_mode = strict_mode
        logger.info("Initialized Agent3Skeleton (strict_mode=%s)", self.strict_mode)

    def validate_input(self, input_data: Agent3Input) -> None:
        """Validate input payload against contract schema.

        Args:
            input_data: Agent3Input instance to validate.

        Raises:
            InvalidInputError: If flow_context or sub-structures are invalid.
            MissingAgentError: If strict_mode is True and an agent result is missing.
        """
        if not isinstance(input_data, Agent3Input):
            raise InvalidInputError(f"Expected Agent3Input, got {type(input_data).__name__}")

        try:
            input_data.validate()
        except ValueError as exc:
            raise InvalidInputError(f"Input validation failed: {exc}") from exc

        if self.strict_mode:
            if input_data.a1_result is None or input_data.a2_result is None:
                raise MissingAgentError("Strict mode enabled: both A1 and A2 results are required.")

    def inspect_agent_availability(
        self,
        input_data: Agent3Input
    ) -> Tuple[bool, bool, FusionStatus]:
        """Inspect presence and operational status of Agent 1 and Agent 2.

        Returns:
            Tuple of (a1_available, a2_available, fusion_status).
        """
        a1_ok = (
            input_data.a1_result is not None
            and input_data.a1_result.status == AgentStatus.SUCCESS
        )
        a2_ok = (
            input_data.a2_result is not None
            and input_data.a2_result.status == AgentStatus.SUCCESS
        )

        if a1_ok and a2_ok:
            return True, True, FusionStatus.DUAL_AGENT
        elif a1_ok and not a2_ok:
            return True, False, FusionStatus.SINGLE_AGENT_A1_ONLY
        elif not a1_ok and a2_ok:
            return False, True, FusionStatus.SINGLE_AGENT_A2_ONLY
        else:
            return False, False, FusionStatus.NO_AGENT_DATA

    def process(self, input_data: Agent3Input) -> Agent3Output:
        """Primary entry point for Agent 3 evaluation.

        Executes schema validation, missing-agent handling, and produces
        a provisional output structure.

        Args:
            input_data: Validated or unvalidated Agent3Input.

        Returns:
            Agent3Output: Structured detection and triage verdict.
        """
        start_time = time.perf_counter()
        self.validate_input(input_data)

        a1_ok, a2_ok, fusion_status = self.inspect_agent_availability(input_data)
        incident_id = f"inc-{uuid.uuid4().hex[:12]}"
        contributing: List[str] = []

        if a1_ok:
            contributing.append("agent_1")
        if a2_ok:
            contributing.append("agent_2")

        # ---------------------------------------------------------------------
        # SKELETON LOGIC / PROVISIONAL FUSION DISPATCH
        # NOTE: Deep contextual fusion algorithms will be implemented in Block 2.
        # Below is the provisional stub establishing the interface contract.
        # ---------------------------------------------------------------------
        verdict = Verdict.INCONCLUSIVE
        fused_risk_score = 0.0
        confidence = 0.0
        recommended_action = RecommendedAction.LOG_ALLOW
        summary = "Provisional evaluation pending Block 2 fusion implementation."

        if fusion_status == FusionStatus.DUAL_AGENT:
            # Placeholder for dual-agent fusion logic
            a1 = input_data.a1_result
            a2 = input_data.a2_result
            assert a1 is not None and a2 is not None

            # Provisional baseline: weighted aggregation stub
            fused_risk_score = round(0.5 * a1.confidence + 0.5 * a2.anomaly_score, 4)
            confidence = round(0.5 * a1.confidence + 0.5 * a2.confidence, 4)

            if a1.threat_detected or a2.anomaly_detected:
                verdict = Verdict.SUSPICIOUS if fused_risk_score < 0.75 else Verdict.MALICIOUS
                recommended_action = (
                    RecommendedAction.ALERT if verdict == Verdict.SUSPICIOUS else RecommendedAction.DROP
                )
                summary = (
                    f"Correlated threat detected by {contributing}: "
                    f"A1 threat='{a1.threat_type}', A2 anomaly='{a2.anomaly_type}'."
                )
            else:
                verdict = Verdict.BENIGN
                recommended_action = RecommendedAction.LOG_ALLOW
                summary = "Both agents reported benign flow traffic."

        elif fusion_status == FusionStatus.SINGLE_AGENT_A1_ONLY:
            a1 = input_data.a1_result
            assert a1 is not None
            # Penalty applied for missing A2 confirmation
            confidence_penalty = 0.8
            fused_risk_score = round(a1.confidence * confidence_penalty, 4)
            confidence = round(a1.confidence * confidence_penalty, 4)
            verdict = Verdict.SUSPICIOUS if a1.threat_detected else Verdict.BENIGN
            recommended_action = RecommendedAction.ALERT if a1.threat_detected else RecommendedAction.LOG_ALLOW
            summary = (
                f"Degraded single-agent triage (A1 only). "
                f"Threat='{a1.threat_type}' (penalty applied due to missing A2)."
            )

        elif fusion_status == FusionStatus.SINGLE_AGENT_A2_ONLY:
            a2 = input_data.a2_result
            assert a2 is not None
            # Penalty applied for missing A1 signature confirmation
            confidence_penalty = 0.75
            fused_risk_score = round(a2.anomaly_score * confidence_penalty, 4)
            confidence = round(a2.confidence * confidence_penalty, 4)
            verdict = Verdict.SUSPICIOUS if a2.anomaly_detected else Verdict.BENIGN
            recommended_action = RecommendedAction.ALERT if a2.anomaly_detected else RecommendedAction.LOG_ALLOW
            summary = (
                f"Degraded single-agent triage (A2 only). "
                f"Anomaly='{a2.anomaly_type}' (penalty applied due to missing A1)."
            )

        else:  # NO_AGENT_DATA
            verdict = Verdict.INCONCLUSIVE
            fused_risk_score = 0.0
            confidence = 0.0
            recommended_action = RecommendedAction.LOG_ALLOW
            summary = "No upstream agent detections available. Marked inconclusive."

        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 3)

        return Agent3Output(
            incident_id=incident_id,
            flow_id=input_data.flow_context.flow_id,
            timestamp=input_data.flow_context.timestamp,
            verdict=verdict,
            fused_risk_score=fused_risk_score,
            confidence=confidence,
            contributing_agents=contributing,
            fusion_status=fusion_status,
            threat_summary=summary,
            details={
                "provisional_contract_version": "0.1.0-provisional",
                "flow": {
                    "src": f"{input_data.flow_context.src_ip}:{input_data.flow_context.src_port}",
                    "dst": f"{input_data.flow_context.dst_ip}:{input_data.flow_context.dst_port}",
                    "protocol": input_data.flow_context.protocol,
                },
                "a1_present": a1_ok,
                "a2_present": a2_ok,
            },
            recommended_policy_action=recommended_action,
            processing_time_ms=elapsed_ms,
        )

    def process_raw(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Convenience method accepting raw JSON-compatible dict and returning dict.

        Args:
            payload: Dict matching Agent3Input schema.

        Returns:
            Dict matching Agent3Output schema.
        """
        flow_raw = payload.get("flow_context")
        if not isinstance(flow_raw, dict):
            raise InvalidInputError("Payload missing required 'flow_context' object.")

        flow_context = FlowContext(
            flow_id=flow_raw.get("flow_id", ""),
            timestamp=flow_raw.get("timestamp", ""),
            src_ip=flow_raw.get("src_ip", ""),
            src_port=int(flow_raw.get("src_port", 0)),
            dst_ip=flow_raw.get("dst_ip", ""),
            dst_port=int(flow_raw.get("dst_port", 0)),
            protocol=flow_raw.get("protocol", "TCP"),
            packet_count=flow_raw.get("packet_count"),
            byte_count=flow_raw.get("byte_count"),
        )

        a1_result: Optional[A1DetectionResult] = None
        if "a1_result" in payload and payload["a1_result"] is not None:
            a1_raw = payload["a1_result"]
            a1_result = A1DetectionResult(
                agent_id=a1_raw.get("agent_id", "agent_1"),
                status=AgentStatus(a1_raw.get("status", AgentStatus.SUCCESS.value)),
                threat_detected=bool(a1_raw.get("threat_detected", False)),
                threat_type=a1_raw.get("threat_type"),
                confidence=float(a1_raw.get("confidence", 0.0)),
                rule_id=a1_raw.get("rule_id"),
                features=a1_raw.get("features", {}),
                latency_ms=a1_raw.get("latency_ms"),
                error_message=a1_raw.get("error_message"),
            )

        a2_result: Optional[A2DetectionResult] = None
        if "a2_result" in payload and payload["a2_result"] is not None:
            a2_raw = payload["a2_result"]
            a2_result = A2DetectionResult(
                agent_id=a2_raw.get("agent_id", "agent_2"),
                status=AgentStatus(a2_raw.get("status", AgentStatus.SUCCESS.value)),
                anomaly_detected=bool(a2_raw.get("anomaly_detected", False)),
                anomaly_score=float(a2_raw.get("anomaly_score", 0.0)),
                anomaly_type=a2_raw.get("anomaly_type"),
                confidence=float(a2_raw.get("confidence", 0.0)),
                model_version=a2_raw.get("model_version"),
                features=a2_raw.get("features", {}),
                latency_ms=a2_raw.get("latency_ms"),
                error_message=a2_raw.get("error_message"),
            )

        input_data = Agent3Input(
            flow_context=flow_context,
            a1_result=a1_result,
            a2_result=a2_result,
            network_metadata=payload.get("network_metadata", {}),
        )

        output = self.process(input_data)
        return output.to_dict()

