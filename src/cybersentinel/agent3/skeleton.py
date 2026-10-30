"""Minimal module skeleton for Agent 3 (Contextual Fusion & Triage).

This module contains the skeleton class and entry point conforming to the
interface contract, delegating to the Block 4 FusionScorer for deterministic
fusion scoring, evidence correlation, and structured output production.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple, Union

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
    SchemaValidationError,
)
from cybersentinel.agent3.fusion_scorer import (
    FusionConfig,
    FusionResult,
    FusionScorer,
)
from cybersentinel.agent3.schemas import (
    Agent1ThreatPrediction,
    Agent2AnomalyAssessment,
    Agent3FusionInput,
    Agent3ThreatAssessment,
)
from cybersentinel.agent3.validator import (
    validate_agent1_output,
    validate_agent2_output,
)

logger = logging.getLogger(__name__)


class Agent3Skeleton:
    """Minimal skeleton for Agent 3 in CyberSentinel.

    Responsibilities:
      - Validates incoming flow context and detection payloads from A1 and A2.
      - Handles missing or delayed upstream agent detections gracefully.
      - Dispatches to intelligent fusion scorer (Block 4) combining evidence.
      - Produces normalized Agent3Output consumed by downstream Policy Engine.
    """

    def __init__(
        self,
        strict_mode: bool = False,
        fusion_config: Optional[FusionConfig] = None,
    ) -> None:
        """Initialize Agent 3 skeleton.

        Args:
            strict_mode: If True, requires both A1 and A2 to be present.
                         If False, enables graceful single-agent fallback.
            fusion_config: Optional configuration for fusion weights and thresholds.
        """
        self.strict_mode = strict_mode
        self.fusion_config = fusion_config or FusionConfig()
        self.scorer = FusionScorer(config=self.fusion_config)
        logger.info("Initialized Agent3Skeleton (strict_mode=%s)", self.strict_mode)

    def validate_input(self, input_data: Union[Agent3Input, Agent3FusionInput]) -> None:
        """Validate input payload against contract schema.

        Args:
            input_data: Agent3Input or Agent3FusionInput instance to validate.

        Raises:
            InvalidInputError: If flow_context or sub-structures are invalid.
            MissingAgentError: If strict_mode is True and an agent result is missing.
        """
        if not isinstance(input_data, (Agent3Input, Agent3FusionInput)):
            raise InvalidInputError(f"Expected Agent3Input or Agent3FusionInput, got {type(input_data).__name__}")

        try:
            input_data.validate()
        except ValueError as exc:
            raise InvalidInputError(f"Input validation failed: {exc}") from exc

        if self.strict_mode:
            a1 = getattr(input_data, "a1_prediction", None) or getattr(input_data, "a1_result", None)
            a2 = getattr(input_data, "a2_assessment", None) or getattr(input_data, "a2_result", None)
            if a1 is None or a2 is None:
                raise MissingAgentError("Strict mode enabled: both A1 and A2 results are required.")

    def inspect_agent_availability(
        self,
        input_data: Union[Agent3Input, Agent3FusionInput]
    ) -> Tuple[bool, bool, FusionStatus]:
        """Inspect presence and operational status of Agent 1 and Agent 2.

        Returns:
            Tuple of (a1_available, a2_available, fusion_status).
        """
        a1 = getattr(input_data, "a1_prediction", None) or getattr(input_data, "a1_result", None)
        a2 = getattr(input_data, "a2_assessment", None) or getattr(input_data, "a2_result", None)

        a1_ok = (
            a1 is not None
            and getattr(a1, "status", AgentStatus.SUCCESS) == AgentStatus.SUCCESS
        )
        a2_ok = (
            a2 is not None
            and getattr(a2, "status", AgentStatus.SUCCESS) == AgentStatus.SUCCESS
        )

        if a1_ok and a2_ok:
            return True, True, FusionStatus.DUAL_AGENT
        elif a1_ok and not a2_ok:
            return True, False, FusionStatus.SINGLE_AGENT_A1_ONLY
        elif not a1_ok and a2_ok:
            return False, True, FusionStatus.SINGLE_AGENT_A2_ONLY
        else:
            return False, False, FusionStatus.NO_AGENT_DATA

    def process(self, input_data: Union[Agent3Input, Agent3FusionInput]) -> Agent3Output:
        """Primary entry point for Agent 3 evaluation.

        Executes schema validation, missing-agent handling, and produces
        a structured detection and triage verdict via FusionScorer.

        Args:
            input_data: Validated or unvalidated Agent3Input or Agent3FusionInput.

        Returns:
            Agent3Output: Structured detection and triage verdict.
        """
        start_time = time.perf_counter()
        self.validate_input(input_data)

        # Execute Block 4 fusion scoring engine
        fusion_result = self.scorer.score(input_data=input_data)
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 3)

        return fusion_result.to_agent3_output(processing_time_ms=elapsed_ms)

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

    def process_flow(
        self,
        agent1_result: Optional[Union[Agent1ThreatPrediction, A1DetectionResult, Dict[str, Any]]] = None,
        agent2_result: Optional[Union[Agent2AnomalyAssessment, A2DetectionResult, Dict[str, Any]]] = None,
        flow_id: Optional[str] = None,
        flow_context: Optional[Union[FlowContext, Dict[str, Any]]] = None,
        strict_mode: Optional[bool] = None,
    ) -> Agent3ThreatAssessment:
        """Process a flow through the complete Agent 3 pipeline.

        1. Input validation & missing agent checks
        2. Evidence correlation across A1 and A2
        3. Deterministic intelligent fusion scoring
        4. Template-based explainability generation
        5. Structured threat assessment emission

        Args:
            agent1_result: Agent 1 detection result or dict.
            agent2_result: Agent 2 anomaly assessment or dict.
            flow_id: Identifier for the flow.
            flow_context: Optional FlowContext instance or dict.
            strict_mode: Optional override for strict mode setting.

        Returns:
            Agent3ThreatAssessment: Final structured threat assessment.
        """
        start_time = time.perf_counter()
        use_strict = self.strict_mode if strict_mode is None else strict_mode

        # Reject obviously invalid input payload types
        for agent_name, raw_res in (("Agent 1", agent1_result), ("Agent 2", agent2_result)):
            if raw_res is not None and not isinstance(raw_res, dict) and not hasattr(raw_res, "__dataclass_fields__") and not hasattr(raw_res, "confidence"):
                raise InvalidInputError(f"{agent_name} payload must be a dict or dataclass, got {type(raw_res).__name__}.")

        # Resolve FlowContext
        if flow_context is not None:
            if isinstance(flow_context, dict):
                flow_ctx = FlowContext(
                    flow_id=str(flow_context.get("flow_id", flow_id or f"FLOW-{uuid.uuid4().hex[:8]}")),
                    timestamp=str(flow_context.get("timestamp", "")),
                    src_ip=str(flow_context.get("src_ip", "0.0.0.0")),
                    src_port=int(flow_context.get("src_port", 0)),
                    dst_ip=str(flow_context.get("dst_ip", "0.0.0.0")),
                    dst_port=int(flow_context.get("dst_port", 0)),
                    protocol=str(flow_context.get("protocol", "TCP")),
                    packet_count=flow_context.get("packet_count"),
                    byte_count=flow_context.get("byte_count"),
                )
            elif isinstance(flow_context, FlowContext):
                flow_ctx = flow_context
            else:
                raise InvalidInputError(f"Expected FlowContext or dict for flow_context, got {type(flow_context).__name__}")
        else:
            import datetime
            fid = flow_id or f"FLOW-{uuid.uuid4().hex[:8]}"
            flow_ctx = FlowContext(
                flow_id=fid,
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                src_ip="192.168.1.1",
                src_port=1024,
                dst_ip="10.0.0.1",
                dst_port=80,
                protocol="TCP",
            )

        # Validate flow_context
        try:
            flow_ctx.validate()
        except ValueError as exc:
            raise InvalidInputError(f"Invalid flow context: {exc}") from exc

        # Handle strict mode requirements
        if use_strict:
            if agent1_result is None or agent2_result is None:
                raise MissingAgentError("Strict mode enabled: both Agent 1 and Agent 2 results are required.")
            val1 = validate_agent1_output(agent1_result)
            if not val1.is_valid:
                raise SchemaValidationError(f"Invalid Agent 1 input in strict mode: {'; '.join(val1.error_messages)}", validation_result=val1)
            val2 = validate_agent2_output(agent2_result)
            if not val2.is_valid:
                raise SchemaValidationError(f"Invalid Agent 2 input in strict mode: {'; '.join(val2.error_messages)}", validation_result=val2)

        # Execute fusion scoring (which correlates and generates explanations)
        fusion_result = self.scorer.score(
            flow_context=flow_ctx,
            a1_prediction=agent1_result,
            a2_assessment=agent2_result,
            flow_id=flow_ctx.flow_id,
            timestamp=flow_ctx.timestamp,
        )

        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 3)
        return fusion_result.to_threat_assessment(processing_time_ms=elapsed_ms)


def process_flow(
    agent1_result: Optional[Union[Agent1ThreatPrediction, A1DetectionResult, Dict[str, Any]]] = None,
    agent2_result: Optional[Union[Agent2AnomalyAssessment, A2DetectionResult, Dict[str, Any]]] = None,
    flow_id: Optional[str] = None,
    flow_context: Optional[Union[FlowContext, Dict[str, Any]]] = None,
    strict_mode: bool = False,
    config: Optional[FusionConfig] = None,
) -> Agent3ThreatAssessment:
    """Public standalone entry point for CyberSentinel Agent 3.

    Provides a clean, unified invocation pipeline:
      1. Validate inputs (distinguishing missing from malformed).
      2. Correlate evidence across Agent 1 and Agent 2.
      3. Compute normalized, deterministic multi-source fusion score.
      4. Generate template-based, explainable cybersecurity rationale.
      5. Return structured Agent3ThreatAssessment.

    Args:
        agent1_result: Agent 1 classification payload (dict, dataclass, or None).
        agent2_result: Agent 2 anomaly assessment payload (dict, dataclass, or None).
        flow_id: Network flow identifier string.
        flow_context: Optional complete FlowContext or dictionary metadata.
        strict_mode: If True, requires both A1 and A2 to be present.
        config: Optional custom FusionConfig parameters.

    Returns:
        Agent3ThreatAssessment: Complete structured threat assessment.
    """
    skeleton = Agent3Skeleton(strict_mode=strict_mode, fusion_config=config)
    return skeleton.process_flow(
        agent1_result=agent1_result,
        agent2_result=agent2_result,
        flow_id=flow_id,
        flow_context=flow_context,
        strict_mode=strict_mode,
    )

