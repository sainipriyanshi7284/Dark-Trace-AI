"""Agent 2 (Network Anomaly Detection) Coordinator.

This module provides the main entry point for Agent 2 in the Dark-Trace-AI
architecture.

CORE ARCHITECTURAL RULES:
1. INDEPENDENT EXECUTION: Agent 2 operates independently of Agent 1. It does not
   read, require, or wait for Agent 1's supervised classification.
2. EVIDENCE GENERATION WITHOUT PREMATURE VERDICTS: Agent 2 produces anomaly
   evidence. When the model is unavailable or encounters an error, it explicitly
   reports status ('MODEL_NOT_READY', 'VALIDATION_ERROR', 'INFERENCE_ERROR', 'INVALID_INPUT')
   and sets is_anomaly to None. It NEVER reports is_anomaly=False without an actual real model evaluation.
3. AGENT 3 EVIDENCE HANDOVER: Formats evidence into the standardized payload for Agent 3.
   Threat intelligence is completely disabled and reports an explicit 'DISABLED' status.
"""

from typing import Any, Dict, Optional
import logging
import time

from dark_trace.agent2.config import Agent2Config
from dark_trace.agent2.model import AnomalyDetectorInterface, IsolationForestDetector
from dark_trace.agent2.schemas import (
    Agent2Evidence,
    AnomalyScore,
    NetworkFlowInput,
    create_disabled_threat_intel_payload,
)

logger = logging.getLogger(__name__)


class Agent2:
    """Agent 2 Pipeline Coordinator.

    Orchestrates unsupervised network anomaly detection using the calibrated 74-feature
    Isolation Forest model and packages evidence for Agent 3 evidence fusion.
    """

    def __init__(
        self,
        config: Optional[Agent2Config] = None,
        model: Optional[AnomalyDetectorInterface] = None,
    ):
        """Initialize Agent 2.

        Args:
            config: Agent 2 configuration settings.
            model: Anomaly detector instance (default: IsolationForestDetector).
        """
        self.config = config or Agent2Config()
        if model is not None:
            self.model = model
        else:
            try:
                self.model = IsolationForestDetector(
                    model_path=self.config.model_path,
                    metadata_path=self.config.metadata_path,
                    config=self.config,
                )
            except Exception as load_err:
                logger.warning("Agent 2 detector could not be loaded: %s", load_err)
                # Create unloaded detector so Agent 2 safely reports MODEL_NOT_READY
                unloaded = IsolationForestDetector.__new__(IsolationForestDetector)
                unloaded.config = self.config
                unloaded.model_path = None
                unloaded.metadata_path = None
                unloaded.model = None
                unloaded.metadata = {}
                unloaded.feature_names = []
                unloaded.expected_feature_count = 74
                unloaded.threshold = None
                unloaded.model_version = "unavailable"
                self.model = unloaded

    def analyze_flow(self, flow: Any) -> Agent2Evidence:
        """Process a single network flow and produce evidence for Agent 3.

        Steps:
        1. Validate flow structure (accepts NetworkFlowInput, NetworkFlow, or dict).
        2. Check model readiness. If unavailable, return MODEL_NOT_READY with is_anomaly=None.
        3. Validate 74 flow features and execute real Isolation Forest scoring.
        4. If validation or inference fails, catch safely and return explicit error status with is_anomaly=None.
        5. Assemble standardized Agent2Evidence package for Agent 3.

        Args:
            flow: Input network flow data (NetworkFlowInput, NetworkFlow, or dictionary).

        Returns:
            Agent2Evidence: Structured evidence payload for Agent 3.
        """
        # Step 1: Input structural validation
        if flow is None:
            return Agent2Evidence(
                flow_id="unknown",
                agent_id="A2",
                anomaly_evidence=AnomalyScore(
                    status="INVALID_INPUT",
                    is_anomaly=None,
                    threshold=getattr(self.model, "threshold", self.config.calibrated_threshold),
                    model_version=getattr(self.model, "model_version", "unavailable"),
                    error_message="Flow input cannot be None.",
                ).to_dict(),
            )

        validated_flow: NetworkFlowInput
        if isinstance(flow, dict):
            try:
                validated_flow = NetworkFlowInput.from_dict(flow)
            except Exception as err:
                return Agent2Evidence(
                    flow_id="unknown",
                    agent_id="A2",
                    anomaly_evidence=AnomalyScore(
                        status="INVALID_INPUT",
                        is_anomaly=None,
                        threshold=getattr(self.model, "threshold", self.config.calibrated_threshold),
                        model_version=getattr(self.model, "model_version", "unavailable"),
                        error_message=f"Failed to parse flow dictionary: {err}",
                    ).to_dict(),
                )
        elif isinstance(flow, NetworkFlowInput):
            validated_flow = flow
        elif hasattr(flow, "features") and isinstance(getattr(flow, "features"), dict):
            # Compatible flow object (e.g., dark_trace.common.schemas.NetworkFlow)
            validated_flow = NetworkFlowInput(
                flow_id=str(getattr(flow, "flow_id", "unknown")),
                timestamp=str(getattr(flow, "timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))),
                src_ip=str(getattr(flow, "src_ip", "0.0.0.0")),
                dst_ip=str(getattr(flow, "dst_ip", "0.0.0.0")),
                src_port=int(getattr(flow, "src_port", 0)),
                dst_port=int(getattr(flow, "dst_port", 0)),
                protocol=getattr(flow, "protocol", "TCP"),
                features=dict(getattr(flow, "features", {})),
                metadata=dict(getattr(flow, "metadata", {})),
            )
        else:
            return Agent2Evidence(
                flow_id=str(getattr(flow, "flow_id", "unknown")),
                agent_id="A2",
                anomaly_evidence=AnomalyScore(
                    status="INVALID_INPUT",
                    is_anomaly=None,
                    threshold=getattr(self.model, "threshold", self.config.calibrated_threshold),
                    model_version=getattr(self.model, "model_version", "unavailable"),
                    error_message=f"Expected NetworkFlowInput or dict, got {type(flow).__name__}",
                ).to_dict(),
            )

        # Step 2: Anomaly Scoring via Isolation Forest interface
        anomaly_score: AnomalyScore

        if not self.model.is_loaded():
            anomaly_score = AnomalyScore(
                status="MODEL_NOT_READY",
                is_anomaly=None,
                raw_score=None,
                normalized_score=None,
                threshold=self.config.calibrated_threshold,
                model_version="unavailable",
                supporting_features=[],
                inference_latency_ms=None,
                error_message="Isolation Forest model artifact or verified metadata is not loaded.",
            )
        else:
            try:
                anomaly_score = self.model.predict_anomaly(validated_flow.features)
            except ValueError as val_err:
                logger.warning("Feature validation error for flow %s: %s", validated_flow.flow_id, val_err)
                anomaly_score = AnomalyScore(
                    status="VALIDATION_ERROR",
                    is_anomaly=None,
                    raw_score=None,
                    normalized_score=None,
                    threshold=getattr(self.model, "threshold", self.config.calibrated_threshold),
                    model_version=getattr(self.model, "model_version", "unknown"),
                    supporting_features=[],
                    inference_latency_ms=None,
                    error_message=str(val_err),
                )
            except Exception as inf_err:
                logger.error("Inference exception for flow %s: %s", validated_flow.flow_id, inf_err)
                anomaly_score = AnomalyScore(
                    status="INFERENCE_ERROR",
                    is_anomaly=None,
                    raw_score=None,
                    normalized_score=None,
                    threshold=getattr(self.model, "threshold", self.config.calibrated_threshold),
                    model_version=getattr(self.model, "model_version", "unknown"),
                    supporting_features=[],
                    inference_latency_ms=None,
                    error_message=str(inf_err),
                )

        evidence = Agent2Evidence(
            flow_id=validated_flow.flow_id,
            timestamp=validated_flow.timestamp,
            agent_id="A2",
            anomaly_evidence=anomaly_score.to_dict(),
            threat_intelligence=create_disabled_threat_intel_payload(),
            routing_metadata={
                "src_ip": validated_flow.src_ip,
                "dst_ip": validated_flow.dst_ip,
                "src_port": validated_flow.src_port,
                "dst_port": validated_flow.dst_port,
                "protocol": validated_flow.protocol,
            },
        )

        return evidence

    def format_for_agent3(self, evidence: Agent2Evidence) -> Dict[str, Any]:
        """Convert Agent2Evidence into the standard dictionary contract for Agent 3.

        Args:
            evidence: Agent2Evidence generated by analyze_flow().

        Returns:
            Dict[str, Any]: Standardized evidence package ready for Agent 3 fusion.
        """
        return evidence.to_dict()


# Backward compatibility alias
AnomalyAgent2 = Agent2
