"""Batch processing engine and flow orchestration for Agent 2.

Handles batch ingestion of network flows, per-record input validation,
resilient execution, and generation of Agent2Evidence payloads.
"""

from dataclasses import asdict, dataclass, field
import json
import time
from typing import Any, Dict, List, Optional, Sequence, Union

from dark_trace.agent2.explainability import AnomalyExplainer
from dark_trace.agent2.trainer import TrainedAnomalyModel
from dark_trace.common.schemas import (
    Agent2Evidence,
    AnomalyDetectionResult,
    NetworkFlow,
    ThreatIntelligenceResult,
    ValidationError,
)


@dataclass
class BatchProcessingResult:
    """Aggregated outcome of batch flow inference."""

    total_records: int
    valid_count: int
    invalid_count: int
    anomalous_count: int
    normal_count: int
    evidence: List[Agent2Evidence]
    errors: List[Dict[str, Any]]  # {'record_index': int, 'error': str, 'raw_record': Any}
    processing_time_ms: float

    def to_dict(self) -> Dict[str, Any]:
        """Serialize batch result to dictionary."""
        return {
            "total_records": self.total_records,
            "valid_count": self.valid_count,
            "invalid_count": self.invalid_count,
            "anomalous_count": self.anomalous_count,
            "normal_count": self.normal_count,
            "evidence": [e.to_dict() for e in self.evidence],
            "errors": list(self.errors),
            "processing_time_ms": self.processing_time_ms,
        }

    def to_json(self) -> str:
        """Serialize batch result to JSON string."""
        return json.dumps(self.to_dict())


class BatchAnomalyProcessor:
    """Orchestrates validation, preprocessing, Isolation Forest scoring, and explainability.

    Processes individual flows or high-throughput batches while isolating invalid records
    so that partial inputs do not terminate the entire batch.
    """

    def __init__(
        self,
        trained_model: TrainedAnomalyModel,
        explainer: Optional[AnomalyExplainer] = None,
    ):
        """Initialize the batch processor.

        Args:
            trained_model: TrainedAnomalyModel artifact bundle.
            explainer: Optional AnomalyExplainer instance. If omitted, an explainer
                calibrated with the model's preprocessor feature_stats_ is initialized.
        """
        self.trained_model = trained_model
        stats = trained_model.preprocessor.feature_stats_
        self.explainer = explainer or AnomalyExplainer(baseline_stats=stats)

    def process_flow(
        self,
        raw_flow: Union[NetworkFlow, Dict[str, Any]],
    ) -> Agent2Evidence:
        """Process a single network flow record into complete Agent 2 evidence.

        Args:
            raw_flow: NetworkFlow object or dictionary.

        Returns:
            Agent2Evidence: Complete anomaly detection evidence package.

        Raises:
            ValidationError: If raw_flow fails schema validation.
        """
        start_time = time.perf_counter()

        # Step 1: Validate flow schema
        if isinstance(raw_flow, NetworkFlow):
            flow = raw_flow
        elif isinstance(raw_flow, dict):
            flow = NetworkFlow.from_dict(raw_flow)
        else:
            raise ValidationError("root", f"Unsupported flow type: {type(raw_flow).__name__}", raw_flow)

        # Step 2: Anomaly Detection Scoring
        score_info = self.trained_model.score_record(flow)

        # Step 3: Statistical Explainability
        supporting_features = self.explainer.explain_flow(
            flow, preprocessor=self.trained_model.preprocessor
        )

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        anomaly_detection_result = AnomalyDetectionResult(
            is_anomaly=score_info["is_anomaly"],
            anomaly_label=score_info["anomaly_label"],
            raw_anomaly_score=score_info["raw_anomaly_score"],
            normalized_anomaly_score=score_info["normalized_anomaly_score"],
            threshold=score_info["threshold"],
            supporting_features=supporting_features,
            model_version=self.trained_model.model_version,
            inference_latency_ms=latency_ms,
        )

        # Default un-enriched threat intelligence payload (enriched in Phase 3)
        threat_intel_result = ThreatIntelligenceResult(
            provider="tinyfish",
            investigation_status="NOT_REQUESTED",
        )

        # Metadata echo for Agent 3 correlation
        metadata = {
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "force_threat_intel": flow.force_threat_intel,
        }
        if flow.metadata:
            metadata.update(flow.metadata)

        return Agent2Evidence(
            agent_id="A2",
            flow_id=flow.flow_id,
            timestamp=flow.timestamp,
            anomaly_detection=anomaly_detection_result,
            threat_intelligence=threat_intel_result,
            metadata=metadata,
        )

    def process_batch(
        self,
        records: Sequence[Any],
    ) -> BatchProcessingResult:
        """Process a sequence of network flow records in batch.

        Invalid records are safely caught, logged in `errors`, and do not terminate
        the processing of valid records.

        Args:
            records: Sequence of NetworkFlow objects, dictionaries, or JSON strings.

        Returns:
            BatchProcessingResult: Aggregated summary, evidence list, and error log.
        """
        start_time = time.perf_counter()

        if not records:
            return BatchProcessingResult(
                total_records=0,
                valid_count=0,
                invalid_count=0,
                anomalous_count=0,
                normal_count=0,
                evidence=[],
                errors=[],
                processing_time_ms=0.0,
            )

        valid_flows: List[NetworkFlow] = []
        errors: List[Dict[str, Any]] = []

        # Step 1: Resilient Ingestion & Validation
        for i, item in enumerate(records):
            try:
                if isinstance(item, NetworkFlow):
                    valid_flows.append(item)
                elif isinstance(item, dict):
                    valid_flows.append(NetworkFlow.from_dict(item))
                elif isinstance(item, str):
                    valid_flows.append(NetworkFlow.from_json(item))
                else:
                    errors.append(
                        {
                            "record_index": i,
                            "error": f"Invalid record type: {type(item).__name__}",
                            "raw_record": str(item),
                        }
                    )
            except Exception as err:
                errors.append(
                    {
                        "record_index": i,
                        "error": str(err),
                        "raw_record": str(item) if not isinstance(item, dict) else item.get("flow_id", str(item)),
                    }
                )

        if not valid_flows:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return BatchProcessingResult(
                total_records=len(records),
                valid_count=0,
                invalid_count=len(errors),
                anomalous_count=0,
                normal_count=0,
                evidence=[],
                errors=errors,
                processing_time_ms=duration_ms,
            )

        # Step 2: High-throughput batch anomaly scoring
        batch_scores = self.trained_model.score_batch(valid_flows)

        # Step 3: Evidence packaging and per-flow explainability
        evidence_list: List[Agent2Evidence] = []
        anomalous_count = 0
        normal_count = 0

        for flow, score_info in zip(valid_flows, batch_scores):
            is_anomaly = score_info["is_anomaly"]
            if is_anomaly:
                anomalous_count += 1
            else:
                normal_count += 1

            supporting_features = self.explainer.explain_flow(
                flow, preprocessor=self.trained_model.preprocessor
            )

            anomaly_result = AnomalyDetectionResult(
                is_anomaly=is_anomaly,
                anomaly_label=score_info["anomaly_label"],
                raw_anomaly_score=score_info["raw_anomaly_score"],
                normalized_anomaly_score=score_info["normalized_anomaly_score"],
                threshold=score_info["threshold"],
                supporting_features=supporting_features,
                model_version=self.trained_model.model_version,
                inference_latency_ms=0.0,
            )

            threat_intel_result = ThreatIntelligenceResult(
                provider="tinyfish",
                investigation_status="NOT_REQUESTED",
            )

            metadata = {
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "src_port": flow.src_port,
                "dst_port": flow.dst_port,
                "protocol": flow.protocol,
                "force_threat_intel": flow.force_threat_intel,
            }
            if flow.metadata:
                metadata.update(flow.metadata)

            evidence_list.append(
                Agent2Evidence(
                    agent_id="A2",
                    flow_id=flow.flow_id,
                    timestamp=flow.timestamp,
                    anomaly_detection=anomaly_result,
                    threat_intelligence=threat_intel_result,
                    metadata=metadata,
                )
            )

        total_duration_ms = (time.perf_counter() - start_time) * 1000.0

        return BatchProcessingResult(
            total_records=len(records),
            valid_count=len(valid_flows),
            invalid_count=len(errors),
            anomalous_count=anomalous_count,
            normal_count=normal_count,
            evidence=evidence_list,
            errors=errors,
            processing_time_ms=total_duration_ms,
        )
