"""Unified Agent 2: Intelligent Anomaly Detection & Threat Intelligence Coordinator.

Ties together:
1. Ingestion validation (NetworkFlow)
2. Statistical preprocessing (AnomalyPreprocessor)
3. Unsupervised ML anomaly detection (Isolation Forest)
4. Score calibration & outlier severity indexing
5. Statistical explainability (AnomalyExplainer)
6. External threat intelligence investigation (TinyFish Search & Fetch)
7. Final structured evidence packaging for Agent 3 (Agent2Evidence)
"""

import time
from typing import Any, Dict, List, Optional, Sequence, Union

from dark_trace.agent2.agent3_contract import format_agent2_for_agent3
from dark_trace.agent2.batch import BatchProcessingResult
from dark_trace.agent2.config import Agent2Config
from dark_trace.agent2.explainability import AnomalyExplainer
from dark_trace.agent2.threat_intel.client import TinyFishClient
from dark_trace.agent2.threat_intel.investigator import ThreatIntelInvestigator
from dark_trace.agent2.threat_intel.triggers import ThreatIntelTriggerPolicy
from dark_trace.agent2.trainer import TrainedAnomalyModel
from dark_trace.common.schemas import (
    Agent2Evidence,
    AnomalyDetectionResult,
    NetworkFlow,
    ThreatIntelligenceResult,
    ValidationError,
)


class AnomalyAgent2:
    """Agent 2 coordinator unifying ML anomaly detection and TinyFish threat intelligence."""

    def __init__(
        self,
        trained_model: TrainedAnomalyModel,
        explainer: Optional[AnomalyExplainer] = None,
        investigator: Optional[ThreatIntelInvestigator] = None,
        config: Optional[Agent2Config] = None,
    ):
        """Initialize Agent 2.

        Args:
            trained_model: Fitted TrainedAnomalyModel bundle.
            explainer: Optional AnomalyExplainer instance.
            investigator: Optional ThreatIntelInvestigator instance.
            config: Optional master Agent2Config dataclass.
        """
        self.config = config or Agent2Config()
        self.trained_model = trained_model

        stats = trained_model.preprocessor.feature_stats_
        self.explainer = explainer or AnomalyExplainer(baseline_stats=stats)

        # Initialize TinyFish threat intelligence investigator
        if investigator is not None:
            self.investigator = investigator
        else:
            client = TinyFishClient(
                timeout=self.config.threat_intel.request_timeout_seconds,
                max_retries=self.config.threat_intel.max_retries,
            )
            policy = ThreatIntelTriggerPolicy(
                severity_threshold=self.config.threat_intel.severity_trigger_threshold,
                cache_ttl_seconds=self.config.threat_intel.cache_ttl_seconds,
            )
            self.investigator = ThreatIntelInvestigator(client=client, policy=policy)

    def analyze_flow(
        self,
        raw_flow: Union[NetworkFlow, Dict[str, Any]],
    ) -> Agent2Evidence:
        """Perform end-to-end analysis on a single network flow record.

        Pipeline:
        1. Ingest & validate NetworkFlow schema.
        2. Score flow through Isolation Forest.
        3. Extract statistical supporting feature deviations.
        4. Conditionally enrich with TinyFish threat intelligence.
        5. Package into Agent2Evidence schema for Agent 3.

        Args:
            raw_flow: NetworkFlow object or dictionary.

        Returns:
            Agent2Evidence: Complete multi-dimensional evidence record.
        """
        start_time = time.perf_counter()

        # Step 1: Validate Schema
        if isinstance(raw_flow, NetworkFlow):
            flow = raw_flow
        elif isinstance(raw_flow, dict):
            flow = NetworkFlow.from_dict(raw_flow)
        else:
            raise ValidationError("root", f"Unsupported flow type: {type(raw_flow).__name__}", raw_flow)

        # Step 2: Isolation Forest Anomaly Scoring
        score_info = self.trained_model.score_record(flow)
        normalized_score = score_info["normalized_anomaly_score"]

        # Step 3: Statistical Explainability
        supporting_features = self.explainer.explain_flow(
            flow, preprocessor=self.trained_model.preprocessor
        )

        # Step 4: Selective External Threat Intelligence (TinyFish)
        if self.config.threat_intel.enabled:
            threat_intel_result = self.investigator.investigate_flow(
                flow=flow,
                normalized_anomaly_score=normalized_score,
            )
        else:
            threat_intel_result = ThreatIntelligenceResult(
                provider="tinyfish",
                investigation_status="NOT_REQUESTED",
            )

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        anomaly_result = AnomalyDetectionResult(
            is_anomaly=score_info["is_anomaly"],
            anomaly_label=score_info["anomaly_label"],
            raw_anomaly_score=score_info["raw_anomaly_score"],
            normalized_anomaly_score=normalized_score,
            threshold=score_info["threshold"],
            supporting_features=supporting_features,
            model_version=self.trained_model.model_version,
            inference_latency_ms=latency_ms,
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

        return Agent2Evidence(
            agent_id="A2",
            flow_id=flow.flow_id,
            timestamp=flow.timestamp,
            anomaly_detection=anomaly_result,
            threat_intelligence=threat_intel_result,
            metadata=metadata,
        )

    def analyze_batch(
        self,
        records: Sequence[Any],
    ) -> BatchProcessingResult:
        """Process a batch of network flow records in high throughput.

        Fault-tolerant: malformed records are isolated into errors without
        impacting valid flows.

        Args:
            records: Sequence of NetworkFlow objects, dicts, or JSON strings.

        Returns:
            BatchProcessingResult: Aggregated summary and evidence list.
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

        for i, item in enumerate(records):
            try:
                if isinstance(item, NetworkFlow):
                    valid_flows.append(item)
                elif isinstance(item, dict):
                    valid_flows.append(NetworkFlow.from_dict(item))
                elif isinstance(item, str):
                    valid_flows.append(NetworkFlow.from_json(item))
                else:
                    errors.append({"record_index": i, "error": f"Invalid type: {type(item).__name__}", "raw_record": str(item)})
            except Exception as err:
                errors.append({"record_index": i, "error": str(err), "raw_record": str(item) if not isinstance(item, dict) else item.get("flow_id", str(item))})

        evidence_list: List[Agent2Evidence] = []
        anomalous_count = 0
        normal_count = 0

        for flow in valid_flows:
            ev = self.analyze_flow(flow)
            if ev.anomaly_detection.is_anomaly:
                anomalous_count += 1
            else:
                normal_count += 1
            evidence_list.append(ev)

        duration_ms = (time.perf_counter() - start_time) * 1000.0

        return BatchProcessingResult(
            total_records=len(records),
            valid_count=len(valid_flows),
            invalid_count=len(errors),
            anomalous_count=anomalous_count,
            normal_count=normal_count,
            evidence=evidence_list,
            errors=errors,
            processing_time_ms=duration_ms,
        )

    def get_agent3_payload(
        self,
        raw_flow: Union[NetworkFlow, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Convenience method returning Agent 3-formatted evidence dictionary directly."""
        evidence = self.analyze_flow(raw_flow)
        return format_agent2_for_agent3(evidence)
