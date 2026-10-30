"""Comprehensive unit tests for CyberSentinel central orchestration pipeline."""

import json
from unittest.mock import MagicMock, patch
import pytest

from cybersentinel.agent1 import ThreatClassifierAgent
from cybersentinel.agent1.contract import Agent1ThreatPrediction, AgentStatus
from cybersentinel.agent2 import AnomalyAgent2
from cybersentinel.agent3 import Agent3Skeleton
from cybersentinel.agent3.schemas import Agent2AnomalyAssessment, Agent3ThreatAssessment
from cybersentinel.agent4 import PolicyAction, PolicyDecision, PolicyEngine
from cybersentinel.data_quality import DataQualityMonitor, FlowQualityReport, QualityStatus
from cybersentinel.orchestration.contracts import BatchProcessingSummary, FlowProcessingResult
from cybersentinel.orchestration.pipeline import CyberSentinelPipeline


@pytest.fixture
def mock_agent1():
    """Mock Agent 1 returning healthy prediction."""
    agent = MagicMock(spec=ThreatClassifierAgent)
    agent.is_loaded = True
    agent.predict_flow.return_value = Agent1ThreatPrediction(
        agent_id="agent_1",
        status=AgentStatus.SUCCESS,
        predicted_class="BENIGN",
        confidence=0.99,
        probabilities={"BENIGN": 0.99, "DOS": 0.01},
    )
    return agent


@pytest.fixture
def mock_agent2():
    """Mock Agent 2 returning healthy anomaly assessment."""
    agent = MagicMock(spec=AnomalyAgent2)
    evidence_mock = MagicMock()
    evidence_mock.flow_id = "test_flow_001"
    evidence_mock.timestamp = "2026-10-30T12:00:00Z"
    evidence_mock.metadata = {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1"}
    evidence_mock.anomaly_detection.is_anomaly = False
    evidence_mock.anomaly_detection.anomaly_label = "NORMAL"
    evidence_mock.anomaly_detection.normalized_anomaly_score = 0.05
    evidence_mock.anomaly_detection.raw_anomaly_score = -0.1
    evidence_mock.anomaly_detection.threshold = 0.5
    evidence_mock.anomaly_detection.model_version = "isolation_forest_v1"
    evidence_mock.anomaly_detection.supporting_features = []
    evidence_mock.anomaly_detection.inference_latency_ms = 1.2
    evidence_mock.to_dict.return_value = {
        "anomaly_evidence": {
            "is_anomaly": False,
            "anomaly_label": "NORMAL",
            "anomaly_score": 0.05,
        },
        "threat_intelligence": {},
        "routing_metadata": {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1"},
    }
    agent.analyze_flow.return_value = evidence_mock
    return agent


@pytest.fixture
def sample_healthy_flow():
    """Realistic network flow with routing metadata and telemetry features."""
    return {
        "flow_id": "FLOW-TEST-001",
        "timestamp": "2026-10-30T12:00:00Z",
        "src_ip": "10.0.1.5",
        "dst_ip": "192.168.1.100",
        "src_port": 49152,
        "dst_port": 443,
        "protocol": "TCP",
        "Destination Port": 443,
        "Flow Duration": 1200,
        "Total Fwd Packets": 10,
        "Total Backward Packets": 12,
        "Total Length of Fwd Packets": 500,
        "Total Length of Bwd Packets": 1200,
    }


# =============================================================================
# 1. Healthy Flow Through All Five Modules
# =============================================================================
def test_one_healthy_flow_end_to_end(mock_agent1, mock_agent2, sample_healthy_flow):
    """Test full execution of healthy flow producing ALLOW decision."""
    pipeline = CyberSentinelPipeline(
        agent1=mock_agent1,
        agent2=mock_agent2,
    )
    result = pipeline.process_flow(sample_healthy_flow)

    assert isinstance(result, FlowProcessingResult)
    assert result.flow_id == "FLOW-TEST-001"
    assert result.action in ("ALLOW", "ALERT", "REVIEW")
    assert result.final_status == "SUCCESS"
    assert len(result.processing_errors) == 0

    # Ensure all five modules left artifacts
    assert result.data_quality_report is not None
    assert result.data_quality_report["quality_status"] == "HEALTHY"
    assert result.agent1_result is not None
    assert result.agent1_result["predicted_class"] == "BENIGN"
    assert result.agent2_result is not None
    assert result.agent3_assessment is not None
    assert result.agent4_policy_decision is not None


# =============================================================================
# 2. Batch Processing & Aggregation
# =============================================================================
def test_batch_processing(mock_agent1, mock_agent2, sample_healthy_flow):
    """Verify batch processing produces individual outputs and correct summary counts."""
    pipeline = CyberSentinelPipeline(
        agent1=mock_agent1,
        agent2=mock_agent2,
    )
    batch = [
        dict(sample_healthy_flow, flow_id="BATCH-001"),
        dict(sample_healthy_flow, flow_id="BATCH-002"),
        dict(sample_healthy_flow, flow_id="BATCH-003", **{"Destination Port": -99, "Flow Duration": float("nan")}),
    ]

    summary = pipeline.process_batch(batch)

    assert isinstance(summary, BatchProcessingSummary)
    assert summary.total_flows == 3
    assert len(summary.results) == 3
    assert summary.quality_critical_count >= 1
    assert (summary.allow_count + summary.alert_count + summary.review_count + summary.block_count) == 3


# =============================================================================
# 3. Critical Data-Quality Failure
# =============================================================================
def test_critical_data_quality_failure(mock_agent1, mock_agent2, sample_healthy_flow):
    """Corrupted flow must NOT be sent to Agent 1 or 2, and must yield REVIEW."""
    corrupt_flow = dict(
        sample_healthy_flow,
        flow_id="FLOW-CORRUPT-001",
        **{"Destination Port": -500, "Flow Duration": float("nan"), "Total Fwd Packets": float("inf")}
    )
    pipeline = CyberSentinelPipeline(
        agent1=mock_agent1,
        agent2=mock_agent2,
    )
    result = pipeline.process_flow(corrupt_flow)

    assert result.flow_id == "FLOW-CORRUPT-001"
    assert result.action == "REVIEW"
    assert result.final_status == "CRITICAL_QUALITY_FAILURE"
    assert len(result.processing_errors) > 0

    # Ensure detection agents were NOT invoked for corrupt flow
    mock_agent1.predict_flow.assert_not_called()
    mock_agent2.analyze_flow.assert_not_called()


# =============================================================================
# 4. Agent 1 Failure Graceful Handling
# =============================================================================
def test_agent1_failure_handling(mock_agent2, sample_healthy_flow):
    """When Agent 1 raises an exception, pipeline records error and completes via fallback."""
    failing_a1 = MagicMock(spec=ThreatClassifierAgent)
    failing_a1.is_loaded = True
    failing_a1.predict_flow.side_effect = RuntimeError("Agent 1 GPU out of memory")

    pipeline = CyberSentinelPipeline(
        agent1=failing_a1,
        agent2=mock_agent2,
    )
    result = pipeline.process_flow(sample_healthy_flow)

    assert result.flow_id == "FLOW-TEST-001"
    assert any("Agent 1" in err for err in result.processing_errors)
    assert result.agent3_assessment is not None
    assert result.agent4_policy_decision is not None
    assert result.action in ("ALLOW", "ALERT", "REVIEW")


# =============================================================================
# 5. Agent 2 Failure Graceful Handling
# =============================================================================
def test_agent2_failure_handling(mock_agent1, sample_healthy_flow):
    """When Agent 2 fails, pipeline continues gracefully using Agent 1."""
    failing_a2 = MagicMock(spec=AnomalyAgent2)
    failing_a2.analyze_flow.side_effect = TimeoutError("Agent 2 TinyFish lookup timeout")

    pipeline = CyberSentinelPipeline(
        agent1=mock_agent1,
        agent2=failing_a2,
    )
    result = pipeline.process_flow(sample_healthy_flow)

    assert result.flow_id == "FLOW-TEST-001"
    assert any("Agent 2" in err for err in result.processing_errors)
    assert result.agent1_result is not None
    assert result.agent3_assessment is not None
    assert result.agent4_policy_decision is not None


# =============================================================================
# 6. Agent 3 Fusion Failure Graceful Handling
# =============================================================================
def test_agent3_failure_handling(mock_agent1, mock_agent2, sample_healthy_flow):
    """When Agent 3 fails, pipeline falls back to safe REVIEW policy."""
    failing_a3 = MagicMock(spec=Agent3Skeleton)
    failing_a3.process.side_effect = ValueError("Agent 3 correlation matrix error")

    pipeline = CyberSentinelPipeline(
        agent1=mock_agent1,
        agent2=mock_agent2,
        agent3=failing_a3,
    )
    result = pipeline.process_flow(sample_healthy_flow)

    assert result.action == "REVIEW"
    assert any("Agent 3" in err for err in result.processing_errors)
    assert result.agent4_policy_decision is not None
    assert result.agent4_policy_decision["matched_rule"] == "FALLBACK_AGENT3_UNAVAILABLE"


# =============================================================================
# 7. Agent 4 Policy Failure Graceful Handling
# =============================================================================
def test_agent4_failure_handling(mock_agent1, mock_agent2, sample_healthy_flow):
    """When Agent 4 fails, pipeline fails safe to REVIEW."""
    failing_a4 = MagicMock(spec=PolicyEngine)
    failing_a4.evaluate.side_effect = KeyError("Rule evaluation table missing")

    pipeline = CyberSentinelPipeline(
        agent1=mock_agent1,
        agent2=mock_agent2,
        policy_engine=failing_a4,
    )
    result = pipeline.process_flow(sample_healthy_flow)

    assert result.action == "REVIEW"
    assert any("Agent 4" in err for err in result.processing_errors)
    assert result.agent4_policy_decision["matched_rule"] == "POLICY_EXECUTION_FAILURE_SAFEGUARD"


# =============================================================================
# 8. Missing or Invalid Flow IDs
# =============================================================================
def test_missing_flow_id(mock_agent1, mock_agent2, sample_healthy_flow):
    """Missing flow_id is gracefully defaulted and preserved."""
    no_id_flow = dict(sample_healthy_flow)
    del no_id_flow["flow_id"]

    pipeline = CyberSentinelPipeline(
        agent1=mock_agent1,
        agent2=mock_agent2,
    )
    result = pipeline.process_flow(no_id_flow)

    assert result.flow_id is not None
    assert len(result.flow_id) > 0
    assert result.metadata["flow_id"] == result.flow_id


# =============================================================================
# 9. Metadata Preservation
# =============================================================================
def test_metadata_preservation(mock_agent1, mock_agent2, sample_healthy_flow):
    """Ensure original IPs, ports, and protocols are retained in metadata."""
    pipeline = CyberSentinelPipeline(
        agent1=mock_agent1,
        agent2=mock_agent2,
    )
    result = pipeline.process_flow(sample_healthy_flow)

    assert result.metadata["src_ip"] == "10.0.1.5"
    assert result.metadata["dst_ip"] == "192.168.1.100"
    assert result.metadata["src_port"] == 49152
    assert result.metadata["dst_port"] == 443
    assert result.metadata["protocol"] == "TCP"


# =============================================================================
# 10. JSON Serialization of Final Results
# =============================================================================
def test_json_serialization(mock_agent1, mock_agent2, sample_healthy_flow):
    """Ensure result to_json() produces valid, uncorrupted JSON."""
    pipeline = CyberSentinelPipeline(
        agent1=mock_agent1,
        agent2=mock_agent2,
    )
    result = pipeline.process_flow(sample_healthy_flow)
    json_str = result.to_json()

    parsed = json.loads(json_str)
    assert parsed["flow_id"] == "FLOW-TEST-001"
    assert "data_quality_report" in parsed
    assert "action" in parsed
    assert "metadata" in parsed


# =============================================================================
# 11. No Accidental Real Blocking Action
# =============================================================================
def test_no_accidental_real_blocking(sample_healthy_flow):
    """Verify that BLOCK decisions are strictly flagged as simulated."""
    # Create attack prediction to trigger BLOCK
    attack_a1 = MagicMock(spec=ThreatClassifierAgent)
    attack_a1.is_loaded = True
    attack_a1.predict_flow.return_value = Agent1ThreatPrediction(
        agent_id="agent_1",
        status=AgentStatus.SUCCESS,
        predicted_class="DOS",
        confidence=0.99,
        probabilities={"BENIGN": 0.01, "DOS": 0.99},
    )

    pipeline = CyberSentinelPipeline(agent1=attack_a1)
    result = pipeline.process_flow(sample_healthy_flow)

    assert result.agent4_policy_decision is not None
    # Ensure simulated is unconditionally True
    assert result.agent4_policy_decision.get("simulated") is True

