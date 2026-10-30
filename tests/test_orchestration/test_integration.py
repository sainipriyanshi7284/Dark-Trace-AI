"""End-to-end integration tests using real available module instances."""

import json
import os
import pytest

from cybersentinel.agent1 import ThreatClassifierAgent
from cybersentinel.agent3 import Agent3Skeleton
from cybersentinel.agent4 import PolicyAction, PolicyEngine
from cybersentinel.data_quality import DataQualityMonitor
from cybersentinel.orchestration.contracts import FlowProcessingResult
from cybersentinel.orchestration.pipeline import CyberSentinelPipeline


@pytest.fixture
def real_pipeline():
    """Construct real pipeline using real trained ThreatClassifierAgent and core agents."""
    model_path = "models/threat_classifier.joblib"
    a1 = ThreatClassifierAgent(model_path=model_path) if os.path.exists(model_path) else None
    return CyberSentinelPipeline(
        quality_monitor=DataQualityMonitor(),
        agent1=a1,
        agent2=None,  # Real A2 uses unsupervised isolation forest which requires baseline training
        agent3=Agent3Skeleton(strict_mode=False),
        policy_engine=PolicyEngine(),
    )


def test_real_pipeline_benign_flow(real_pipeline):
    """Test actual execution of real pipeline with a benign flow."""
    benign_flow = {
        "flow_id": "REAL-BENIGN-001",
        "timestamp": "2026-10-30T14:00:00Z",
        "src_ip": "192.168.1.50",
        "dst_ip": "10.0.0.1",
        "src_port": 51234,
        "dst_port": 80,
        "protocol": "TCP",
        "Destination Port": 80,
        "Flow Duration": 15000,
        "Total Fwd Packets": 6,
        "Total Backward Packets": 6,
        "Total Length of Fwd Packets": 250,
        "Total Length of Bwd Packets": 400,
        "Fwd Packet Length Max": 100,
        "Fwd Packet Length Min": 0,
        "Fwd Packet Length Mean": 41.6,
        "Fwd Packet Length Std": 20.0,
        "Bwd Packet Length Max": 150,
        "Bwd Packet Length Min": 0,
        "Bwd Packet Length Mean": 66.6,
        "Bwd Packet Length Std": 25.0,
        "Flow Bytes/s": 43333.3,
        "Flow Packets/s": 800.0,
    }

    result = real_pipeline.process_flow(benign_flow)

    assert isinstance(result, FlowProcessingResult)
    assert result.flow_id == "REAL-BENIGN-001"
    assert result.data_quality_report["quality_status"] == "HEALTHY"
    assert result.agent1_result is not None
    assert result.agent1_result["status"] == "SUCCESS"
    assert result.agent3_assessment is not None
    assert result.agent4_policy_decision is not None
    assert result.action in ("ALLOW", "ALERT", "REVIEW")
    assert result.agent4_policy_decision["simulated"] is True

    # Test full JSON serialization
    serialized = result.to_json()
    assert isinstance(serialized, str)
    deserialized = json.loads(serialized)
    assert deserialized["flow_id"] == "REAL-BENIGN-001"


def test_real_pipeline_attack_flow(real_pipeline):
    """Test actual execution of real pipeline with a high-volume DoS signature flow."""
    dos_flow = {
        "flow_id": "REAL-DOS-001",
        "timestamp": "2026-10-30T14:05:00Z",
        "src_ip": "172.16.0.5",
        "dst_ip": "192.168.10.50",
        "src_port": 44444,
        "dst_port": 80,
        "protocol": "TCP",
        "Destination Port": 80,
        "Flow Duration": 200,
        "Total Fwd Packets": 1000,
        "Total Backward Packets": 0,
        "Total Length of Fwd Packets": 0,
        "Total Length of Bwd Packets": 0,
        "Fwd Packet Length Max": 0,
        "Fwd Packet Length Min": 0,
        "Fwd Packet Length Mean": 0.0,
        "Fwd Packet Length Std": 0.0,
        "Bwd Packet Length Max": 0,
        "Bwd Packet Length Min": 0,
        "Bwd Packet Length Mean": 0.0,
        "Bwd Packet Length Std": 0.0,
        "Flow Bytes/s": 0.0,
        "Flow Packets/s": 5000000.0,
    }

    result = real_pipeline.process_flow(dos_flow)

    assert isinstance(result, FlowProcessingResult)
    assert result.flow_id == "REAL-DOS-001"
    assert result.agent1_result is not None
    assert result.agent3_assessment is not None
    assert result.agent4_policy_decision is not None
    assert result.agent4_policy_decision["simulated"] is True


def test_real_pipeline_batch_execution(real_pipeline):
    """Test batch processing over mixed real flows."""
    batch = [
        {
            "flow_id": f"BATCH-REAL-{i}",
            "Destination Port": 443,
            "Flow Duration": 500 + i * 10,
            "Total Fwd Packets": 5,
            "Total Backward Packets": 5,
        }
        for i in range(5)
    ]
    # Add one corrupt record
    batch.append({
        "flow_id": "BATCH-CORRUPT",
        "Destination Port": -99,
        "Flow Duration": float("nan"),
    })

    summary = real_pipeline.process_batch(batch)

    assert summary.total_flows == 6
    assert len(summary.results) == 6
    assert summary.quality_critical_count == 1
    assert (summary.allow_count + summary.alert_count + summary.review_count + summary.block_count) == 6

