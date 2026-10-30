"""Unit tests for Agent 3 skeleton and provisional interface contract."""

import json
import pytest

from cybersentinel.agent3 import (
    A1DetectionResult,
    A2DetectionResult,
    Agent3Input,
    Agent3Output,
    Agent3Skeleton,
    AgentStatus,
    FlowContext,
    FusionStatus,
    InvalidInputError,
    MissingAgentError,
    RecommendedAction,
    Verdict,
)


@pytest.fixture
def sample_flow() -> FlowContext:
    return FlowContext(
        flow_id="flow-xyz-1001",
        timestamp="2026-10-30T10:15:30Z",
        src_ip="192.168.1.105",
        src_port=44321,
        dst_ip="10.0.0.5",
        dst_port=80,
        protocol="TCP",
        packet_count=120,
        byte_count=64500,
    )


@pytest.fixture
def sample_a1() -> A1DetectionResult:
    return A1DetectionResult(
        agent_id="agent_1",
        status=AgentStatus.SUCCESS,
        threat_detected=True,
        threat_type="SYN_FLOOD",
        confidence=0.88,
        rule_id="RULE-DOS-01",
        features={"syn_ratio": 0.95},
        latency_ms=1.2,
    )


@pytest.fixture
def sample_a2() -> A2DetectionResult:
    return A2DetectionResult(
        agent_id="agent_2",
        status=AgentStatus.SUCCESS,
        anomaly_detected=True,
        anomaly_score=0.82,
        anomaly_type="ABNORMAL_VOLUME",
        confidence=0.85,
        model_version="a2-autoencoder-v1",
        features={"reconstruction_loss": 0.45},
        latency_ms=5.4,
    )


def test_import_and_instantiation():
    """Verify Agent 3 skeleton can be imported and initialized."""
    agent = Agent3Skeleton()
    assert agent is not None
    assert agent.strict_mode is False


def test_dual_agent_processing(sample_flow, sample_a1, sample_a2):
    """Verify dual agent input produces valid Agent3Output."""
    agent = Agent3Skeleton()
    inp = Agent3Input(
        flow_context=sample_flow,
        a1_result=sample_a1,
        a2_result=sample_a2,
    )
    output = agent.process(inp)

    assert isinstance(output, Agent3Output)
    assert output.flow_id == sample_flow.flow_id
    assert output.fusion_status == FusionStatus.DUAL_AGENT
    assert output.verdict in [Verdict.MALICIOUS, Verdict.SUSPICIOUS]
    assert "agent_1" in output.contributing_agents
    assert "agent_2" in output.contributing_agents
    assert 0.0 <= output.fused_risk_score <= 1.0
    assert 0.0 <= output.confidence <= 1.0


def test_missing_agent_1_graceful_degradation(sample_flow, sample_a2):
    """Verify graceful handling when Agent 1 is unavailable."""
    agent = Agent3Skeleton()
    inp = Agent3Input(
        flow_context=sample_flow,
        a1_result=None,
        a2_result=sample_a2,
    )
    output = agent.process(inp)

    assert output.fusion_status == FusionStatus.SINGLE_AGENT_A2_ONLY
    assert output.contributing_agents == ["agent_2"]
    assert "agent_1" not in output.contributing_agents
    assert output.verdict == Verdict.SUSPICIOUS


def test_missing_agent_2_graceful_degradation(sample_flow, sample_a1):
    """Verify graceful handling when Agent 2 is unavailable."""
    agent = Agent3Skeleton()
    inp = Agent3Input(
        flow_context=sample_flow,
        a1_result=sample_a1,
        a2_result=None,
    )
    output = agent.process(inp)

    assert output.fusion_status == FusionStatus.SINGLE_AGENT_A1_ONLY
    assert output.contributing_agents == ["agent_1"]
    assert "agent_2" not in output.contributing_agents
    assert output.verdict == Verdict.SUSPICIOUS


def test_missing_both_agents_handling(sample_flow):
    """Verify fallback when neither agent delivers a result."""
    agent = Agent3Skeleton()
    inp = Agent3Input(
        flow_context=sample_flow,
        a1_result=None,
        a2_result=None,
    )
    output = agent.process(inp)

    assert output.fusion_status == FusionStatus.NO_AGENT_DATA
    assert output.verdict == Verdict.INCONCLUSIVE
    assert output.contributing_agents == []
    assert output.fused_risk_score == 0.0


def test_strict_mode_raises_on_missing_agent(sample_flow, sample_a1):
    """Verify strict mode rejects input when an agent is missing."""
    agent = Agent3Skeleton(strict_mode=True)
    inp = Agent3Input(
        flow_context=sample_flow,
        a1_result=sample_a1,
        a2_result=None,
    )
    with pytest.raises(MissingAgentError):
        agent.process(inp)


def test_invalid_input_validation():
    """Verify invalid inputs raise InvalidInputError."""
    agent = Agent3Skeleton()
    bad_flow = FlowContext(
        flow_id="",  # Empty flow_id
        timestamp="2026-10-30T10:15:30Z",
        src_ip="192.168.1.1",
        src_port=80,
        dst_ip="10.0.0.1",
        dst_port=80,
        protocol="TCP",
    )
    inp = Agent3Input(flow_context=bad_flow)
    with pytest.raises(InvalidInputError):
        agent.process(inp)


def test_serialization_and_deserialization(sample_flow, sample_a1, sample_a2):
    """Verify Agent3Output JSON serialization and deserialization."""
    agent = Agent3Skeleton()
    inp = Agent3Input(
        flow_context=sample_flow,
        a1_result=sample_a1,
        a2_result=sample_a2,
    )
    output = agent.process(inp)
    json_str = output.to_json()
    parsed = json.loads(json_str)

    assert parsed["flow_id"] == sample_flow.flow_id
    assert "verdict" in parsed
    assert "fused_risk_score" in parsed

    deserialized = Agent3Output.from_dict(parsed)
    assert deserialized.flow_id == output.flow_id
    assert deserialized.verdict == output.verdict
    assert deserialized.fused_risk_score == output.fused_risk_score


def test_process_raw_dictionary():
    """Verify process_raw interface accepts plain dictionaries."""
    agent = Agent3Skeleton()
    raw_payload = {
        "flow_context": {
            "flow_id": "flow-raw-99",
            "timestamp": "2026-10-30T11:00:00Z",
            "src_ip": "10.1.1.20",
            "src_port": 50505,
            "dst_ip": "172.16.0.4",
            "dst_port": 443,
            "protocol": "TCP",
        },
        "a1_result": {
            "status": "SUCCESS",
            "threat_detected": True,
            "threat_type": "PORT_SCAN",
            "confidence": 0.9,
        },
    }
    result = agent.process_raw(raw_payload)
    assert result["flow_id"] == "flow-raw-99"
    assert result["fusion_status"] == FusionStatus.SINGLE_AGENT_A1_ONLY.value
    assert result["verdict"] == Verdict.SUSPICIOUS.value

