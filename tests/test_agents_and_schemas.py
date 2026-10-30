"""Unit tests verifying agents and schemas module imports and exports."""

from agents.agent3 import Agent3Skeleton
from schemas import (
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


def test_schema_and_agent_package_exports():
    """Verify that agents and schemas top-level packages resolve correctly."""
    flow = FlowContext(
        flow_id="test-pkg-001",
        timestamp="2026-10-30T12:00:00Z",
        src_ip="10.0.0.1",
        src_port=1234,
        dst_ip="10.0.0.2",
        dst_port=80,
        protocol="TCP",
    )
    a1 = A1DetectionResult(agent_id="agent_1", threat_detected=False, confidence=0.1)
    a2 = A2DetectionResult(agent_id="agent_2", anomaly_detected=False, anomaly_score=0.1)
    inp = Agent3Input(flow_context=flow, a1_result=a1, a2_result=a2)

    agent = Agent3Skeleton()
    output = agent.process(inp)

    assert isinstance(output, Agent3Output)
    assert output.verdict == Verdict.BENIGN
    assert output.recommended_policy_action == RecommendedAction.LOG_ALLOW

