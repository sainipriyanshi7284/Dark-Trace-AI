"""Unit tests verifying agents and schemas module imports and exports."""

from agents.agent3 import (
    Agent1ThreatPrediction,
    Agent2AnomalyAssessment,
    Agent3FusionInput,
    Agent3Skeleton,
    validate_agent1_output,
    validate_agent2_output,
    validate_fusion_input,
)
from schemas import (
    A1DetectionResult,
    A1ThreatClass,
    A2DetectionResult,
    Agent1ThreatPrediction as SchemaA1Prediction,
    Agent2AnomalyAssessment as SchemaA2Assessment,
    Agent3FusionInput as SchemaFusionInput,
    Agent3Input,
    Agent3Output,
    AgentStatus,
    FlowContext,
    FusionStatus,
    RecommendedAction,
    Verdict,
    validate_agent1_output as schema_validate_a1,
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


def test_block2_schema_and_agent_exports():
    """Verify that Block 2 typed schemas and validators resolve from schemas and agents packages."""
    flow = FlowContext(
        flow_id="test-pkg-002",
        timestamp="2026-10-30T12:05:00Z",
        src_ip="10.0.0.5",
        src_port=44321,
        dst_ip="10.0.0.10",
        dst_port=22,
        protocol="TCP",
    )
    a1 = SchemaA1Prediction(predicted_class=A1ThreatClass.BRUTE_FORCE.value, confidence=0.89)
    a2 = SchemaA2Assessment(anomaly_score=1.8, anomaly_detected=True, evidence=["failed auth spike"])
    fusion_in = SchemaFusionInput(flow_context=flow, a1_prediction=a1, a2_assessment=a2)

    val_res = validate_fusion_input(fusion_in)
    assert val_res.is_valid is True
    assert val_res.details["fusion_mode"] == "DUAL_AGENT"

    # Verify skeleton process works with Agent3FusionInput
    agent = Agent3Skeleton()
    output = agent.process(fusion_in)
    assert isinstance(output, Agent3Output)
    assert output.flow_id == "test-pkg-002"
    assert "agent_1" in output.contributing_agents
    assert "agent_2" in output.contributing_agents
