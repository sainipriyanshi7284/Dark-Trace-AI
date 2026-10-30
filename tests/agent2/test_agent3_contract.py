"""Unit tests for Agent 3 integration contract and multi-agent independence."""

import unittest

from dark_trace.agent2.agent3_contract import create_agent3_composite_handover, format_agent2_for_agent3
from dark_trace.common.schemas import (
    Agent2Evidence,
    AnomalyDetectionResult,
    SupportingFeature,
    ThreatIntelligenceResult,
)


class TestAgent3Contract(unittest.TestCase):
    """Test suite covering Agent 3 payload structuring and independent agent evidence fusion contracts."""

    def setUp(self):
        self.evidence = Agent2Evidence(
            agent_id="A2",
            flow_id="flow_handover_01",
            timestamp="2026-10-30T17:00:00Z",
            anomaly_detection=AnomalyDetectionResult(
                is_anomaly=True,
                anomaly_label="ANOMALOUS",
                raw_anomaly_score=-0.18,
                normalized_anomaly_score=0.88,
                threshold=0.0,
                supporting_features=[
                    SupportingFeature(
                        feature_name="flow_bytes_per_sec",
                        observed_value=85000000.0,
                        baseline_median=2500.0,
                        deviation_direction="HIGH",
                    )
                ],
                model_version="iforest_v1.0.0",
                inference_latency_ms=1.2,
            ),
            threat_intelligence=ThreatIntelligenceResult(
                provider="tinyfish",
                investigation_status="NOT_REQUESTED",
            ),
            metadata={"src_ip": "10.0.1.5", "dst_ip": "198.51.100.99", "dst_port": 443, "protocol": "TCP"},
        )

    def test_format_agent2_for_agent3(self):
        """Test formatting Agent2Evidence into standard Agent 3 consumption payload."""
        payload = format_agent2_for_agent3(self.evidence)
        self.assertEqual(payload["agent_id"], "A2")
        self.assertEqual(payload["flow_id"], "flow_handover_01")
        self.assertIn("anomaly_evidence", payload)
        self.assertTrue(payload["anomaly_evidence"]["is_anomaly"])
        self.assertEqual(payload["anomaly_evidence"]["anomaly_label"], "ANOMALOUS")
        self.assertEqual(payload["anomaly_evidence"]["anomaly_score"], 0.88)
        self.assertEqual(payload["anomaly_evidence"]["raw_score"], -0.18)
        self.assertEqual(len(payload["anomaly_evidence"]["supporting_features"]), 1)
        self.assertEqual(payload["routing_metadata"]["src_ip"], "10.0.1.5")

    def test_composite_handover_both_agents_available(self):
        """Test composite evidence handover when both Agent 1 and Agent 2 produce evidence."""
        agent1_mock = {
            "agent_id": "A1",
            "predicted_class": "SYN_FLOOD",
            "confidence": 0.94,
        }
        bundle = create_agent3_composite_handover(
            flow_id="flow_handover_01",
            agent2_evidence=self.evidence,
            agent1_evidence=agent1_mock,
        )
        self.assertTrue(bundle["agent1_available"])
        self.assertTrue(bundle["agent2_available"])
        self.assertEqual(bundle["agent1_evidence"]["predicted_class"], "SYN_FLOOD")
        self.assertEqual(bundle["agent2_evidence"]["anomaly_evidence"]["anomaly_label"], "ANOMALOUS")

    def test_composite_handover_agent1_unavailable(self):
        """Test composite evidence handover when Agent 1 is unavailable (Agent 2 operates alone)."""
        bundle = create_agent3_composite_handover(
            flow_id="flow_handover_01",
            agent2_evidence=self.evidence,
            agent1_evidence=None,
        )
        self.assertFalse(bundle["agent1_available"])
        self.assertTrue(bundle["agent2_available"])
        self.assertIsNone(bundle["agent1_evidence"])
        self.assertIsNotNone(bundle["agent2_evidence"])
        self.assertEqual(bundle["agent2_evidence"]["flow_id"], "flow_handover_01")

    def test_composite_handover_agent2_unavailable(self):
        """Test composite evidence handover when Agent 2 is unavailable (Agent 1 operates alone)."""
        agent1_mock = {
            "agent_id": "A1",
            "predicted_class": "BENIGN",
            "confidence": 0.98,
        }
        bundle = create_agent3_composite_handover(
            flow_id="flow_handover_02",
            agent2_evidence=None,
            agent1_evidence=agent1_mock,
        )
        self.assertTrue(bundle["agent1_available"])
        self.assertFalse(bundle["agent2_available"])
        self.assertIsNotNone(bundle["agent1_evidence"])
        self.assertIsNone(bundle["agent2_evidence"])


if __name__ == "__main__":
    unittest.main()
