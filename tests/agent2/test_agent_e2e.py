"""End-to-end multi-agent integration test scenarios for Agent 2.

Tests the 9 mandatory cybersecurity scenarios specified in Part 3 of the Master Prompt:
1. Normal network traffic.
2. Known attack traffic.
3. Unusual traffic representing a potentially unknown/zero-day attack.
4. Suspicious public IP with available threat intelligence.
5. Suspicious traffic when TinyFish is unavailable.
6. Agent 1 and Agent 2 disagreeing (divergent evidence).
7. A batch containing valid and invalid records.
8. A flow where Agent 1 is unavailable but Agent 2 works.
9. A flow where Agent 2 is unavailable but Agent 1 works.
"""

from unittest.mock import MagicMock
import unittest

from dark_trace.agent2.agent import AnomalyAgent2
from dark_trace.agent2.agent3_contract import create_agent3_composite_handover, format_agent2_for_agent3
from dark_trace.agent2.model import IsolationForestModel
from dark_trace.agent2.threat_intel.client import TinyFishClient
from dark_trace.agent2.threat_intel.investigator import ThreatIntelInvestigator
from dark_trace.agent2.threat_intel.triggers import ThreatIntelTriggerPolicy
from dark_trace.agent2.trainer import ModelTrainer
from dark_trace.common.schemas import Agent2Evidence, NetworkFlow


class TestAgent2EndToEnd(unittest.TestCase):
    """End-to-end integration test suite covering all 9 operational scenarios."""

    def setUp(self):
        # 1. Train real Isolation Forest on 100 baseline normal flows
        baseline_flows = [
            NetworkFlow(
                flow_id=f"base_flow_{i}",
                timestamp="2026-10-30T17:00:00Z",
                src_ip="10.0.1.5",
                dst_ip="198.51.100.10",
                src_port=40000 + i,
                dst_port=443,
                protocol="TCP",
                features={
                    "flow_duration_ms": 100.0 + i * 2,
                    "total_fwd_packets": 10 + (i % 5),
                    "flow_bytes_per_sec": 3000.0 + i * 20,
                },
            )
            for i in range(100)
        ]
        model = IsolationForestModel(contamination=0.05, random_state=42)
        trainer = ModelTrainer(model=model)
        self.trained_bundle = trainer.train(baseline_flows)

        # 2. Mock HTTP responder for TinyFish Search API
        self.mock_http = MagicMock()
        self.mock_http.return_value = {
            "results": [
                {
                    "title": "Threat Advisory: Active Scanning Campaign",
                    "url": "https://threat-intel-example.org/advisories/2026-scan",
                    "snippet": "Host 93.184.216.34 observed conducting widespread port reconnaissance.",
                }
            ]
        }
        self.client = TinyFishClient(api_key="mock_key_test", http_requester=self.mock_http)
        self.policy = ThreatIntelTriggerPolicy(severity_threshold=0.75, cache_ttl_seconds=3600)
        self.investigator = ThreatIntelInvestigator(client=self.client, policy=self.policy)

        # 3. Instantiate full Agent 2
        self.agent2 = AnomalyAgent2(
            trained_model=self.trained_bundle,
            investigator=self.investigator,
        )

    def test_scenario_1_normal_network_traffic(self):
        """Scenario 1: Normal network traffic correctly classified with low anomaly severity."""
        flow = NetworkFlow(
            flow_id="scen_1_normal",
            timestamp="2026-10-30T17:00:00Z",
            src_ip="10.0.1.5",
            dst_ip="198.51.100.10",
            src_port=45000,
            dst_port=443,
            protocol="TCP",
            features={"flow_duration_ms": 110.0, "total_fwd_packets": 12, "flow_bytes_per_sec": 3100.0},
        )
        evidence = self.agent2.analyze_flow(flow)
        self.assertEqual(evidence.flow_id, "scen_1_normal")
        self.assertFalse(evidence.anomaly_detection.is_anomaly)
        self.assertEqual(evidence.anomaly_detection.anomaly_label, "NORMAL")
        self.assertLess(evidence.anomaly_detection.normalized_anomaly_score, 0.50)

    def test_scenario_2_known_attack_traffic(self):
        """Scenario 2: Known volumetric attack traffic flagged as anomalous with high severity."""
        attack_flow = NetworkFlow(
            flow_id="scen_2_ddos",
            timestamp="2026-10-30T17:05:00Z",
            src_ip="10.0.1.5",
            dst_ip="198.51.100.10",
            src_port=55555,
            dst_port=443,
            protocol="TCP",
            features={
                "flow_duration_ms": 80000.0,
                "total_fwd_packets": 100000,
                "flow_bytes_per_sec": 95000000.0,
            },
        )
        evidence = self.agent2.analyze_flow(attack_flow)
        self.assertTrue(evidence.anomaly_detection.is_anomaly)
        self.assertEqual(evidence.anomaly_detection.anomaly_label, "ANOMALOUS")
        self.assertGreaterEqual(evidence.anomaly_detection.normalized_anomaly_score, 0.80)
        self.assertTrue(len(evidence.anomaly_detection.supporting_features) > 0)

    def test_scenario_3_unusual_zero_day_traffic(self):
        """Scenario 3: Novel attack with abnormal features flagged without requiring signature."""
        novel_flow = NetworkFlow(
            flow_id="scen_3_novel",
            timestamp="2026-10-30T17:06:00Z",
            src_ip="10.0.1.5",
            dst_ip="198.51.100.10",
            src_port=55556,
            dst_port=443,
            protocol="TCP",
            features={
                "flow_duration_ms": 0.01,  # Extreme micro-burst
                "total_fwd_packets": 500,  # Highly abnormal packet density
                "flow_bytes_per_sec": 12000000.0,
            },
        )
        evidence = self.agent2.analyze_flow(novel_flow)
        self.assertTrue(evidence.anomaly_detection.is_anomaly)
        self.assertEqual(evidence.anomaly_detection.anomaly_label, "ANOMALOUS")
        self.assertGreater(evidence.anomaly_detection.normalized_anomaly_score, 0.70)

    def test_scenario_4_suspicious_public_ip_with_threat_intelligence(self):
        """Scenario 4: High anomaly score on a public IP triggers TinyFish enrichment."""
        flow = NetworkFlow(
            flow_id="scen_4_public_threat",
            timestamp="2026-10-30T17:07:00Z",
            src_ip="10.0.1.5",
            dst_ip="93.184.216.34",  # Genuine public IP
            src_port=49000,
            dst_port=80,
            protocol="TCP",
            features={
                "flow_duration_ms": 50000.0,
                "total_fwd_packets": 50000,
                "flow_bytes_per_sec": 50000000.0,
            },
        )
        evidence = self.agent2.analyze_flow(flow)
        self.assertTrue(evidence.anomaly_detection.is_anomaly)
        # Verify TinyFish investigation was executed and completed
        self.assertEqual(evidence.threat_intelligence.investigation_status, "COMPLETED")
        self.assertEqual(evidence.threat_intelligence.indicator, "93.184.216.34")
        self.assertTrue(len(evidence.threat_intelligence.findings) > 0)
        self.assertTrue(len(evidence.threat_intelligence.sources) > 0)

    def test_scenario_5_suspicious_traffic_tinyfish_unavailable(self):
        """Scenario 5: TinyFish unavailable (unconfigured key) does not crash ML detection."""
        unconfigured_agent2 = AnomalyAgent2(
            trained_model=self.trained_bundle,
            investigator=ThreatIntelInvestigator(client=TinyFishClient(api_key="")),
        )
        flow = NetworkFlow(
            flow_id="scen_5_unavail",
            timestamp="2026-10-30T17:08:00Z",
            src_ip="10.0.1.5",
            dst_ip="93.184.216.34",
            src_port=49001,
            dst_port=80,
            protocol="TCP",
            features={"flow_duration_ms": 50000.0, "total_fwd_packets": 50000, "flow_bytes_per_sec": 50000000.0},
        )
        evidence = unconfigured_agent2.analyze_flow(flow)
        # ML detection succeeded completely
        self.assertTrue(evidence.anomaly_detection.is_anomaly)
        self.assertEqual(evidence.anomaly_detection.anomaly_label, "ANOMALOUS")
        # Threat intel marked UNAVAILABLE gracefully
        self.assertEqual(evidence.threat_intelligence.investigation_status, "UNAVAILABLE")
        self.assertIn("not configured", evidence.threat_intelligence.error)

    def test_scenario_6_agent1_and_agent2_disagreeing(self):
        """Scenario 6: Agent 1 flags benign while Agent 2 flags anomaly (zero-day detection)."""
        flow = NetworkFlow(
            flow_id="scen_6_disagree",
            timestamp="2026-10-30T17:09:00Z",
            src_ip="10.0.1.5",
            dst_ip="198.51.100.10",
            src_port=50000,
            dst_port=443,
            protocol="TCP",
            features={"flow_duration_ms": 60000.0, "total_fwd_packets": 70000, "flow_bytes_per_sec": 60000000.0},
        )
        a2_evidence = self.agent2.analyze_flow(flow)
        # Agent 1 mock: falsely classifies as BENIGN (low confidence)
        a1_mock = {"agent_id": "A1", "predicted_class": "BENIGN", "confidence": 0.52}

        # Handover bundle for Agent 3
        handover = create_agent3_composite_handover(
            flow_id=flow.flow_id,
            agent2_evidence=a2_evidence,
            agent1_evidence=a1_mock,
        )
        self.assertEqual(handover["agent1_evidence"]["predicted_class"], "BENIGN")
        self.assertEqual(handover["agent2_evidence"]["anomaly_evidence"]["anomaly_label"], "ANOMALOUS")
        # Agent 3 receives independent, divergent evidence to resolve!

    def test_scenario_7_batch_with_valid_and_invalid_records(self):
        """Scenario 7: Batch containing valid and invalid records executes resiliently."""
        batch_records = [
            {"flow_id": "v1", "src_ip": "10.0.0.1", "dst_ip": "198.51.100.1", "src_port": 50000, "dst_port": 443, "protocol": "TCP", "features": {"duration_ms": 100.0}},
            {"flow_id": "inv1", "src_ip": "invalid-ip", "dst_ip": "198.51.100.1", "src_port": 50000, "dst_port": 443, "protocol": "TCP"},
            {"flow_id": "v2", "src_ip": "10.0.0.2", "dst_ip": "198.51.100.2", "src_port": 50001, "dst_port": 80, "protocol": "TCP", "features": {"duration_ms": 120.0}},
        ]
        result = self.agent2.analyze_batch(batch_records)
        self.assertEqual(result.total_records, 3)
        self.assertEqual(result.valid_count, 2)
        self.assertEqual(result.invalid_count, 1)
        self.assertEqual(len(result.evidence), 2)
        self.assertEqual(len(result.errors), 1)

    def test_scenario_8_agent1_unavailable_agent2_operates_alone(self):
        """Scenario 8: Agent 1 is offline; Agent 2 provides independent evidence to Agent 3."""
        flow = NetworkFlow(
            flow_id="scen_8_a1_offline",
            timestamp="2026-10-30T17:10:00Z",
            src_ip="10.0.1.5",
            dst_ip="198.51.100.10",
            src_port=50000,
            dst_port=443,
            protocol="TCP",
            features={"flow_duration_ms": 110.0, "total_fwd_packets": 10, "flow_bytes_per_sec": 3000.0},
        )
        a2_evidence = self.agent2.analyze_flow(flow)
        handover = create_agent3_composite_handover(
            flow_id=flow.flow_id,
            agent2_evidence=a2_evidence,
            agent1_evidence=None,  # Agent 1 offline
        )
        self.assertFalse(handover["agent1_available"])
        self.assertTrue(handover["agent2_available"])
        self.assertIsNotNone(handover["agent2_evidence"])

    def test_scenario_9_agent2_unavailable_agent1_operates_alone(self):
        """Scenario 9: Agent 2 is offline; Agent 1 provides independent evidence to Agent 3."""
        a1_mock = {"agent_id": "A1", "predicted_class": "PORT_SCAN", "confidence": 0.89}
        handover = create_agent3_composite_handover(
            flow_id="scen_9_a2_offline",
            agent2_evidence=None,  # Agent 2 offline
            agent1_evidence=a1_mock,
        )
        self.assertTrue(handover["agent1_available"])
        self.assertFalse(handover["agent2_available"])
        self.assertIsNotNone(handover["agent1_evidence"])
        self.assertIsNone(handover["agent2_evidence"])


if __name__ == "__main__":
    unittest.main()
