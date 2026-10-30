"""Unit tests for NetworkFlow ingestion schema and Agent 2 evidence output schema."""

import json
import unittest

from dark_trace.common.schemas import (
    Agent2Evidence,
    AnomalyDetectionResult,
    NetworkFlow,
    SupportingFeature,
    ThreatIntelligenceResult,
    ValidationError,
)


class TestSchemas(unittest.TestCase):
    """Test suite covering data validation, schema instantiation, and JSON serialization."""

    def setUp(self):
        self.valid_flow_dict = {
            "flow_id": "flow_test_001",
            "timestamp": "2026-10-30T16:00:00Z",
            "src_ip": "10.0.0.1",
            "dst_ip": "198.51.100.5",
            "src_port": 49152,
            "dst_port": 443,
            "protocol": "TCP",
            "features": {
                "flow_duration_ms": 120.5,
                "total_fwd_packets": 10,
                "total_bwd_packets": 8,
                "flow_bytes_per_sec": 4500.0,
            },
            "force_threat_intel": False,
            "metadata": {"sensor": "edge_01"},
        }

    def test_valid_network_flow_instantiation(self):
        """Test instantiation of a valid NetworkFlow object."""
        flow = NetworkFlow.from_dict(self.valid_flow_dict)
        self.assertEqual(flow.flow_id, "flow_test_001")
        self.assertEqual(flow.src_ip, "10.0.0.1")
        self.assertEqual(flow.dst_ip, "198.51.100.5")
        self.assertEqual(flow.src_port, 49152)
        self.assertEqual(flow.dst_port, 443)
        self.assertEqual(flow.protocol, "TCP")
        self.assertEqual(flow.features["flow_duration_ms"], 120.5)
        self.assertEqual(flow.metadata["sensor"], "edge_01")

    def test_network_flow_json_roundtrip(self):
        """Test JSON serialization and deserialization of NetworkFlow."""
        flow = NetworkFlow.from_dict(self.valid_flow_dict)
        json_str = flow.to_json()
        restored = NetworkFlow.from_json(json_str)
        self.assertEqual(flow.flow_id, restored.flow_id)
        self.assertEqual(flow.src_ip, restored.src_ip)
        self.assertEqual(flow.dst_ip, restored.dst_ip)
        self.assertEqual(flow.features, restored.features)

    def test_missing_required_fields(self):
        """Test validation error when required fields are missing."""
        required_keys = ["flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol"]
        for key in required_keys:
            data = dict(self.valid_flow_dict)
            del data[key]
            with self.assertRaises(ValidationError) as ctx:
                NetworkFlow.from_dict(data)
            self.assertEqual(ctx.exception.field_name, key)

    def test_invalid_ip_addresses(self):
        """Test rejection of invalid IP formats."""
        invalid_ips = ["999.999.999.999", "10.0.0", "not_an_ip", "", None]
        for bad_ip in invalid_ips:
            # Source IP
            data = dict(self.valid_flow_dict)
            data["src_ip"] = bad_ip
            with self.assertRaises(ValidationError) as ctx:
                NetworkFlow.from_dict(data)
            self.assertEqual(ctx.exception.field_name, "src_ip")

            # Destination IP
            data = dict(self.valid_flow_dict)
            data["dst_ip"] = bad_ip
            with self.assertRaises(ValidationError) as ctx:
                NetworkFlow.from_dict(data)
            self.assertEqual(ctx.exception.field_name, "dst_ip")

    def test_invalid_ports(self):
        """Test rejection of out-of-range or non-numeric port numbers."""
        invalid_ports = [-1, 65536, 100000, "not_a_port", None]
        for bad_port in invalid_ports:
            data = dict(self.valid_flow_dict)
            data["src_port"] = bad_port
            with self.assertRaises(ValidationError) as ctx:
                NetworkFlow.from_dict(data)
            self.assertEqual(ctx.exception.field_name, "src_port")

    def test_invalid_features(self):
        """Test feature validation handling non-numeric values."""
        data = dict(self.valid_flow_dict)
        data["features"] = {"valid_num": 10.5, "invalid_str": "string_cannot_be_float"}
        with self.assertRaises(ValidationError) as ctx:
            NetworkFlow.from_dict(data)
        self.assertEqual(ctx.exception.field_name, "features")

    def test_agent2_evidence_serialization(self):
        """Test Agent2Evidence schema instantiation, validation, and JSON export."""
        ad_result = AnomalyDetectionResult(
            is_anomaly=True,
            anomaly_label="ANOMALOUS",
            raw_anomaly_score=-0.25,
            normalized_anomaly_score=0.92,
            threshold=0.0,
            supporting_features=[
                SupportingFeature(
                    feature_name="flow_bytes_per_sec",
                    observed_value=999999.0,
                    baseline_median=1200.0,
                    deviation_direction="HIGH",
                )
            ],
            model_version="iforest_v1.0.0",
            inference_latency_ms=1.5,
        )

        ti_result = ThreatIntelligenceResult(
            provider="tinyfish",
            investigation_status="COMPLETED",
            indicator="198.51.100.5",
            indicator_type="PUBLIC_IP",
            findings=["Observed in brute-force scanning activity"],
            sources=[{"title": "Advisory 101", "url": "https://example.com/advisory"}],
        )

        evidence = Agent2Evidence(
            flow_id="flow_test_001",
            timestamp="2026-10-30T16:00:00Z",
            anomaly_detection=ad_result,
            threat_intelligence=ti_result,
            metadata={"sensor": "edge_01"},
        )

        # Test dictionary export
        ev_dict = evidence.to_dict()
        self.assertEqual(ev_dict["agent_id"], "A2")
        self.assertEqual(ev_dict["flow_id"], "flow_test_001")
        self.assertTrue(ev_dict["anomaly_detection"]["is_anomaly"])
        self.assertEqual(ev_dict["anomaly_detection"]["normalized_anomaly_score"], 0.92)
        self.assertEqual(
            ev_dict["anomaly_detection"]["supporting_features"][0]["feature_name"],
            "flow_bytes_per_sec",
        )
        self.assertEqual(ev_dict["threat_intelligence"]["indicator"], "198.51.100.5")

        # Test JSON roundtrip
        json_str = evidence.to_json()
        restored = Agent2Evidence.from_json(json_str)
        self.assertEqual(restored.flow_id, "flow_test_001")
        self.assertEqual(restored.anomaly_detection.is_anomaly, True)
        self.assertEqual(restored.anomaly_detection.raw_anomaly_score, -0.25)
        self.assertEqual(restored.threat_intelligence.investigation_status, "COMPLETED")


if __name__ == "__main__":
    unittest.main()

