"""Unit tests for BatchAnomalyProcessor and resilient flow batch execution."""

import unittest

from dark_trace.agent2.batch import BatchAnomalyProcessor, BatchProcessingResult
from dark_trace.agent2.model import IsolationForestModel
from dark_trace.agent2.trainer import ModelTrainer
from dark_trace.common.schemas import Agent2Evidence, NetworkFlow, ValidationError


class TestBatchProcessing(unittest.TestCase):
    """Test suite covering batch flow processing, partial failure handling, and result serialization."""

    def setUp(self):
        # Generate baseline flows to train real Isolation Forest
        baseline_flows = [
            NetworkFlow(
                flow_id=f"base_flow_{i}",
                timestamp="2026-10-30T17:00:00Z",
                src_ip="10.0.0.1",
                dst_ip="198.51.100.1",
                src_port=50000 + i,
                dst_port=443,
                protocol="TCP",
                features={"duration_ms": 100.0 + i * 5, "byte_rate": 2000.0 + i * 50},
            )
            for i in range(50)
        ]
        model = IsolationForestModel(contamination=0.05, random_state=42)
        trainer = ModelTrainer(model=model)
        self.trained_bundle = trainer.train(baseline_flows)
        self.processor = BatchAnomalyProcessor(trained_model=self.trained_bundle)

    def test_single_flow_processing(self):
        """Test process_flow() on an individual valid flow."""
        flow = NetworkFlow(
            flow_id="single_flow_01",
            timestamp="2026-10-30T17:00:00Z",
            src_ip="10.0.0.1",
            dst_ip="198.51.100.1",
            src_port=50001,
            dst_port=443,
            protocol="TCP",
            features={"duration_ms": 110.0, "byte_rate": 2100.0},
        )
        evidence = self.processor.process_flow(flow)
        self.assertIsInstance(evidence, Agent2Evidence)
        self.assertEqual(evidence.agent_id, "A2")
        self.assertEqual(evidence.flow_id, "single_flow_01")
        self.assertIn(evidence.anomaly_detection.anomaly_label, ["NORMAL", "ANOMALOUS"])
        self.assertTrue(0.0 <= evidence.anomaly_detection.normalized_anomaly_score <= 1.0)

    def test_empty_batch(self):
        """Test processing an empty batch returns empty summary without error."""
        result = self.processor.process_batch([])
        self.assertIsInstance(result, BatchProcessingResult)
        self.assertEqual(result.total_records, 0)
        self.assertEqual(result.valid_count, 0)
        self.assertEqual(result.invalid_count, 0)
        self.assertEqual(len(result.evidence), 0)
        self.assertEqual(len(result.errors), 0)

    def test_valid_batch_execution(self):
        """Test processing a batch of valid network flows."""
        flows = [
            NetworkFlow(
                flow_id=f"test_flow_{i}",
                timestamp="2026-10-30T17:00:00Z",
                src_ip="10.0.0.1",
                dst_ip="198.51.100.1",
                src_port=50000 + i,
                dst_port=443,
                protocol="TCP",
                features={"duration_ms": 105.0, "byte_rate": 2050.0},
            )
            for i in range(5)
        ]
        result = self.processor.process_batch(flows)
        self.assertEqual(result.total_records, 5)
        self.assertEqual(result.valid_count, 5)
        self.assertEqual(result.invalid_count, 0)
        self.assertEqual(len(result.evidence), 5)
        self.assertEqual(len(result.errors), 0)

        # Confirm flow IDs preserved in order
        for i, ev in enumerate(result.evidence):
            self.assertEqual(ev.flow_id, f"test_flow_{i}")

    def test_mixed_batch_with_invalid_records(self):
        """Test that invalid records in a batch are isolated and do not terminate valid flows."""
        mixed_batch = [
            # 0: Valid flow
            {
                "flow_id": "flow_valid_0",
                "timestamp": "2026-10-30T17:00:00Z",
                "src_ip": "10.0.0.1",
                "dst_ip": "198.51.100.1",
                "src_port": 50000,
                "dst_port": 443,
                "protocol": "TCP",
                "features": {"duration_ms": 100.0, "byte_rate": 2000.0},
            },
            # 1: Invalid IP
            {
                "flow_id": "flow_invalid_ip",
                "src_ip": "999.999.999.999",
                "dst_ip": "198.51.100.1",
                "src_port": 50000,
                "dst_port": 443,
                "protocol": "TCP",
                "features": {"duration_ms": 100.0, "byte_rate": 2000.0},
            },
            # 2: Valid flow
            {
                "flow_id": "flow_valid_1",
                "timestamp": "2026-10-30T17:00:00Z",
                "src_ip": "10.0.0.2",
                "dst_ip": "198.51.100.2",
                "src_port": 50002,
                "dst_port": 80,
                "protocol": "TCP",
                "features": {"duration_ms": 120.0, "byte_rate": 2500.0},
            },
            # 3: Out of range port
            {
                "flow_id": "flow_invalid_port",
                "src_ip": "10.0.0.1",
                "dst_ip": "198.51.100.1",
                "src_port": 999999,
                "dst_port": 443,
                "protocol": "TCP",
                "features": {"duration_ms": 100.0, "byte_rate": 2000.0},
            },
        ]

        result = self.processor.process_batch(mixed_batch)
        self.assertEqual(result.total_records, 4)
        self.assertEqual(result.valid_count, 2)
        self.assertEqual(result.invalid_count, 2)
        self.assertEqual(len(result.evidence), 2)
        self.assertEqual(len(result.errors), 2)

        # Confirm valid flow IDs
        self.assertEqual(result.evidence[0].flow_id, "flow_valid_0")
        self.assertEqual(result.evidence[1].flow_id, "flow_valid_1")

        # Confirm structured error reports
        self.assertEqual(result.errors[0]["record_index"], 1)
        self.assertIn("src_ip", result.errors[0]["error"])
        self.assertEqual(result.errors[1]["record_index"], 3)
        self.assertIn("src_port", result.errors[1]["error"])

    def test_batch_serialization(self):
        """Test BatchProcessingResult serialization to dict and JSON."""
        result = self.processor.process_batch([])
        res_dict = result.to_dict()
        self.assertIn("total_records", res_dict)
        self.assertIn("processing_time_ms", res_dict)

        json_str = result.to_json()
        self.assertIsInstance(json_str, str)


if __name__ == "__main__":
    unittest.main()
