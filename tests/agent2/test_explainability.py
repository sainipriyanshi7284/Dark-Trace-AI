"""Unit tests for AnomalyExplainer statistical feature attribution engine."""

import unittest

from dark_trace.agent2.explainability import AnomalyExplainer, FeatureDeviation
from dark_trace.common.schemas import NetworkFlow, SupportingFeature


class TestExplainability(unittest.TestCase):
    """Test suite covering statistical deviation analysis, dispersion guards, and narratives."""

    def setUp(self):
        self.baseline_stats = {
            "flow_bytes_per_sec": {"median": 1000.0, "std": 200.0, "min": 500.0, "max": 2000.0},
            "total_fwd_packets": {"median": 10.0, "std": 2.0, "min": 5.0, "max": 20.0},
            "flow_duration_ms": {"median": 150.0, "std": 30.0, "min": 50.0, "max": 300.0},
            "constant_feature": {"median": 5.0, "std": 0.0, "min": 5.0, "max": 5.0},  # Zero variance
        }
        self.explainer = AnomalyExplainer(
            baseline_stats=self.baseline_stats,
            deviation_threshold=1.5,
            max_supporting_features=3,
        )

    def test_explain_anomalous_flow_top_deviations(self):
        """Test identification of top deviating features on an anomalous flow."""
        anomalous_flow = NetworkFlow(
            flow_id="anom_flow_01",
            timestamp="2026-10-30T17:00:00Z",
            src_ip="10.0.0.1",
            dst_ip="198.51.100.1",
            src_port=50000,
            dst_port=443,
            protocol="TCP",
            features={
                "flow_bytes_per_sec": 50000.0,  # Extreme high: (50000 - 1000)/200 = 245 std devs
                "total_fwd_packets": 100.0,     # Elevated: (100 - 10)/2 = 45 std devs
                "flow_duration_ms": 155.0,      # Normal: (155 - 150)/30 = 0.16 std dev (below 1.5)
            },
        )

        supporting = self.explainer.explain_flow(anomalous_flow)
        self.assertEqual(len(supporting), 2)  # Only 2 exceed threshold 1.5

        # Rank 1: flow_bytes_per_sec
        self.assertEqual(supporting[0].feature_name, "flow_bytes_per_sec")
        self.assertEqual(supporting[0].deviation_direction, "HIGH")
        self.assertEqual(supporting[0].observed_value, 50000.0)
        self.assertEqual(supporting[0].baseline_median, 1000.0)

        # Rank 2: total_fwd_packets
        self.assertEqual(supporting[1].feature_name, "total_fwd_packets")
        self.assertEqual(supporting[1].deviation_direction, "HIGH")
        self.assertEqual(supporting[1].observed_value, 100.0)

    def test_zero_dispersion_guard(self):
        """Test that features with zero standard deviation do not cause division by zero."""
        flow = {
            "features": {
                "constant_feature": 50.0,  # Baseline median 5.0, std 0.0
            }
        }
        supporting = self.explainer.explain_flow(flow)
        self.assertEqual(len(supporting), 1)
        self.assertEqual(supporting[0].feature_name, "constant_feature")
        self.assertEqual(supporting[0].deviation_direction, "HIGH")

    def test_normal_flow_no_significant_deviations(self):
        """Test that normal flow values within threshold produce zero supporting deviations."""
        normal_flow = {
            "features": {
                "flow_bytes_per_sec": 1050.0,  # Deviation = 50 / 200 = 0.25 (below threshold 1.5)
                "total_fwd_packets": 11.0,     # Deviation = 1 / 2 = 0.5 (below threshold 1.5)
                "flow_duration_ms": 152.0,     # Deviation = 2 / 30 = 0.06 (below threshold 1.5)
            }
        }
        supporting = self.explainer.explain_flow(normal_flow)
        self.assertEqual(len(supporting), 0)

    def test_narrative_explanation_generation(self):
        """Test human-readable narrative generation for normal and anomalous flows."""
        # Normal narrative
        norm_narrative = self.explainer.generate_narrative_explanation(
            supporting_features=[],
            is_anomaly=False,
            raw_anomaly_score=0.15,
            normalized_anomaly_score=0.25,
        )
        self.assertIn("normal statistical characteristics", norm_narrative.lower())
        self.assertIn("0.25", norm_narrative)

        # Anomalous narrative
        features = [
            SupportingFeature(
                feature_name="flow_bytes_per_sec",
                observed_value=50000.0,
                baseline_median=1000.0,
                deviation_direction="HIGH",
            )
        ]
        anom_narrative = self.explainer.generate_narrative_explanation(
            supporting_features=features,
            is_anomaly=True,
            raw_anomaly_score=-0.22,
            normalized_anomaly_score=0.92,
        )
        self.assertIn("anomalous", anom_narrative.lower())
        self.assertIn("flow_bytes_per_sec", anom_narrative)
        self.assertIn("statistical divergence, not confirmed causality", anom_narrative)


if __name__ == "__main__":
    unittest.main()
