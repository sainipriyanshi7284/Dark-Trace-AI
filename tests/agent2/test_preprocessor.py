"""Unit tests for AnomalyPreprocessor data pipeline, imputation, and feature hygiene."""

import json
import math
import os
import tempfile
import unittest

from dark_trace.agent2.config import PreprocessingConfig
from dark_trace.agent2.preprocessor import AnomalyPreprocessor, NotFittedError
from dark_trace.common.schemas import NetworkFlow


class TestAnomalyPreprocessor(unittest.TestCase):
    """Test suite covering feature selection, imputation, infinite clipping, and serialization."""

    def setUp(self):
        # Synthetic baseline network flows
        self.train_flows = [
            NetworkFlow(
                flow_id=f"flow_{i}",
                timestamp="2026-10-30T16:00:00Z",
                src_ip="10.0.0.1",
                dst_ip="198.51.100.1",
                src_port=10000 + i,
                dst_port=80,
                protocol="TCP",
                features={
                    "duration_ms": 100.0 + i * 10,
                    "packet_count": 10 + i,
                    "byte_rate": 500.0 + i * 50,
                },
            )
            for i in range(10)
        ]

    def test_fit_learns_feature_names_and_medians(self):
        """Test that fit() extracts features, sorts them, and computes valid medians."""
        preprocessor = AnomalyPreprocessor()
        preprocessor.fit(self.train_flows)

        self.assertTrue(preprocessor.is_fitted_)
        expected_features = ["byte_rate", "duration_ms", "packet_count"]
        self.assertEqual(preprocessor.feature_names_, expected_features)

        # Median of byte_rate: 500, 550, 600, 650, 700, 750, 800, 850, 900, 950 -> median = 725.0
        self.assertAlmostEqual(preprocessor.imputation_values_["byte_rate"], 725.0)
        # Median of duration_ms: 100, 110, ..., 190 -> median = 145.0
        self.assertAlmostEqual(preprocessor.imputation_values_["duration_ms"], 145.0)
        # Median of packet_count: 10, 11, ..., 19 -> median = 14.5
        self.assertAlmostEqual(preprocessor.imputation_values_["packet_count"], 14.5)

    def test_transform_produces_consistent_2d_matrix(self):
        """Test that transform produces a matrix with matching columns and order."""
        preprocessor = AnomalyPreprocessor()
        preprocessor.fit(self.train_flows)

        matrix = preprocessor.transform(self.train_flows[:2])
        self.assertEqual(len(matrix), 2)
        self.assertEqual(len(matrix[0]), 3)
        self.assertEqual(len(matrix[1]), 3)

        # First row: byte_rate=500.0, duration_ms=100.0, packet_count=10.0
        self.assertAlmostEqual(matrix[0][0], 500.0)
        self.assertAlmostEqual(matrix[0][1], 100.0)
        self.assertAlmostEqual(matrix[0][2], 10.0)

    def test_not_fitted_error_raised(self):
        """Test that calling transform before fit raises NotFittedError."""
        preprocessor = AnomalyPreprocessor()
        with self.assertRaises(NotFittedError):
            preprocessor.transform(self.train_flows)

    def test_imputation_of_missing_and_nan_values(self):
        """Test that missing keys, None, and NaN are replaced with fitted medians."""
        preprocessor = AnomalyPreprocessor()
        preprocessor.fit(self.train_flows)

        corrupted_record = {
            "features": {
                "byte_rate": None,  # Missing -> should get 725.0
                "duration_ms": float("nan"),  # NaN -> should get 145.0
                # packet_count omitted entirely -> should get 14.5
            }
        }

        result = preprocessor.transform([corrupted_record])
        self.assertEqual(len(result), 1)
        self.assertAlmostEqual(result[0][0], 725.0)  # byte_rate
        self.assertAlmostEqual(result[0][1], 145.0)  # duration_ms
        self.assertAlmostEqual(result[0][2], 14.5)  # packet_count

    def test_infinite_values_clipping(self):
        """Test that positive and negative infinities are clipped to finite bounds."""
        preprocessor = AnomalyPreprocessor()
        preprocessor.fit(self.train_flows)

        inf_record = {
            "features": {
                "byte_rate": float("inf"),  # Should clip to max learned
                "duration_ms": float("-inf"),  # Should clip to min learned
                "packet_count": 20.0,
            }
        }

        result = preprocessor.transform([inf_record])
        # byte_rate max was 950.0
        self.assertAlmostEqual(result[0][0], 950.0)
        # duration_ms min was 100.0
        self.assertAlmostEqual(result[0][1], 100.0)
        self.assertAlmostEqual(result[0][2], 20.0)

    def test_target_leakage_and_metadata_stripping(self):
        """Test that attack labels and flow metadata are strictly excluded from features."""
        data_with_labels = [
            {
                "flow_id": "flow_x",
                "timestamp": "2026-10-30T16:00:00Z",
                "src_ip": "10.0.0.1",
                "dst_ip": "198.51.100.1",
                "src_port": 80,
                "dst_port": 443,
                "protocol": "TCP",
                "label": "DDoS",  # Prohibited label
                "attack_cat": "DoS",  # Prohibited label
                "is_attack": 1,  # Prohibited label
                "metric_a": 42.0,
                "metric_b": 100.0,
            }
        ]

        preprocessor = AnomalyPreprocessor()
        preprocessor.fit(data_with_labels)

        # Only numerical non-label, non-metadata columns should be in feature_names_
        self.assertEqual(preprocessor.feature_names_, ["metric_a", "metric_b"])
        self.assertNotIn("label", preprocessor.feature_names_)
        self.assertNotIn("attack_cat", preprocessor.feature_names_)
        self.assertNotIn("is_attack", preprocessor.feature_names_)
        self.assertNotIn("src_ip", preprocessor.feature_names_)
        self.assertNotIn("flow_id", preprocessor.feature_names_)

    def test_unexpected_columns_gracefully_dropped(self):
        """Test that extra un-fitted columns during inference are safely dropped."""
        preprocessor = AnomalyPreprocessor()
        preprocessor.fit(self.train_flows)

        test_record = {
            "features": {
                "byte_rate": 500.0,
                "duration_ms": 100.0,
                "packet_count": 10.0,
                "random_unexpected_column": 999999.0,  # Should be ignored
            }
        }

        result = preprocessor.transform([test_record])
        self.assertEqual(len(result[0]), 3)  # Exact fitted dimension

    def test_serialization_and_restoration(self):
        """Test preprocessor state save and load roundtrip."""
        preprocessor = AnomalyPreprocessor()
        preprocessor.fit(self.train_flows)

        state_dict = preprocessor.to_dict()
        restored = AnomalyPreprocessor.from_dict(state_dict)

        self.assertTrue(restored.is_fitted_)
        self.assertEqual(restored.feature_names_, preprocessor.feature_names_)
        self.assertEqual(restored.imputation_values_, preprocessor.imputation_values_)
        self.assertEqual(restored.clipping_bounds_, preprocessor.clipping_bounds_)

        # Test file serialization
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            preprocessor.save(tmp_path)
            loaded_from_file = AnomalyPreprocessor.load(tmp_path)
            self.assertEqual(loaded_from_file.feature_names_, preprocessor.feature_names_)
            self.assertEqual(
                loaded_from_file.imputation_values_, preprocessor.imputation_values_
            )
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_empty_dataset_raises_value_error(self):
        """Test that fitting on an empty dataset raises ValueError."""
        preprocessor = AnomalyPreprocessor()
        with self.assertRaises(ValueError):
            preprocessor.fit([])

    def test_missing_column_in_inference_is_imputed(self):
        """Test that a column completely missing in inference is imputed with fitted median."""
        preprocessor = AnomalyPreprocessor()
        preprocessor.fit(self.train_flows)

        # Record missing duration_ms entirely
        flow_missing_col = {
            "features": {
                "byte_rate": 600.0,
                "packet_count": 12.0,
            }
        }
        matrix = preprocessor.transform([flow_missing_col])
        self.assertEqual(len(matrix[0]), 3)
        self.assertAlmostEqual(matrix[0][0], 600.0)  # byte_rate
        self.assertAlmostEqual(matrix[0][1], 145.0)  # duration_ms (imputed median)
        self.assertAlmostEqual(matrix[0][2], 12.0)   # packet_count

    def test_feature_stats_populated(self):
        """Test that feature_stats_ dictionary contains summary statistics."""
        preprocessor = AnomalyPreprocessor()
        preprocessor.fit(self.train_flows)

        self.assertIn("byte_rate", preprocessor.feature_stats_)
        stats = preprocessor.feature_stats_["byte_rate"]
        self.assertEqual(stats["min"], 500.0)
        self.assertEqual(stats["max"], 950.0)
        self.assertEqual(stats["median"], 725.0)
        self.assertTrue(stats["std"] > 0)


if __name__ == "__main__":
    unittest.main()
