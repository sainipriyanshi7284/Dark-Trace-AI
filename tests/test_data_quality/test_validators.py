"""Unit Tests for Data Quality Validators in CyberSentinel (Feature E)."""

import math
import os
import sys
import unittest
from datetime import datetime

# Ensure src is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src")))

from cybersentinel.data_quality.validators import (
    detect_distribution_drift,
    extract_and_validate_timestamp,
    extract_flow_id,
    validate_flow_id,
    validate_missing_and_nulls,
    validate_nan_and_inf,
    validate_timestamp,
    validate_types_and_ranges,
)


class TestValidators(unittest.TestCase):
    """Test suite for individual validation functions."""

    def test_extract_flow_id(self):
        """Test extraction of flow ID across candidate keys."""
        self.assertEqual(extract_flow_id({"flow_id": "flow_123"}), "flow_123")
        self.assertEqual(extract_flow_id({"record_id": 999}), 999)
        self.assertEqual(extract_flow_id({"Flow ID": "f_1"}), "f_1")
        self.assertEqual(extract_flow_id({}, default="fallback"), "fallback")

    def test_validate_flow_id(self):
        """Test flow ID validation and duplicate detection."""
        seen = {"flow_1", "flow_2"}
        is_dup, msg = validate_flow_id("flow_3", seen)
        self.assertFalse(is_dup)
        self.assertIsNone(msg)

        is_dup, msg = validate_flow_id("flow_1", seen)
        self.assertTrue(is_dup)
        self.assertIn("Duplicate flow_id", msg)

        is_dup, msg = validate_flow_id(None, seen)
        self.assertFalse(is_dup)
        self.assertIn("Missing or empty", msg)

        is_dup, msg = validate_flow_id("", seen)
        self.assertFalse(is_dup)
        self.assertIn("Missing or empty", msg)

    def test_validate_missing_and_nulls(self):
        """Test identification of missing or null fields."""
        record = {
            "Destination Port": 80,
            "Flow Duration": None,
            "Total Fwd Packets": "",
            "Total Backward Packets": 5
        }
        required = ["Destination Port", "Flow Duration", "NonExistentField"]
        missing, issues = validate_missing_and_nulls(record, required_fields=required)

        self.assertIn("Flow Duration", missing)
        self.assertIn("Total Fwd Packets", missing)
        self.assertIn("NonExistentField", missing)
        self.assertNotIn("Destination Port", missing)
        self.assertNotIn("Total Backward Packets", missing)
        self.assertTrue(len(issues) >= 3)

    def test_validate_nan_and_inf(self):
        """Test detection of NaN and infinite float values."""
        record = {
            "f1": 100.5,
            "f2": float("nan"),
            "f3": float("inf"),
            "f4": float("-inf"),
            "f5": 0.0
        }
        invalid, issues = validate_nan_and_inf(record)
        self.assertIn("f2", invalid)
        self.assertIn("f3", invalid)
        self.assertIn("f4", invalid)
        self.assertNotIn("f1", invalid)
        self.assertNotIn("f5", invalid)
        self.assertEqual(len(invalid), 3)
        self.assertEqual(len(issues), 3)

    def test_validate_types_and_ranges(self):
        """Test type verification and numerical boundary enforcement."""
        # Port out of bounds (> 65535) and negative duration
        record = {
            "Destination Port": 70000,
            "Flow Duration": -50,
            "Total Fwd Packets": 10,
            "CorruptStringField": "NotANumber"
        }
        expected_numeric = ["Destination Port", "Flow Duration", "Total Fwd Packets", "CorruptStringField"]
        invalid, issues = validate_types_and_ranges(
            record,
            expected_numeric_fields=expected_numeric
        )
        self.assertIn("Destination Port", invalid)
        self.assertIn("Flow Duration", invalid)
        self.assertIn("CorruptStringField", invalid)
        self.assertNotIn("Total Fwd Packets", invalid)

    def test_validate_timestamp_healthy(self):
        """Test valid timestamps across ISO, epoch, and datetime formats."""
        # ISO string
        valid, err = validate_timestamp("2026-10-30T14:30:00Z")
        self.assertTrue(valid)
        self.assertIsNone(err)

        # Datetime
        valid, err = validate_timestamp(datetime(2026, 10, 30, 12, 0, 0))
        self.assertTrue(valid)
        self.assertIsNone(err)

        # Epoch seconds
        valid, err = validate_timestamp(1761825000)
        self.assertTrue(valid)
        self.assertIsNone(err)

        # None / Not provided
        valid, err = validate_timestamp(None)
        self.assertIsNone(valid)
        self.assertIsNone(err)

    def test_validate_timestamp_invalid(self):
        """Test invalid, corrupt, or unparseable timestamps."""
        # Malformed string
        valid, err = validate_timestamp("invalid-date-string-xyz")
        self.assertFalse(valid)
        self.assertIn("Unparseable timestamp", err)

        # Negative epoch
        valid, err = validate_timestamp(-500)
        self.assertFalse(valid)
        self.assertIn("cannot be negative", err)

        # Out of bounds year
        valid, err = validate_timestamp("1900-01-01T00:00:00")
        self.assertFalse(valid)
        self.assertIn("out of", err)

    def test_extract_and_validate_timestamp_absent(self):
        """Test that schema with no timestamp returns None (not evaluated as invalid)."""
        record = {"Destination Port": 443, "Flow Duration": 1200}
        valid, err = extract_and_validate_timestamp(record)
        self.assertIsNone(valid)
        self.assertIsNone(err)

    def test_detect_distribution_drift_missing_baseline(self):
        """Test that drift is None when no baseline exists."""
        features = {"Flow Duration": [100.0, 200.0, 300.0]}
        drift, scores, drifted_cols = detect_distribution_drift(features, baseline_stats=None)
        self.assertIsNone(drift)
        self.assertIsNone(scores)
        self.assertEqual(drifted_cols, [])

    def test_detect_distribution_drift_with_baseline(self):
        """Test drift detection against provided baseline."""
        baseline = {
            "Flow Duration": {"mean": 100.0, "std": 10.0},
            "Total Fwd Packets": {"mean": 5.0, "std": 2.0}
        }
        # Normal batch
        normal_batch = {
            "Flow Duration": [98.0, 102.0, 101.0, 99.0],
            "Total Fwd Packets": [4.0, 6.0, 5.0, 5.0]
        }
        drift, scores, drifted_cols = detect_distribution_drift(normal_batch, baseline, drift_threshold=3.0)
        self.assertFalse(drift)
        self.assertEqual(drifted_cols, [])

        # Severely drifted batch (Flow Duration mean = 500.0 vs baseline 100.0)
        drifted_batch = {
            "Flow Duration": [500.0, 510.0, 490.0, 505.0],
            "Total Fwd Packets": [5.0, 5.0, 5.0, 5.0]
        }
        drift, scores, drifted_cols = detect_distribution_drift(drifted_batch, baseline, drift_threshold=3.0)
        self.assertTrue(drift)
        self.assertIn("Flow Duration", drifted_cols)
        self.assertNotIn("Total Fwd Packets", drifted_cols)


if __name__ == "__main__":
    unittest.main()

