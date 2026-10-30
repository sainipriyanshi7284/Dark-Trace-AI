"""Unit and Integration Tests for DataQualityMonitor in CyberSentinel (Feature E)."""

import math
import os
import sys
import unittest

# Ensure src is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src")))

import pandas as pd
import numpy as np

from cybersentinel.data_quality import (
    DataQualityMonitor,
    FlowQualityReport,
    BatchQualityReport,
    QualityRecommendation,
    QualityStatus,
)


class TestDataQualityMonitor(unittest.TestCase):
    """Comprehensive test suite for DataQualityMonitor."""

    def setUp(self):
        """Set up standard test fixtures."""
        self.standard_features = [
            "Destination Port",
            "Flow Duration",
            "Total Fwd Packets",
            "Total Backward Packets",
            "Total Length of Fwd Packets",
            "Total Length of Bwd Packets"
        ]
        self.monitor = DataQualityMonitor(expected_features=self.standard_features)

        self.healthy_flow = {
            "record_id": 1001,
            "Destination Port": 443,
            "Flow Duration": 1500,
            "Total Fwd Packets": 10,
            "Total Backward Packets": 12,
            "Total Length of Fwd Packets": 500,
            "Total Length of Bwd Packets": 1200,
            "timestamp": "2026-10-30T12:00:00Z"
        }

    # 1. Healthy Input Test
    def test_healthy_flow(self):
        """Test that pristine input receives 100.0 score and HEALTHY status."""
        data, report, is_safe = self.monitor.validate_flow(self.healthy_flow)

        self.assertTrue(is_safe)
        self.assertEqual(report.quality_status, QualityStatus.HEALTHY.value)
        self.assertEqual(report.quality_score, 100.0)
        self.assertEqual(len(report.issues), 0)
        self.assertEqual(len(report.missing_fields), 0)
        self.assertEqual(len(report.invalid_fields), 0)
        self.assertFalse(report.duplicate_flow_id)
        self.assertTrue(report.timestamp_valid)
        self.assertIsNone(report.drift_detected)
        self.assertEqual(report.recommendation, QualityRecommendation.ALLOW_PASS.value)
        # Ensure metadata is preserved
        self.assertEqual(data["record_id"], 1001)

    # 2. Missing Values Test
    def test_missing_values(self):
        """Test identification of missing and null fields."""
        flow_missing = dict(self.healthy_flow)
        flow_missing["record_id"] = 1002
        flow_missing["Flow Duration"] = None
        del flow_missing["Total Fwd Packets"]  # completely absent required feature

        data, report, is_safe = self.monitor.validate_flow(flow_missing)

        self.assertIn("Flow Duration", report.missing_fields)
        self.assertIn("Total Fwd Packets", report.missing_fields)
        self.assertLess(report.quality_score, 100.0)
        self.assertTrue(len(report.issues) >= 2)

    # 3. NaN and Infinity Test & No Silent Zero Replacement
    def test_nan_and_infinity_preservation(self):
        """Test detection of NaN/Inf and ensure values are NEVER replaced with zero."""
        flow_nan = dict(self.healthy_flow)
        flow_nan["record_id"] = 1003
        flow_nan["Flow Duration"] = float("nan")
        flow_nan["Total Fwd Packets"] = float("inf")

        data, report, is_safe = self.monitor.validate_flow(flow_nan)

        self.assertFalse(is_safe)
        self.assertIn("Flow Duration", report.invalid_fields)
        self.assertIn("Total Fwd Packets", report.invalid_fields)
        self.assertLess(report.quality_score, 100.0)

        # CRUCIAL RULE: Never silently replace invalid values with zero
        self.assertTrue(math.isnan(data["Flow Duration"]))
        self.assertTrue(math.isinf(data["Total Fwd Packets"]))
        self.assertNotEqual(data["Flow Duration"], 0)
        self.assertNotEqual(data["Total Fwd Packets"], 0)

    # 4. Duplicate Flow IDs Test
    def test_duplicate_flow_ids_in_batch(self):
        """Test duplicate detection within a single batch."""
        batch = [
            dict(self.healthy_flow, record_id=2001),
            dict(self.healthy_flow, record_id=2002),
            dict(self.healthy_flow, record_id=2001),  # Duplicate within batch
        ]
        safe_flows, batch_report, reports = self.monitor.validate_batch(batch)

        self.assertEqual(batch_report.total_flows, 3)
        self.assertEqual(batch_report.duplicate_count, 1)
        self.assertTrue(reports[2].duplicate_flow_id)
        self.assertFalse(reports[2].is_safe_downstream)
        # First two should be safe, third dropped
        self.assertEqual(len(safe_flows), 2)

    def test_duplicate_flow_ids_across_history(self):
        """Test duplicate detection across consecutive stream batches."""
        monitor = DataQualityMonitor(track_history=True)
        flow1 = dict(self.healthy_flow, record_id="STREAM_001")
        _, rep1, safe1 = monitor.validate_flow(flow1)
        self.assertTrue(safe1)
        self.assertFalse(rep1.duplicate_flow_id)

        # Later arrival of identical ID
        flow2 = dict(self.healthy_flow, record_id="STREAM_001")
        _, rep2, safe2 = monitor.validate_flow(flow2)
        self.assertFalse(safe2)
        self.assertTrue(rep2.duplicate_flow_id)
        self.assertIn("Duplicate flow_id", rep2.issues[0])

    # 5. Invalid Timestamps Test
    def test_invalid_timestamps(self):
        """Test detection and handling of corrupted timestamps."""
        flow_bad_ts = dict(self.healthy_flow, record_id=3001, timestamp="garbage-not-a-date")
        _, report, _ = self.monitor.validate_flow(flow_bad_ts)

        self.assertFalse(report.timestamp_valid)
        self.assertLess(report.quality_score, 100.0)
        self.assertTrue(any("timestamp" in issue.lower() for issue in report.issues))

    def test_missing_timestamp_in_schema(self):
        """Test that schemas without timestamp are not marked as invalid."""
        flow_no_ts = dict(self.healthy_flow, record_id=3002)
        del flow_no_ts["timestamp"]
        _, report, is_safe = self.monitor.validate_flow(flow_no_ts)

        self.assertTrue(is_safe)
        self.assertIsNone(report.timestamp_valid)  # Not provided, not penalized

    # 6. Invalid Data Types & Domain Range Test
    def test_invalid_types_and_domain_ranges(self):
        """Test type errors and boundary constraint violations."""
        flow_invalid = dict(
            self.healthy_flow,
            record_id=4001,
            **{"Destination Port": -1, "Flow Duration": -100}  # Negative port and duration
        )
        _, report, is_safe = self.monitor.validate_flow(flow_invalid)

        self.assertIn("Destination Port", report.invalid_fields)
        self.assertIn("Flow Duration", report.invalid_fields)
        self.assertFalse(is_safe)
        self.assertLess(report.quality_score, 85.0)

    # 7. Missing Optional Baseline Test
    def test_missing_optional_baseline(self):
        """Test that drift is None when no reference baseline is supplied."""
        monitor_no_baseline = DataQualityMonitor(baseline_stats=None)
        batch = [dict(self.healthy_flow, record_id=i) for i in range(5001, 5010)]

        _, batch_report, reports = monitor_no_baseline.validate_batch(batch)
        self.assertIsNone(batch_report.drift_detected)
        for r in reports:
            self.assertIsNone(r.drift_detected)

    # 8. Drift Detection With Supplied Baseline Test
    def test_drift_detection_with_supplied_baseline(self):
        """Test drift detection when valid reference baseline is provided."""
        baseline = {
            "Flow Duration": {"mean": 1000.0, "std": 100.0},
            "Total Fwd Packets": {"mean": 10.0, "std": 2.0}
        }
        monitor_with_baseline = DataQualityMonitor(
            baseline_stats=baseline,
            drift_threshold=3.0,
            track_history=False
        )

        # Drifted batch: Flow Duration mean is 9000.0 (80 std dev deviation)
        drifted_batch = []
        for i in range(10):
            row = dict(self.healthy_flow, record_id=6000 + i)
            row["Flow Duration"] = 9000 + (i * 10)
            drifted_batch.append(row)

        _, batch_report, reports = monitor_with_baseline.validate_batch(drifted_batch)
        self.assertTrue(batch_report.drift_detected)
        self.assertIsNotNone(batch_report.drift_details)
        self.assertIn("Flow Duration", batch_report.drift_details["drifted_features"])
        self.assertTrue(reports[0].drift_detected)

    # 9. Critical Quality Issues Test
    def test_critical_quality_issues(self):
        """Test that severely degraded data triggers CRITICAL status and DROP recommendation."""
        severe_flow = {
            "record_id": 7001,
            "Destination Port": -99,
            "Flow Duration": float("nan"),
            "Total Fwd Packets": float("inf"),
            "timestamp": "invalid_date"
        }
        _, report, is_safe = self.monitor.validate_flow(severe_flow)

        self.assertFalse(is_safe)
        self.assertEqual(report.quality_status, QualityStatus.CRITICAL.value)
        self.assertEqual(report.recommendation, QualityRecommendation.DROP_DO_NOT_PROCESS.value)
        self.assertLess(report.quality_score, 50.0)

    # 10. Empty Input and Malformed Input Test
    def test_empty_and_malformed_inputs(self):
        """Test graceful handling of empty, None, and unexpected types."""
        # None flow
        _, rep_none, safe_none = self.monitor.validate_flow(None)
        self.assertFalse(safe_none)
        self.assertEqual(rep_none.quality_status, QualityStatus.CRITICAL.value)

        # Empty dict flow
        _, rep_empty, safe_empty = self.monitor.validate_flow({})
        self.assertFalse(safe_empty)
        self.assertEqual(rep_empty.quality_status, QualityStatus.CRITICAL.value)

        # Malformed non-dict type
        _, rep_str, safe_str = self.monitor.validate_flow("not_a_valid_flow")
        self.assertFalse(safe_str)
        self.assertEqual(rep_str.quality_status, QualityStatus.CRITICAL.value)

        # Empty batch list
        safe_list, batch_list_rep, ind_list = self.monitor.validate_batch([])
        self.assertEqual(len(safe_list), 0)
        self.assertEqual(batch_list_rep.total_flows, 0)

        # None batch
        safe_none_batch, batch_none_rep, _ = self.monitor.validate_batch(None)
        self.assertEqual(batch_none_rep.total_flows, 0)

        # Empty DataFrame
        df_empty = pd.DataFrame()
        safe_df, batch_df_rep, _ = self.monitor.validate_batch(df_empty)
        self.assertTrue(safe_df.empty)
        self.assertEqual(batch_df_rep.total_flows, 0)

    # 11. DataFrame Batch Downstream Integration Test
    def test_dataframe_batch_downstream(self):
        """Test processing pandas DataFrame batch with mixed health."""
        df = pd.DataFrame([
            dict(self.healthy_flow, record_id=8001),  # Healthy
            dict(self.healthy_flow, record_id=8002, **{"Destination Port": -5}),  # Invalid port
            dict(self.healthy_flow, record_id=8003),  # Healthy
            dict(self.healthy_flow, record_id=8001),  # Duplicate ID
        ])

        safe_df, batch_rep, reports = self.monitor.validate_batch(df)

        self.assertIsInstance(safe_df, pd.DataFrame)
        self.assertEqual(batch_rep.total_flows, 4)
        self.assertEqual(batch_rep.duplicate_count, 1)
        # Safe rows should be 8001 (first occurrence) and 8003
        self.assertEqual(len(safe_df), 2)
        self.assertListEqual(list(safe_df["record_id"]), [8001, 8003])


if __name__ == "__main__":
    unittest.main()

