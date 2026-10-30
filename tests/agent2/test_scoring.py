"""Unit tests for anomaly score normalization, scaling, and label interpretation."""

import unittest

from dark_trace.agent2.scoring import compute_normalized_anomaly_score, interpret_anomaly_label


class TestScoring(unittest.TestCase):
    """Test suite covering Isolation Forest decision function calibration and score semantics."""

    def test_score_monotonicity(self):
        """Test that lower raw scores (more anomalous) produce higher normalized scores."""
        raw_scores = [-0.4, -0.2, -0.05, 0.0, 0.1, 0.3]
        norm_scores = [compute_normalized_anomaly_score(s) for s in raw_scores]

        # Monotonically non-increasing: norm_scores[i] >= norm_scores[i+1]
        for i in range(len(norm_scores) - 1):
            self.assertGreaterEqual(
                norm_scores[i],
                norm_scores[i + 1],
                f"Monotonicity failed at index {i}: {norm_scores[i]} < {norm_scores[i+1]}",
            )

    def test_score_bounded_between_zero_and_one(self):
        """Test that normalized scores never exceed [0.0, 1.0], even on extreme inputs."""
        extreme_scores = [-1000.0, -50.0, -0.5, 0.0, 0.5, 100.0, 9999.0]
        for s in extreme_scores:
            norm = compute_normalized_anomaly_score(s)
            self.assertGreaterEqual(norm, 0.0)
            self.assertLessEqual(norm, 1.0)

    def test_threshold_boundary_semantics(self):
        """Test score behavior around the 0.0 decision threshold."""
        # Exact threshold is at 0.5 severity
        norm_at_threshold = compute_normalized_anomaly_score(0.0, raw_threshold=0.0)
        self.assertAlmostEqual(norm_at_threshold, 0.5)

        # Negative raw score (anomalous) must be >= 0.5
        norm_negative = compute_normalized_anomaly_score(-0.15, raw_threshold=0.0)
        self.assertGreater(norm_negative, 0.5)

        # Positive raw score (inlier) must be < 0.5
        norm_positive = compute_normalized_anomaly_score(0.15, raw_threshold=0.0)
        self.assertLess(norm_positive, 0.5)

    def test_calibration_with_training_stats(self):
        """Test normalized scoring using training baseline score statistics."""
        training_stats = {
            "min_score": -0.4,
            "max_score": 0.2,
            "median_score": 0.0,
        }

        # Lowest score in training -> 1.0 severity
        norm_min = compute_normalized_anomaly_score(-0.4, training_score_stats=training_stats)
        self.assertAlmostEqual(norm_min, 1.0)

        # Highest score in training -> 0.0 severity
        norm_max = compute_normalized_anomaly_score(0.2, training_score_stats=training_stats)
        self.assertAlmostEqual(norm_max, 0.0)

        # Beyond minimum (more anomalous than anything in training) -> clamped to 1.0
        norm_extreme = compute_normalized_anomaly_score(-1.0, training_score_stats=training_stats)
        self.assertEqual(norm_extreme, 1.0)

    def test_interpret_anomaly_label(self):
        """Test categorical label assignment."""
        self.assertEqual(interpret_anomaly_label(True), "ANOMALOUS")
        self.assertEqual(interpret_anomaly_label(False), "NORMAL")


if __name__ == "__main__":
    unittest.main()

