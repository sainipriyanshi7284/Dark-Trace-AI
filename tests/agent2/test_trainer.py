"""Unit tests for ModelTrainer and TrainedAnomalyModel pipeline execution."""

from unittest.mock import MagicMock, patch
import unittest

from dark_trace.agent2.config import ModelConfig
from dark_trace.agent2.model import IsolationForestModel
from dark_trace.agent2.preprocessor import AnomalyPreprocessor
from dark_trace.agent2.trainer import ModelTrainer, TrainedAnomalyModel
from dark_trace.common.schemas import NetworkFlow


class TestModelTrainer(unittest.TestCase):
    """Test suite covering pipeline training, baseline score calibration, and record scoring."""

    def setUp(self):
        self.sample_flows = [
            NetworkFlow(
                flow_id=f"flow_{i}",
                timestamp="2026-10-30T16:00:00Z",
                src_ip="10.0.0.1",
                dst_ip="198.51.100.1",
                src_port=50000 + i,
                dst_port=443,
                protocol="TCP",
                features={
                    "duration_ms": 100.0 + i * 10,
                    "byte_rate": 1000.0 + i * 100,
                    "packet_count": 5 + i,
                },
            )
            for i in range(20)
        ]

    def test_train_pipeline_with_mocked_sklearn(self):
        """Test ModelTrainer.train() execution, preprocessor fitting, and baseline score capture."""
        mock_sklearn_instance = MagicMock()
        # Mock 20 decision scores matching the 20 samples
        mock_scores = [-0.2 + (i * 0.02) for i in range(20)]
        mock_sklearn_instance.decision_function.return_value = mock_scores

        mock_sklearn_cls = MagicMock(return_value=mock_sklearn_instance)

        preprocessor = AnomalyPreprocessor()
        model = IsolationForestModel(n_estimators=25, random_state=42)
        trainer = ModelTrainer(preprocessor=preprocessor, model=model)

        with patch("dark_trace.agent2.model.SKLEARN_AVAILABLE", True), \
             patch("dark_trace.agent2.model.SklearnIsolationForest", mock_sklearn_cls):

            trained_artifact = trainer.train(self.sample_flows)

            self.assertIsInstance(trained_artifact, TrainedAnomalyModel)
            self.assertTrue(trained_artifact.preprocessor.is_fitted_)
            self.assertTrue(trained_artifact.model.is_fitted)

            # Verify training metadata
            meta = trained_artifact.training_metadata
            self.assertEqual(meta["sample_count"], 20)
            self.assertEqual(meta["feature_count"], 3)
            self.assertEqual(meta["feature_names"], ["byte_rate", "duration_ms", "packet_count"])

            stats = meta["training_score_stats"]
            self.assertIn("min_score", stats)
            self.assertIn("max_score", stats)
            self.assertIn("median_score", stats)
            self.assertIn("p05_score", stats)
            self.assertIn("p95_score", stats)

    def test_score_record_and_score_batch(self):
        """Test scoring of single records and batches via TrainedAnomalyModel."""
        mock_sklearn_instance = MagicMock()
        # Realistic training score range from -0.3 to +0.2 across 10 samples
        train_scores = [-0.3 + (i * 0.05) for i in range(10)]
        mock_sklearn_instance.decision_function.return_value = train_scores
        mock_sklearn_instance.predict.return_value = [1] * 10
        mock_sklearn_cls = MagicMock(return_value=mock_sklearn_instance)

        preprocessor = AnomalyPreprocessor()
        model = IsolationForestModel()
        trainer = ModelTrainer(preprocessor=preprocessor, model=model)

        with patch("dark_trace.agent2.model.SKLEARN_AVAILABLE", True), \
             patch("dark_trace.agent2.model.SklearnIsolationForest", mock_sklearn_cls):

            trained_artifact = trainer.train(self.sample_flows[:10])

            # Now set inference return values
            mock_sklearn_instance.predict.return_value = [-1]
            mock_sklearn_instance.decision_function.return_value = [-0.25]

            # Score single record
            result = trained_artifact.score_record(self.sample_flows[0])
            self.assertTrue(result["is_anomaly"])
            self.assertEqual(result["anomaly_label"], "ANOMALOUS")
            self.assertAlmostEqual(result["raw_anomaly_score"], -0.25)
            self.assertGreater(result["normalized_anomaly_score"], 0.5)

            # Score batch
            mock_sklearn_instance.predict.return_value = [1, -1]
            mock_sklearn_instance.decision_function.return_value = [0.15, -0.25]

            batch_results = trained_artifact.score_batch(self.sample_flows[:2])
            self.assertEqual(len(batch_results), 2)
            self.assertFalse(batch_results[0]["is_anomaly"])
            self.assertEqual(batch_results[0]["anomaly_label"], "NORMAL")
            self.assertTrue(batch_results[1]["is_anomaly"])
            self.assertEqual(batch_results[1]["anomaly_label"], "ANOMALOUS")

    def test_train_empty_dataset_raises_value_error(self):
        """Test that passing an empty dataset to ModelTrainer.train raises ValueError."""
        trainer = ModelTrainer()
        with self.assertRaises(ValueError):
            trainer.train([])


if __name__ == "__main__":
    unittest.main()
