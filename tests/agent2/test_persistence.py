"""Unit tests for artifact persistence, deserialization, and integrity validation."""

import json
import os
import shutil
import tempfile
from unittest.mock import MagicMock, patch
import unittest

from dark_trace.agent2.model import DependencyMissingError, IsolationForestModel
from dark_trace.agent2.persistence import load_trained_model, save_trained_model
from dark_trace.agent2.preprocessor import AnomalyPreprocessor
from dark_trace.agent2.trainer import TrainedAnomalyModel


class TestPersistence(unittest.TestCase):
    """Test suite covering model saving, loading, corruption detection, and joblib guards."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

        # Build mock trained model bundle
        self.preprocessor = AnomalyPreprocessor()
        self.preprocessor.feature_names_ = ["duration_ms", "packet_count"]
        self.preprocessor.imputation_values_ = {"duration_ms": 100.0, "packet_count": 5.0}
        self.preprocessor.clipping_bounds_ = {
            "duration_ms": (10.0, 1000.0),
            "packet_count": (1.0, 50.0),
        }
        self.preprocessor.is_fitted_ = True

        self.model = IsolationForestModel(n_estimators=50, random_state=42)
        self.model.sklearn_model_ = MagicMock()
        self.model.n_features_in_ = 2
        self.model.is_fitted_ = True

        self.trained_bundle = TrainedAnomalyModel(
            model=self.model,
            preprocessor=self.preprocessor,
            training_metadata={
                "sample_count": 100,
                "feature_count": 2,
                "training_score_stats": {"min_score": -0.3, "max_score": 0.1},
            },
        )

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_save_and_load_roundtrip_with_mocked_joblib(self):
        """Test complete artifact save and load roundtrip."""
        def fake_dump(obj, path, **kwargs):
            with open(path, "w") as f:
                f.write("mock_joblib_binary")

        mock_joblib = MagicMock()
        mock_joblib.dump.side_effect = fake_dump
        mock_joblib.load.return_value = self.model.sklearn_model_

        save_dir = os.path.join(self.temp_dir, "saved_agent2_model")

        with patch("dark_trace.agent2.persistence.JOBLIB_AVAILABLE", True), \
             patch("dark_trace.agent2.persistence.joblib", mock_joblib):

            # Save artifact
            saved_path = save_trained_model(self.trained_bundle, save_dir)
            self.assertTrue(os.path.exists(save_dir))
            self.assertTrue(os.path.exists(os.path.join(save_dir, "metadata.json")))
            mock_joblib.dump.assert_called_once()

            # Load artifact
            loaded_bundle = load_trained_model(save_dir)

            self.assertIsInstance(loaded_bundle, TrainedAnomalyModel)
            self.assertTrue(loaded_bundle.preprocessor.is_fitted_)
            self.assertEqual(loaded_bundle.preprocessor.feature_names_, ["duration_ms", "packet_count"])
            self.assertEqual(loaded_bundle.model.n_estimators, 50)
            self.assertEqual(loaded_bundle.model.random_state, 42)
            self.assertEqual(
                loaded_bundle.training_metadata["training_score_stats"]["min_score"],
                -0.3,
            )

    def test_load_non_existent_path(self):
        """Test that loading from a non-existent path raises FileNotFoundError."""
        with patch("dark_trace.agent2.persistence.JOBLIB_AVAILABLE", True):
            with self.assertRaises(FileNotFoundError):
                load_trained_model("/non/existent/path")

    def test_load_missing_metadata(self):
        """Test that missing metadata.json raises FileNotFoundError."""
        save_dir = os.path.join(self.temp_dir, "incomplete_model")
        os.makedirs(save_dir)
        # Create model binary only
        with open(os.path.join(save_dir, "model.joblib"), "w") as f:
            f.write("binary_placeholder")

        with patch("dark_trace.agent2.persistence.JOBLIB_AVAILABLE", True):
            with self.assertRaises(FileNotFoundError) as ctx:
                load_trained_model(save_dir)
            self.assertIn("metadata.json", str(ctx.exception))

    def test_load_corrupted_metadata(self):
        """Test that corrupted metadata JSON raises ValueError."""
        save_dir = os.path.join(self.temp_dir, "corrupt_model")
        os.makedirs(save_dir)
        with open(os.path.join(save_dir, "model.joblib"), "w") as f:
            f.write("binary_placeholder")
        with open(os.path.join(save_dir, "metadata.json"), "w") as f:
            f.write("NOT_VALID_JSON{{{")

        with patch("dark_trace.agent2.persistence.JOBLIB_AVAILABLE", True):
            with self.assertRaises(ValueError) as ctx:
                load_trained_model(save_dir)
            self.assertIn("Corrupted metadata", str(ctx.exception))

    def test_missing_joblib_raises_dependency_error(self):
        """Test that save and load raise DependencyMissingError when joblib is absent."""
        with patch("dark_trace.agent2.persistence.JOBLIB_AVAILABLE", False):
            with self.assertRaises(DependencyMissingError) as ctx:
                save_trained_model(self.trained_bundle, self.temp_dir)
            self.assertEqual(ctx.exception.package_name, "joblib")

            with self.assertRaises(DependencyMissingError) as ctx:
                load_trained_model(self.temp_dir)
            self.assertEqual(ctx.exception.package_name, "joblib")


if __name__ == "__main__":
    unittest.main()
