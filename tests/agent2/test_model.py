"""Unit tests for IsolationForestModel wrapper, input validation, and hyperparameter controls."""

from unittest.mock import MagicMock, patch
import unittest

from dark_trace.agent2.config import ModelConfig
from dark_trace.agent2.model import (
    DependencyMissingError,
    IsolationForestModel,
    _validate_numerical_matrix,
)
from dark_trace.agent2.preprocessor import NotFittedError


class TestIsolationForestModel(unittest.TestCase):
    """Test suite covering hyperparameter checks, input validation, and fitted state guards."""

    def test_default_initialization(self):
        """Test model creation with default configuration."""
        model = IsolationForestModel()
        self.assertEqual(model.n_estimators, 100)
        self.assertEqual(model.contamination, "auto")
        self.assertEqual(model.random_state, 42)
        self.assertFalse(model.is_fitted)
        self.assertEqual(model.model_version, "iforest_v1.0.0")

    def test_custom_hyperparameters(self):
        """Test model initialization with custom parameters."""
        config = ModelConfig(
            n_estimators=50,
            contamination=0.05,
            random_state=123,
            raw_decision_threshold=-0.05,
            model_version="iforest_v2.0.0",
        )
        model = IsolationForestModel(config=config)
        self.assertEqual(model.n_estimators, 50)
        self.assertEqual(model.contamination, 0.05)
        self.assertEqual(model.random_state, 123)
        self.assertEqual(model.raw_decision_threshold, -0.05)
        self.assertEqual(model.model_version, "iforest_v2.0.0")

    def test_invalid_hyperparameters(self):
        """Test that invalid hyperparameters raise ValueError."""
        with self.assertRaises(ValueError):
            IsolationForestModel(n_estimators=0)

        with self.assertRaises(ValueError):
            IsolationForestModel(n_estimators=-10)

        with self.assertRaises(ValueError):
            IsolationForestModel(contamination=0.0)

        with self.assertRaises(ValueError):
            IsolationForestModel(contamination=0.6)

        with self.assertRaises(ValueError):
            IsolationForestModel(contamination="invalid_string")

    def test_matrix_validation_empty_and_none(self):
        """Test validation on empty or None matrices."""
        with self.assertRaises(ValueError):
            _validate_numerical_matrix(None)

        with self.assertRaises(ValueError):
            _validate_numerical_matrix([])

        with self.assertRaises(ValueError):
            _validate_numerical_matrix([[]])

    def test_matrix_validation_nan_and_infinities(self):
        """Test that unhandled NaNs and infinities are rejected with informative errors."""
        with self.assertRaises(ValueError) as ctx:
            _validate_numerical_matrix([[1.0, 2.0], [float("nan"), 4.0]])
        self.assertIn("NaN value detected", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            _validate_numerical_matrix([[1.0, float("inf")], [3.0, 4.0]])
        self.assertIn("Infinite value", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            _validate_numerical_matrix([[1.0, float("-inf")], [3.0, 4.0]])
        self.assertIn("Infinite value", str(ctx.exception))

    def test_matrix_validation_inconsistent_dimensions(self):
        """Test rejection of ragged matrices with inconsistent column counts."""
        ragged = [[1.0, 2.0, 3.0], [4.0, 5.0]]
        with self.assertRaises(ValueError) as ctx:
            _validate_numerical_matrix(ragged)
        self.assertIn("Inconsistent feature dimensions", str(ctx.exception))

    def test_not_fitted_error_raised(self):
        """Test that predict, decision_function, and score_samples raise NotFittedError before fit."""
        model = IsolationForestModel()
        dummy_x = [[1.0, 2.0, 3.0]]

        with self.assertRaises(NotFittedError):
            model.predict(dummy_x)

        with self.assertRaises(NotFittedError):
            model.decision_function(dummy_x)

        with self.assertRaises(NotFittedError):
            model.score_samples(dummy_x)

    def test_dependency_missing_error_raised(self):
        """Test that DependencyMissingError is raised if scikit-learn is not available."""
        model = IsolationForestModel()
        dummy_x = [[1.0, 2.0, 3.0], [4.0, 5.0, 6.0]]

        with patch("dark_trace.agent2.model.SKLEARN_AVAILABLE", False):
            with self.assertRaises(DependencyMissingError) as ctx:
                model.fit(dummy_x)
            self.assertEqual(ctx.exception.package_name, "scikit-learn")
            self.assertIn("pip install scikit-learn", ctx.exception.install_cmd)

    def test_fit_and_inference_with_mocked_sklearn(self):
        """Test complete wrapper behavior (fit, predict, decision_function) with mock sklearn."""
        mock_sklearn_instance = MagicMock()
        mock_sklearn_instance.predict.return_value = [1, -1]
        mock_sklearn_instance.decision_function.return_value = [0.15, -0.22]
        mock_sklearn_instance.score_samples.return_value = [-0.45, -0.68]

        mock_sklearn_cls = MagicMock(return_value=mock_sklearn_instance)

        model = IsolationForestModel(n_estimators=50, random_state=42)
        train_data = [[10.0, 20.0, 30.0], [15.0, 25.0, 35.0]]

        with patch("dark_trace.agent2.model.SKLEARN_AVAILABLE", True), \
             patch("dark_trace.agent2.model.SklearnIsolationForest", mock_sklearn_cls):

            model.fit(train_data)

            self.assertTrue(model.is_fitted)
            self.assertEqual(model.n_features_in_, 3)
            mock_sklearn_cls.assert_called_once_with(
                n_estimators=50,
                max_samples="auto",
                contamination="auto",
                random_state=42,
                n_jobs=-1,
            )
            mock_sklearn_instance.fit.assert_called_once()

            # Test predict
            preds = model.predict([[10.0, 20.0, 30.0], [100.0, 200.0, 300.0]])
            self.assertEqual(preds, [1, -1])

            # Test decision_function
            scores = model.decision_function([[10.0, 20.0, 30.0], [100.0, 200.0, 300.0]])
            self.assertEqual(len(scores), 2)
            self.assertAlmostEqual(scores[0], 0.15)
            self.assertAlmostEqual(scores[1], -0.22)

            # Test score_samples
            sample_scores = model.score_samples([[10.0, 20.0, 30.0], [100.0, 200.0, 300.0]])
            self.assertEqual(len(sample_scores), 2)
            self.assertAlmostEqual(sample_scores[0], -0.45)
            self.assertAlmostEqual(sample_scores[1], -0.68)


if __name__ == "__main__":
    unittest.main()

