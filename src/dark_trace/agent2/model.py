"""Isolation Forest anomaly detection model wrapper.

This module encapsulates `sklearn.ensemble.IsolationForest` with strict input validation,
hyperparameter management, fitted-state verification, and reproducible execution.
"""

import math
from typing import Any, Dict, List, Optional, Sequence, Union

from dark_trace.agent2.config import ModelConfig
from dark_trace.agent2.preprocessor import NotFittedError

# Check scikit-learn availability
try:
    from sklearn.ensemble import IsolationForest as SklearnIsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SklearnIsolationForest = None
    SKLEARN_AVAILABLE = False


class DependencyMissingError(ImportError):
    """Raised when an ML operation requires an external library that is not installed."""

    def __init__(self, package_name: str, purpose: str, install_cmd: str):
        msg = (
            f"Missing required ML dependency: '{package_name}'. "
            f"Required for {purpose}. "
            f"Please install it in your active virtual environment using: {install_cmd}"
        )
        super().__init__(msg)
        self.package_name = package_name
        self.purpose = purpose
        self.install_cmd = install_cmd


def _validate_numerical_matrix(X: Any, expected_features: Optional[int] = None) -> List[List[float]]:
    """Validate that input X is a non-empty 2D numerical matrix containing finite floats.

    Args:
        X: Input sequence of rows.
        expected_features: Optional number of columns the matrix must match.

    Returns:
        List[List[float]]: Validated 2D matrix of finite floats.

    Raises:
        ValueError: If matrix is empty, non-2D, has mismatched column counts, or has NaNs/infs.
    """
    if X is None:
        raise ValueError("Input feature matrix X cannot be None.")

    # Convert to list of rows if iterable
    if hasattr(X, "tolist") and callable(getattr(X, "tolist")):
        raw_rows = X.tolist()
    elif isinstance(X, (list, tuple)):
        raw_rows = list(X)
    else:
        raise ValueError(f"Unsupported input type for feature matrix: {type(X).__name__}. Expected 2D sequence.")

    if not raw_rows:
        raise ValueError("Input feature matrix X cannot be empty.")

    validated: List[List[float]] = []
    col_count: Optional[int] = expected_features

    for i, row in enumerate(raw_rows):
        if not isinstance(row, (list, tuple)):
            raise ValueError(f"Row {i} in matrix is not a 1D sequence (got {type(row).__name__}).")

        if col_count is None:
            col_count = len(row)
            if col_count == 0:
                raise ValueError("Feature matrix has rows with 0 features.")
        elif len(row) != col_count:
            raise ValueError(
                f"Inconsistent feature dimensions: row {i} has {len(row)} features, "
                f"expected {col_count}."
            )

        float_row: List[float] = []
        for j, val in enumerate(row):
            if val is None:
                raise ValueError(
                    f"Non-finite value detected at row {i}, column {j}: None. "
                    "Ensure AnomalyPreprocessor.transform() is executed before model inference."
                )
            try:
                f_val = float(val)
            except (TypeError, ValueError):
                raise ValueError(
                    f"Non-numeric value detected at row {i}, column {j}: {val!r}. "
                    "All features must be numeric floats."
                )

            if math.isnan(f_val):
                raise ValueError(
                    f"NaN value detected at row {i}, column {j}. "
                    "Ensure AnomalyPreprocessor.transform() is executed before model inference."
                )
            if math.isinf(f_val):
                raise ValueError(
                    f"Infinite value ({f_val}) detected at row {i}, column {j}. "
                    "Ensure AnomalyPreprocessor.transform() clips infinities before model inference."
                )

            float_row.append(f_val)

        validated.append(float_row)

    return validated


class IsolationForestModel:
    """Wrapper around scikit-learn's Isolation Forest anomaly detector.

    Supports configurable tree counts, contamination ratios, deterministic random states,
    and rigorous validation.
    """

    def __init__(self, config: Optional[ModelConfig] = None, **kwargs):
        """Initialize the model wrapper.

        Args:
            config: Optional ModelConfig dataclass.
            **kwargs: Hyperparameter overrides (e.g. n_estimators, contamination, random_state).
        """
        base_config = config or ModelConfig()

        # Apply overrides if provided
        self.n_estimators = int(kwargs.get("n_estimators", base_config.n_estimators))
        self.max_samples = kwargs.get("max_samples", base_config.max_samples)
        self.contamination = kwargs.get("contamination", base_config.contamination)
        self.random_state = kwargs.get("random_state", base_config.random_state)
        self.n_jobs = kwargs.get("n_jobs", base_config.n_jobs)
        self.raw_decision_threshold = float(
            kwargs.get("raw_decision_threshold", base_config.raw_decision_threshold)
        )
        self.version = str(kwargs.get("model_version", base_config.model_version))

        # Hyperparameter sanity validation
        if self.n_estimators <= 0:
            raise ValueError(f"n_estimators must be greater than 0, got {self.n_estimators}")

        if isinstance(self.contamination, (int, float)):
            if not (0.0 < float(self.contamination) <= 0.5):
                raise ValueError(
                    f"contamination must be 'auto' or in range (0.0, 0.5], got {self.contamination}"
                )
        elif self.contamination != "auto":
            raise ValueError(f"contamination must be 'auto' or float, got {self.contamination!r}")

        self.sklearn_model_: Optional[Any] = None
        self.n_features_in_: Optional[int] = None
        self.is_fitted_: bool = False

    @property
    def is_fitted(self) -> bool:
        """Return True if the model has been fitted."""
        return self.is_fitted_

    @property
    def model_version(self) -> str:
        """Return model version string."""
        return self.version

    def check_is_fitted(self) -> None:
        """Verify that the model has been fitted; raises NotFittedError if not."""
        if not self.is_fitted_ or self.sklearn_model_ is None:
            raise NotFittedError(
                "This IsolationForestModel instance is not fitted yet. "
                "Call 'fit' with training data before using this method."
            )

    def _require_sklearn(self, operation: str) -> Any:
        """Check that scikit-learn is available, raising DependencyMissingError if not."""
        if not SKLEARN_AVAILABLE or SklearnIsolationForest is None:
            raise DependencyMissingError(
                package_name="scikit-learn",
                purpose=f"Isolation Forest model {operation}",
                install_cmd="pip install scikit-learn",
            )
        return SklearnIsolationForest

    def fit(self, X: Any, y: Any = None) -> "IsolationForestModel":
        """Fit the Isolation Forest model on the numerical training matrix X.

        Args:
            X: 2D array-like sequence of shape (n_samples, n_features).
            y: Ignored (unsupervised). Included for API consistency.

        Returns:
            self: The fitted IsolationForestModel instance.
        """
        cls_sklearn = self._require_sklearn("training")
        matrix = _validate_numerical_matrix(X)

        self.n_features_in_ = len(matrix[0])

        # Instantiate underlying scikit-learn model
        self.sklearn_model_ = cls_sklearn(
            n_estimators=self.n_estimators,
            max_samples=self.max_samples,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=self.n_jobs,
        )

        self.sklearn_model_.fit(matrix)
        self.is_fitted_ = True
        return self

    def predict(self, X: Any) -> List[int]:
        """Predict whether samples are inliers (1) or outliers (-1).

        Args:
            X: 2D array-like of shape (n_samples, n_features).

        Returns:
            List[int]: 1 for normal inlier, -1 for anomaly outlier.
        """
        self.check_is_fitted()
        matrix = _validate_numerical_matrix(X, expected_features=self.n_features_in_)
        preds = self.sklearn_model_.predict(matrix)
        return [int(p) for p in preds]

    def decision_function(self, X: Any) -> List[float]:
        """Compute the raw anomaly decision score for each sample.

        Score semantics:
        - Negative scores indicate outliers (anomalies).
        - Positive scores indicate inliers (normal).

        Args:
            X: 2D array-like of shape (n_samples, n_features).

        Returns:
            List[float]: Raw decision function values.
        """
        self.check_is_fitted()
        matrix = _validate_numerical_matrix(X, expected_features=self.n_features_in_)
        scores = self.sklearn_model_.decision_function(matrix)
        return [float(s) for s in scores]

    def score_samples(self, X: Any) -> List[float]:
        """Compute the opposite of the anomaly score defined in the original paper.

        Lower values indicate higher degree of anomaly.

        Args:
            X: 2D array-like of shape (n_samples, n_features).

        Returns:
            List[float]: Sample anomaly scores.
        """
        self.check_is_fitted()
        matrix = _validate_numerical_matrix(X, expected_features=self.n_features_in_)
        scores = self.sklearn_model_.score_samples(matrix)
        return [float(s) for s in scores]

    def get_params(self) -> Dict[str, Any]:
        """Return model hyperparameters as a dictionary."""
        return {
            "n_estimators": self.n_estimators,
            "max_samples": self.max_samples,
            "contamination": self.contamination,
            "random_state": self.random_state,
            "n_jobs": self.n_jobs,
            "raw_decision_threshold": self.raw_decision_threshold,
            "model_version": self.version,
            "n_features_in": self.n_features_in_,
            "is_fitted": self.is_fitted_,
        }

