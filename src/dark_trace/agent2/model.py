"""Model Loading and Inference Module for Agent 2 (Network Anomaly Detection).

Provides:
- AnomalyDetectorInterface: Protocol/ABC for anomaly detection models.
- IsolationForestDetector: Production detector wrapping scikit-learn Isolation Forest.

CRITICAL INFERENCE & FEATURE RULES:
1. STRICT FEATURE ORDERING: Exactly 74 numerical features matching the model metadata
   in exact sequence.
2. INPUT VALIDATION: Rejects missing features, boolean inputs, non-numeric values,
   and non-finite numbers (NaN, +inf, -inf).
3. EXPLICIT AVAILABILITY: Inference raises RuntimeError if the model artifact or
   metadata is not loaded and verified.
4. SCORING CONVENTION: score = -model.score_samples(X). Higher means more anomalous.
5. THRESHOLD COMPARISON: is_anomaly = True if score >= threshold else False.
6. NO RETRAINING: Pre-trained Isolation Forest artifact is loaded read-only.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional
import json
import logging
import math
import time
import warnings

import joblib
import numpy as np

from dark_trace.agent2.config import Agent2Config
from dark_trace.agent2.schemas import AnomalyScore

logger = logging.getLogger(__name__)


class AnomalyDetectorInterface(ABC):
    """Abstract interface defining the contract for anomaly detection models."""

    @abstractmethod
    def is_loaded(self) -> bool:
        """Return True if model and metadata are loaded, verified, and ready."""
        pass

    @abstractmethod
    def validate_features(self, features: Dict[str, Any]) -> np.ndarray:
        """Validate input features against expected schema and return a 2D numpy array."""
        pass

    @abstractmethod
    def predict_anomaly(self, features: Dict[str, Any]) -> AnomalyScore:
        """Predict anomaly status and score for a single flow's features."""
        pass


class IsolationForestDetector(AnomalyDetectorInterface):
    """Production Isolation Forest Anomaly Detector.

    Wraps the trained scikit-learn IsolationForest model, validates incoming
    network flow features against metadata, computes anomaly scores via
    -model.score_samples(X), and compares with the calibrated threshold.
    """

    def __init__(
        self,
        model_path: Optional[Path] = None,
        metadata_path: Optional[Path] = None,
        config: Optional[Agent2Config] = None,
    ):
        """Initialize and automatically load the Isolation Forest model and metadata.

        Args:
            model_path: Optional explicit path to model joblib file.
            metadata_path: Optional explicit path to metadata JSON file.
            config: Optional Agent2Config instance.

        Raises:
            FileNotFoundError: If artifact files do not exist on disk.
            ValueError: If metadata is invalid or inconsistent with model expectations.
            RuntimeError: If artifact cannot be unpickled.
        """
        self.config = config or Agent2Config()
        self.model_path = model_path or self.config.model_path
        self.metadata_path = metadata_path or self.config.metadata_path

        self.model: Optional[Any] = None
        self.metadata: Dict[str, Any] = {}
        self.feature_names: List[str] = []
        self.expected_feature_count: int = 74
        self.threshold: Optional[float] = None
        self.model_version: str = "unavailable"

        # Attempt safe loading if paths are provided
        if self.model_path is not None and self.metadata_path is not None:
            self._load_and_verify()

    def _load_and_verify(self) -> None:
        """Load model artifact and verified metadata, validating schema consistency."""
        m_path = Path(self.model_path).resolve()
        meta_path = Path(self.metadata_path).resolve()

        if not m_path.is_file():
            raise FileNotFoundError(f"Isolation Forest model artifact not found at {m_path}")
        if not meta_path.is_file():
            raise FileNotFoundError(f"Model metadata artifact not found at {meta_path}")

        # 1. Load and parse metadata JSON
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                loaded_metadata = json.load(f)
        except Exception as err:
            raise ValueError(f"Failed to parse metadata JSON at {meta_path}: {err}") from err

        feature_names = loaded_metadata.get("feature_names")
        if not feature_names or not isinstance(feature_names, list):
            raise ValueError(f"Metadata must contain a non-empty list of 'feature_names': {meta_path}")

        if len(feature_names) != 74:
            raise ValueError(f"Expected exactly 74 feature names in metadata, got {len(feature_names)}")

        threshold = loaded_metadata.get("threshold")
        if threshold is None or not isinstance(threshold, (int, float)):
            raise ValueError(f"Metadata missing valid numeric 'threshold': {meta_path}")
        if not math.isfinite(threshold) or threshold <= 0.0:
            raise ValueError(f"Metadata threshold must be positive, got {threshold}")

        # 2. Load model artifact using joblib
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                loaded_model = joblib.load(m_path)
        except Exception as err:
            raise RuntimeError(f"Failed to unpickle model artifact at {m_path}: {err}") from err

        # 3. Validate estimator compatibility
        estimator_class = getattr(loaded_model, "__class__", None)
        class_name = estimator_class.__name__ if estimator_class else ""
        if "IsolationForest" not in class_name:
            raise ValueError(f"Expected IsolationForest estimator, found: {class_name}")

        n_features = getattr(loaded_model, "n_features_in_", None)
        if n_features != 74:
            raise ValueError(f"Model n_features_in_ must be 74, found {n_features}")

        # 4. Check model feature names if preserved on estimator
        if hasattr(loaded_model, "feature_names_in_"):
            model_feat_list = list(loaded_model.feature_names_in_)
            if model_feat_list != feature_names:
                raise ValueError("Model feature_names_in_ does not match metadata feature_names ordering.")

        # Commit loaded state
        self.model = loaded_model
        self.metadata = loaded_metadata
        self.feature_names = list(feature_names)
        self.expected_feature_count = len(self.feature_names)
        self.threshold = float(threshold)
        self.model_path = m_path
        self.metadata_path = meta_path
        self.model_version = loaded_metadata.get("model", "IsolationForest_CICIDS2017")

        logger.info(
            "Successfully loaded Isolation Forest detector (%d features, threshold=%.8f) from %s",
            self.expected_feature_count,
            self.threshold,
            m_path,
        )

    def is_loaded(self) -> bool:
        """Check whether the Isolation Forest model artifact is loaded and validated."""
        return (
            self.model is not None
            and bool(self.feature_names)
            and len(self.feature_names) == 74
            and self.threshold is not None
            and math.isfinite(self.threshold)
        )

    def validate_features(self, features: Dict[str, Any]) -> np.ndarray:
        """Validate and extract all 74 required features in exact metadata order.

        Rules:
        - Must be loaded.
        - Features must be a dictionary.
        - All 74 feature names from metadata must be present.
        - All values must be valid numeric types (convertible to float).
        - Booleans are rejected (not numeric features).
        - Values must NOT be NaN, +inf, or -inf.
        - Extra non-feature dictionary keys are permitted and safely ignored.
        - Features are ordered strictly according to metadata, NOT incoming dictionary order.
        - Missing features are never silently imputed with zero.

        Args:
            features: Dictionary mapping feature names to values.

        Returns:
            np.ndarray: 2D array of shape (1, 74) with float64 values.

        Raises:
            RuntimeError: If model is not loaded.
            ValueError: If missing features, non-numeric values, or non-finite numbers exist.
        """
        if not self.is_loaded():
            raise RuntimeError(
                "Cannot validate features: Isolation Forest model is not loaded and verified."
            )

        if not isinstance(features, dict):
            raise ValueError(f"Features must be provided as a dictionary, got {type(features).__name__}")

        # Check for missing features
        missing_features = [name for name in self.feature_names if name not in features]
        if missing_features:
            sample_missing = missing_features[:5]
            ellipsis_str = "..." if len(missing_features) > 5 else ""
            raise ValueError(
                f"Missing {len(missing_features)} required features: {sample_missing}{ellipsis_str}"
            )

        ordered_values: List[float] = []
        for name in self.feature_names:
            val = features[name]
            if val is None:
                raise ValueError(f"Feature '{name}' has value None; finite numeric float required.")
            if isinstance(val, (bool, np.bool_)):
                raise ValueError(f"Feature '{name}' has boolean value {val!r}; finite numeric value required.")

            # Attempt numeric conversion
            try:
                num = float(val)
            except (ValueError, TypeError) as err:
                raise ValueError(
                    f"Feature '{name}' has non-numeric value {val!r}: {err}"
                ) from err

            # Check for non-finite values (NaN, +inf, -inf)
            if math.isnan(num):
                raise ValueError(f"Feature '{name}' contains NaN (not a number).")
            if math.isinf(num):
                raise ValueError(f"Feature '{name}' contains infinite value: {num}.")

            ordered_values.append(num)

        feature_matrix = np.array([ordered_values], dtype=np.float64)
        if feature_matrix.shape != (1, self.expected_feature_count):
            raise ValueError(
                f"Feature matrix shape mismatch: expected (1, {self.expected_feature_count}), got {feature_matrix.shape}"
            )

        return feature_matrix

    def predict_anomaly(self, features: Dict[str, Any]) -> AnomalyScore:
        """Execute calibrated anomaly scoring on a single flow's extracted features.

        Calculates anomaly score = -model.score_samples(X).
        Compares with calibrated threshold from metadata: is_anomaly = (score >= threshold).

        Args:
            features: Dictionary containing all 74 numerical feature values.

        Returns:
            AnomalyScore: Detailed anomaly evidence.

        Raises:
            RuntimeError: If called before model is loaded.
            ValueError: If feature validation fails.
        """
        if not self.is_loaded():
            raise RuntimeError(
                "Isolation Forest model is unavailable. Artifact and verified metadata must be loaded."
            )

        # Validate and construct input in exact metadata order
        feature_matrix = self.validate_features(features)

        start_time = time.perf_counter()

        # Score using -score_samples(X)
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=UserWarning, message=".*does not have valid feature names.*")
            raw_scores = self.model.score_samples(feature_matrix)

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        raw_score = float(-raw_scores[0])
        is_anomaly = bool(raw_score >= self.threshold)

        return AnomalyScore(
            status="EVALUATED",
            is_anomaly=is_anomaly,
            raw_score=raw_score,
            normalized_score=None,  # Not modeled without a defensible calibrated formula
            threshold=self.threshold,
            model_version=self.model_version,
            supporting_features=[],  # IF does not provide reliable per-feature attribution
            inference_latency_ms=round(latency_ms, 4),
            error_message=None,
        )


# Backward compatibility alias
IsolationForestModel = IsolationForestDetector
