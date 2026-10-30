"""Reusable anomaly preprocessing pipeline for network flow intrusion detection.

This module provides the `AnomalyPreprocessor` responsible for:
1. Feature extraction and selection from raw network flow records.
2. Protection against target leakage by stripping attack labels.
3. Imputation of missing or NaN values using training-set learned medians.
4. Safe clipping of positive and negative infinite values (e.g. flow rates with 0 duration).
5. Strict, deterministic feature column ordering between training and inference.
6. Clean separation of `fit()`, `transform()`, and `fit_transform()`.
7. Preprocessor state serialization for reproducible model artifacts.
"""

from copy import deepcopy
import json
import math
import statistics
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from dark_trace.agent2.config import PreprocessingConfig
from dark_trace.common.schemas import NetworkFlow


class NotFittedError(RuntimeError):
    """Raised when an operation requiring a fitted preprocessor is invoked prior to fitting."""


class AnomalyPreprocessor:
    """Preprocesses network flow data for unsupervised anomaly detection.

    Attributes:
        config: Configuration options for imputation, clipping, and feature filtering.
        feature_names_: Deterministic list of feature names learned during fit.
        imputation_values_: Learned imputation constant (median/mean) per feature.
        clipping_bounds_: Learned (min, max) clipping range per feature.
        feature_stats_: Summary statistics (median, mean, min, max, std) for explainability.
        is_fitted_: Boolean flag indicating whether the preprocessor has been fitted.
    """

    def __init__(self, config: Optional[PreprocessingConfig] = None):
        self.config = config or PreprocessingConfig()
        self.feature_names_: List[str] = []
        self.imputation_values_: Dict[str, float] = {}
        self.clipping_bounds_: Dict[str, Tuple[float, float]] = {}
        self.feature_stats_: Dict[str, Dict[str, float]] = {}
        self.is_fitted_: bool = False

    def _extract_record_features(self, record: Union[NetworkFlow, Dict[str, Any]]) -> Dict[str, Any]:
        """Extract a flat feature dictionary from a NetworkFlow or dict record.

        Strips prohibited label columns and metadata to prevent target leakage.
        """
        if isinstance(record, NetworkFlow):
            # Extract features from NetworkFlow.features dictionary
            raw_features = dict(record.features)
        elif isinstance(record, dict):
            # If 'features' sub-dictionary is present, merge with top-level keys
            raw_features = {}
            if "features" in record and isinstance(record["features"], dict):
                raw_features.update(record["features"])
            for k, v in record.items():
                if k != "features":
                    raw_features[k] = v
        else:
            raise TypeError(f"Unsupported record type: {type(record).__name__}. Expected NetworkFlow or dict.")

        # Filter out target labels and metadata
        clean_features: Dict[str, Any] = {}
        for k, v in raw_features.items():
            if k in self.config.excluded_labels:
                continue
            if k in self.config.excluded_metadata:
                continue
            clean_features[k] = v

        return clean_features

    def _normalize_dataset(self, X: Any) -> List[Dict[str, Any]]:
        """Normalize various input dataset formats into a list of feature dictionaries."""
        # Handle pandas DataFrame if passed
        if hasattr(X, "to_dict") and callable(getattr(X, "to_dict")):
            records = X.to_dict(orient="records")
            return [self._extract_record_features(r) for r in records]

        if isinstance(X, (list, tuple)):
            return [self._extract_record_features(r) for r in X]

        if isinstance(X, (dict, NetworkFlow)):
            return [self._extract_record_features(X)]

        if isinstance(X, Iterable):
            return [self._extract_record_features(r) for r in X]

        raise TypeError(f"Cannot process input dataset of type: {type(X).__name__}")

    def fit(self, X: Any, y: Any = None) -> "AnomalyPreprocessor":
        """Learn feature set, imputation medians, and clipping bounds from training data.

        Args:
            X: Iterable of NetworkFlow objects, dicts, or pandas DataFrame.
            y: Ignored (unsupervised). Included for scikit-learn API compatibility.

        Returns:
            self: The fitted preprocessor instance.
        """
        records = self._normalize_dataset(X)
        if not records:
            raise ValueError("Cannot fit AnomalyPreprocessor on an empty dataset.")

        # Determine feature names
        if self.config.feature_columns:
            # Use explicit user-configured feature list and ordering
            self.feature_names_ = list(self.config.feature_columns)
        else:
            # Infer feature names across all records, sorted deterministically
            inferred = set()
            for r in records:
                for k, v in r.items():
                    # Accept keys whose values can be parsed as numbers
                    if v is None:
                        inferred.add(k)
                    else:
                        try:
                            float(v)
                            inferred.add(k)
                        except (TypeError, ValueError):
                            continue
            self.feature_names_ = sorted(list(inferred))

        if not self.feature_names_:
            raise ValueError("No valid numerical features found to fit AnomalyPreprocessor.")

        # Compute per-feature statistics on finite values
        self.imputation_values_ = {}
        self.clipping_bounds_ = {}
        self.feature_stats_ = {}

        for col in self.feature_names_:
            finite_vals: List[float] = []
            for r in records:
                val = r.get(col)
                if val is not None:
                    try:
                        f_val = float(val)
                        if not math.isnan(f_val) and not math.isinf(f_val):
                            finite_vals.append(f_val)
                    except (TypeError, ValueError):
                        continue

            if finite_vals:
                median_val = float(statistics.median(finite_vals))
                mean_val = float(statistics.mean(finite_vals))
                min_val = float(min(finite_vals))
                max_val = float(max(finite_vals))
                std_val = float(statistics.stdev(finite_vals)) if len(finite_vals) > 1 else 0.0
            else:
                # Safe fallback if column had zero finite training values
                median_val = 0.0
                mean_val = 0.0
                min_val = self.config.finite_clip_min
                max_val = self.config.finite_clip_max
                std_val = 0.0

            # Set imputation constant based on strategy
            if self.config.imputation_strategy == "median":
                self.imputation_values_[col] = median_val
            elif self.config.imputation_strategy == "mean":
                self.imputation_values_[col] = mean_val
            else:
                self.imputation_values_[col] = 0.0

            # Determine clipping bounds
            clip_min = max(self.config.finite_clip_min, min_val)
            clip_max = min(self.config.finite_clip_max, max_val)
            if clip_min > clip_max:
                clip_min, clip_max = self.config.finite_clip_min, self.config.finite_clip_max
            self.clipping_bounds_[col] = (clip_min, clip_max)

            # Store baseline stats for explainability
            self.feature_stats_[col] = {
                "median": median_val,
                "mean": mean_val,
                "min": min_val,
                "max": max_val,
                "std": std_val,
            }

        self.is_fitted_ = True
        return self

    def transform(self, X: Any) -> List[List[float]]:
        """Transform network flows into a clean 2D numerical feature matrix.

        Applies:
        - Target label and metadata stripping.
        - Strict column ordering matching `self.feature_names_`.
        - Imputation of missing or NaN values using fitted parameters.
        - Finite clipping of +inf and -inf values.
        - Graceful imputation for missing columns.
        - Deterministic dropping of unexpected columns.

        Args:
            X: Iterable of NetworkFlow objects, dicts, or pandas DataFrame.

        Returns:
            List[List[float]]: 2D array of sanitized floats ready for Isolation Forest.
        """
        if not self.is_fitted_:
            raise NotFittedError("This AnomalyPreprocessor instance is not fitted yet. Call 'fit' first.")

        records = self._normalize_dataset(X)
        output_matrix: List[List[float]] = []

        for record in records:
            row: List[float] = []
            for col in self.feature_names_:
                val = record.get(col)
                if val is None:
                    # Missing value: impute with learned value
                    row.append(self.imputation_values_[col])
                    continue

                try:
                    f_val = float(val)
                except (TypeError, ValueError):
                    # Unparseable value: impute safely
                    row.append(self.imputation_values_[col])
                    continue

                if math.isnan(f_val):
                    # NaN: impute with learned value
                    row.append(self.imputation_values_[col])
                elif math.isinf(f_val):
                    # Infinite value: clip to learned bounds
                    clip_min, clip_max = self.clipping_bounds_[col]
                    clipped = clip_max if f_val > 0 else clip_min
                    row.append(clipped)
                else:
                    # Optional clipping for extreme values outside bounds if enabled
                    if self.config.clip_infinities:
                        clip_min, clip_max = self.clipping_bounds_[col]
                        # Allow normal data to pass, but clamp beyond absolute config bounds
                        f_val = max(self.config.finite_clip_min, min(self.config.finite_clip_max, f_val))
                    row.append(f_val)

            output_matrix.append(row)

        return output_matrix

    def fit_transform(self, X: Any, y: Any = None) -> List[List[float]]:
        """Fit the preprocessor on X and return the transformed feature matrix."""
        return self.fit(X, y).transform(X)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize preprocessor state to a JSON-compatible dictionary."""
        if not self.is_fitted_:
            raise NotFittedError("Cannot serialize unfitted preprocessor.")
        return {
            "version": "1.0.0",
            "feature_names": list(self.feature_names_),
            "imputation_values": dict(self.imputation_values_),
            "clipping_bounds": {k: list(v) for k, v in self.clipping_bounds_.items()},
            "feature_stats": deepcopy(self.feature_stats_),
            "imputation_strategy": self.config.imputation_strategy,
            "finite_clip_min": self.config.finite_clip_min,
            "finite_clip_max": self.config.finite_clip_max,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnomalyPreprocessor":
        """Deserialize and restore an AnomalyPreprocessor from a dictionary."""
        config = PreprocessingConfig(
            imputation_strategy=data.get("imputation_strategy", "median"),
            finite_clip_min=data.get("finite_clip_min", -1e9),
            finite_clip_max=data.get("finite_clip_max", 1e9),
            feature_columns=data.get("feature_names"),
        )
        instance = cls(config=config)
        instance.feature_names_ = list(data["feature_names"])
        instance.imputation_values_ = {k: float(v) for k, v in data["imputation_values"].items()}
        instance.clipping_bounds_ = {
            k: (float(v[0]), float(v[1])) for k, v in data["clipping_bounds"].items()
        }
        instance.feature_stats_ = deepcopy(data.get("feature_stats", {}))
        instance.is_fitted_ = True
        return instance

    def save(self, filepath: str) -> None:
        """Save preprocessor state to a JSON file."""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, filepath: str) -> "AnomalyPreprocessor":
        """Load preprocessor state from a JSON file."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)

