"""Training pipeline and trained model container for Agent 2.

Connects AnomalyPreprocessor and IsolationForestModel into an integrated,
reproducible training and artifact lifecycle.
"""

from datetime import datetime, timezone
import os
import statistics
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from dark_trace.agent2.config import ModelConfig, PreprocessingConfig
from dark_trace.agent2.model import IsolationForestModel
from dark_trace.agent2.persistence import load_trained_model, save_trained_model
from dark_trace.agent2.preprocessor import AnomalyPreprocessor
from dark_trace.agent2.scoring import compute_normalized_anomaly_score, interpret_anomaly_label
from dark_trace.common.schemas import NetworkFlow


class TrainedAnomalyModel:
    """Artifact bundle uniting a fitted Isolation Forest model, preprocessor, and metadata.

    Attributes:
        model: Fitted IsolationForestModel instance.
        preprocessor: Fitted AnomalyPreprocessor instance.
        training_metadata: Metadata dictionary capturing training sample counts,
            timestamps, feature lists, and baseline score distributions.
    """

    def __init__(
        self,
        model: IsolationForestModel,
        preprocessor: AnomalyPreprocessor,
        training_metadata: Optional[Dict[str, Any]] = None,
    ):
        self.model = model
        self.preprocessor = preprocessor
        self.training_metadata = training_metadata or {}

    @property
    def model_version(self) -> str:
        return self.model.model_version

    @property
    def feature_names(self) -> List[str]:
        return list(self.preprocessor.feature_names_)

    def score_record(
        self, record: Union[NetworkFlow, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Process a single network flow and return anomaly detection evidence.

        Args:
            record: NetworkFlow instance or raw flow dictionary.

        Returns:
            Dict containing:
                - is_anomaly (bool)
                - anomaly_label (str: "ANOMALOUS" | "NORMAL")
                - raw_anomaly_score (float)
                - normalized_anomaly_score (float: [0.0, 1.0])
                - threshold (float)
        """
        matrix = self.preprocessor.transform([record])
        pred = self.model.predict(matrix)[0]
        raw_score = self.model.decision_function(matrix)[0]

        is_anomaly = (pred == -1) or (raw_score < self.model.raw_decision_threshold)
        norm_score = compute_normalized_anomaly_score(
            raw_score=raw_score,
            training_score_stats=self.training_metadata.get("training_score_stats"),
            raw_threshold=self.model.raw_decision_threshold,
        )

        return {
            "is_anomaly": is_anomaly,
            "anomaly_label": interpret_anomaly_label(is_anomaly),
            "raw_anomaly_score": raw_score,
            "normalized_anomaly_score": norm_score,
            "threshold": self.model.raw_decision_threshold,
        }

    def score_batch(
        self, records: Sequence[Union[NetworkFlow, Dict[str, Any]]]
    ) -> List[Dict[str, Any]]:
        """Process a batch of network flows and return anomaly detection evidence for each."""
        if not records:
            return []

        matrix = self.preprocessor.transform(records)
        preds = self.model.predict(matrix)
        raw_scores = self.model.decision_function(matrix)

        stats = self.training_metadata.get("training_score_stats")
        threshold = self.model.raw_decision_threshold

        results: List[Dict[str, Any]] = []
        for pred, raw_score in zip(preds, raw_scores):
            is_anomaly = (pred == -1) or (raw_score < threshold)
            norm_score = compute_normalized_anomaly_score(
                raw_score=raw_score,
                training_score_stats=stats,
                raw_threshold=threshold,
            )
            results.append(
                {
                    "is_anomaly": is_anomaly,
                    "anomaly_label": interpret_anomaly_label(is_anomaly),
                    "raw_anomaly_score": raw_score,
                    "normalized_anomaly_score": norm_score,
                    "threshold": threshold,
                }
            )

        return results

    def save(self, filepath_or_dir: str) -> str:
        """Persist the trained artifact bundle to disk.

        Args:
            filepath_or_dir: Destination path or directory.

        Returns:
            str: Path to the saved artifact package.
        """
        return save_trained_model(self, filepath_or_dir)

    @classmethod
    def load(cls, filepath_or_dir: str) -> "TrainedAnomalyModel":
        """Load a persisted artifact bundle from disk.

        Args:
            filepath_or_dir: Source path or directory containing saved model and metadata.

        Returns:
            TrainedAnomalyModel: Reconstructed, ready-for-inference artifact.
        """
        return load_trained_model(filepath_or_dir)


class ModelTrainer:
    """Orchestrates feature preprocessing and Isolation Forest training."""

    def __init__(
        self,
        preprocessor: Optional[AnomalyPreprocessor] = None,
        model: Optional[IsolationForestModel] = None,
    ):
        self.preprocessor = preprocessor or AnomalyPreprocessor()
        self.model = model or IsolationForestModel()

    def train(self, dataset: Any) -> TrainedAnomalyModel:
        """Train Isolation Forest anomaly detector on unlabelled network traffic.

        Pipeline:
        1. Preprocess raw records (stripping attack labels and metadata).
        2. Extract clean 2D numerical feature matrix.
        3. Fit Isolation Forest model.
        4. Measure training score baseline distribution for calibration.
        5. Package into immutable TrainedAnomalyModel.

        Args:
            dataset: Sequence of NetworkFlow objects, dicts, or pandas DataFrame.

        Returns:
            TrainedAnomalyModel: Bundled model ready for inference or export.

        Raises:
            ValueError: If dataset is empty or invalid.
        """
        # Step 1 & 2: Preprocess training records
        X_train = self.preprocessor.fit_transform(dataset)
        if not X_train or len(X_train) == 0:
            raise ValueError("Training dataset resulted in 0 preprocessed feature records.")

        # Step 3: Fit Isolation Forest model
        self.model.fit(X_train)

        # Step 4: Calibrate training score baseline distribution
        raw_scores = self.model.decision_function(X_train)
        sorted_scores = sorted(raw_scores)
        n_samples = len(sorted_scores)

        p05_idx = max(0, int(0.05 * n_samples))
        p95_idx = min(n_samples - 1, int(0.95 * n_samples))

        training_score_stats = {
            "min_score": float(sorted_scores[0]),
            "max_score": float(sorted_scores[-1]),
            "median_score": float(statistics.median(sorted_scores)),
            "p05_score": float(sorted_scores[p05_idx]),
            "p95_score": float(sorted_scores[p95_idx]),
            "mean_score": float(statistics.mean(sorted_scores)),
        }

        # Step 5: Construct training metadata
        training_metadata = {
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "sample_count": n_samples,
            "feature_count": len(self.preprocessor.feature_names_),
            "feature_names": list(self.preprocessor.feature_names_),
            "model_version": self.model.model_version,
            "training_score_stats": training_score_stats,
            "model_params": self.model.get_params(),
        }

        return TrainedAnomalyModel(
            model=self.model,
            preprocessor=self.preprocessor,
            training_metadata=training_metadata,
        )

