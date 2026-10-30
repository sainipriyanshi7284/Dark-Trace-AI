"""Agent 1: Supervised Threat Classifier for CyberSentinel.

Loads the trained Random Forest classifier pipeline (CICIDS2017 flow data),
extracts expected features, calculates class probabilities and confidence,
and outputs standardized Agent1ThreatPrediction objects for Agent 3.
"""

import os
import time
from typing import Any, Dict, List, Optional, Sequence, Union

import numpy as np
import pandas as pd
import joblib

from cybersentinel.agent1.contract import AgentStatus, Agent1ThreatPrediction


CLASS_CANONICAL_MAP = {
    "BENIGN": "BENIGN",
    "DOS": "DOS",
    "DDOS": "DDOS",
    "PORT_SCAN": "PORT SCAN",
    "PORT SCAN": "PORT SCAN",
    "BRUTE_FORCE": "BRUTE FORCE",
    "BRUTE FORCE": "BRUTE FORCE",
}


class ThreatClassifierAgent:
    """Agent 1 coordinator for supervised network threat classification."""

    def __init__(
        self,
        model_path: Optional[str] = "models/threat_classifier.joblib",
        model_artifact: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize Agent 1 with trained model artifact or file path.

        Args:
            model_path: File path to serialized joblib model dictionary.
            model_artifact: Optional in-memory artifact dictionary.
        """
        self.model_path = model_path
        self.model = None
        self.feature_columns: List[str] = []
        self.classes: List[str] = []
        self.is_loaded: bool = False

        if model_artifact is not None:
            self._unpack_artifact(model_artifact)
        elif model_path and os.path.exists(model_path):
            self.load_model(model_path)

    def load_model(self, model_path: str) -> None:
        """Load trained model pipeline and feature columns from joblib artifact."""
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model artifact not found at: {model_path}")

        artifact = joblib.load(model_path)
        self._unpack_artifact(artifact)
        self.model_path = model_path

    def _unpack_artifact(self, artifact: Any) -> None:
        """Extract pipeline, feature columns, and classes from artifact dictionary."""
        if isinstance(artifact, dict):
            self.model = artifact.get("model") or artifact.get("pipeline")
            self.feature_columns = list(artifact.get("feature_columns", []))
            self.classes = list(artifact.get("classes", []))
        else:
            self.model = artifact
            if hasattr(artifact, "classes_"):
                self.classes = list(artifact.classes_)

        self.is_loaded = self.model is not None

    def predict_flow(self, flow: Union[Dict[str, Any], Any]) -> Agent1ThreatPrediction:
        """Classify a single network flow record.

        Args:
            flow: Dictionary, pandas Series, or compatible record.

        Returns:
            Agent1ThreatPrediction with predicted_class, confidence, probabilities.
        """
        start_time = time.perf_counter()

        if not self.is_loaded or self.model is None:
            return Agent1ThreatPrediction(
                agent_id="agent_1",
                status=AgentStatus.ERROR,
                predicted_class="BENIGN",
                confidence=0.0,
                error_message="Agent 1 model is not loaded or unavailable."
            )

        try:
            # Convert to dict if object/Series
            if hasattr(flow, "to_dict"):
                record = flow.to_dict()
            elif isinstance(flow, dict):
                record = flow
            else:
                return Agent1ThreatPrediction(
                    agent_id="agent_1",
                    status=AgentStatus.ERROR,
                    predicted_class="BENIGN",
                    confidence=0.0,
                    error_message=f"Unsupported flow input type: {type(flow).__name__}"
                )

            # Build single-row DataFrame using required feature columns
            row_dict: Dict[str, Any] = {}
            for col in self.feature_columns:
                row_dict[col] = record.get(col, np.nan)

            df_row = pd.DataFrame([row_dict])[self.feature_columns]
            df_clean = df_row.replace([np.inf, -np.inf], np.nan)

            # Predict probabilities
            probas = self.model.predict_proba(df_clean)[0]
            classes = getattr(self.model, "classes_", self.classes)

            max_idx = int(np.argmax(probas))
            raw_class = str(classes[max_idx])
            confidence = float(probas[max_idx])

            # Map raw class to canonical Agent 3 representation
            canonical_class = CLASS_CANONICAL_MAP.get(raw_class.upper(), raw_class)

            # Format probabilities dictionary
            proba_dict = {
                CLASS_CANONICAL_MAP.get(str(cls_name).upper(), str(cls_name)): round(float(prob), 4)
                for cls_name, prob in zip(classes, probas)
            }

            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 3)

            return Agent1ThreatPrediction(
                agent_id="agent_1",
                status=AgentStatus.SUCCESS,
                predicted_class=canonical_class,
                confidence=round(confidence, 4),
                probabilities=proba_dict,
                features={"extracted_count": len(self.feature_columns)},
                latency_ms=elapsed_ms,
            )

        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 3)
            return Agent1ThreatPrediction(
                agent_id="agent_1",
                status=AgentStatus.ERROR,
                predicted_class="BENIGN",
                confidence=0.0,
                latency_ms=elapsed_ms,
                error_message=f"Agent 1 prediction failure: {exc}"
            )

    def predict_batch(self, flows: Sequence[Dict[str, Any]]) -> List[Agent1ThreatPrediction]:
        """Classify a batch of network flows."""
        return [self.predict_flow(f) for f in flows]

