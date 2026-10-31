"""Agent 2 Configuration Module.

Central configuration settings for Agent 2 (Network Anomaly Detection).
Provides directory paths, artifact paths, and metadata-driven threshold loading.
All paths are dynamically anchored to the dark_trace.agent2 package root.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union
import json
import logging

logger = logging.getLogger(__name__)

# Resolve dark_trace.agent2 package directory safely from file location
# File location: <project_root>/src/dark_trace/agent2/config.py
_CURRENT_FILE = Path(__file__).resolve()
_DEFAULT_BASE_DIR = _CURRENT_FILE.parent
_PROJECT_ROOT = _CURRENT_FILE.parent.parent.parent


@dataclass(frozen=True)
class Agent2Config:
    """Configuration parameters for Agent 2 runtime and model artifacts."""

    # Package directory paths (dynamically anchored to dark_trace.agent2)
    base_dir: Union[Path, str] = field(default_factory=lambda: _DEFAULT_BASE_DIR)
    artifacts_dir: Optional[Path] = None
    data_dir: Optional[Path] = None

    # Trained model artifacts from Google Colab
    model_path: Optional[Path] = None
    metadata_path: Optional[Path] = None
    evaluation_path: Optional[Path] = None

    # Calibrated anomaly threshold (loaded dynamically from verified metadata)
    calibrated_threshold: Optional[float] = None

    def __post_init__(self) -> None:
        """Resolve directory and artifact paths relative to base_dir, and load threshold."""
        resolved_base = Path(self.base_dir).resolve()
        object.__setattr__(self, "base_dir", resolved_base)
        artifacts = resolved_base / "artifacts"
        data = resolved_base / "data"

        # Fallback check if user passed a custom base_dir where artifacts don't exist
        # but package artifacts do (unless explicitly testing custom paths)
        if self.artifacts_dir is None:
            object.__setattr__(self, "artifacts_dir", artifacts)
        else:
            object.__setattr__(self, "artifacts_dir", Path(self.artifacts_dir).resolve())

        if self.data_dir is None:
            object.__setattr__(self, "data_dir", data)
        else:
            object.__setattr__(self, "data_dir", Path(self.data_dir).resolve())

        # Artifact filenames matching Google Colab export
        if self.model_path is None:
            object.__setattr__(self, "model_path", self.artifacts_dir / "agent2_isolation_forest.joblib")
        else:
            object.__setattr__(self, "model_path", Path(self.model_path).resolve())

        if self.metadata_path is None:
            object.__setattr__(self, "metadata_path", self.artifacts_dir / "agent2_metadata.json")
        else:
            object.__setattr__(self, "metadata_path", Path(self.metadata_path).resolve())

        if self.evaluation_path is None:
            object.__setattr__(self, "evaluation_path", self.artifacts_dir / "agent2_final_evaluation.json")
        else:
            object.__setattr__(self, "evaluation_path", Path(self.evaluation_path).resolve())

        # Load calibrated threshold dynamically from verified metadata if available
        if self.calibrated_threshold is None and self.metadata_path.is_file():
            try:
                with open(self.metadata_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                loaded_thresh = meta.get("threshold")
                if loaded_thresh is not None and isinstance(loaded_thresh, (int, float)):
                    object.__setattr__(self, "calibrated_threshold", float(loaded_thresh))
            except Exception as err:
                logger.warning("Could not read threshold from metadata at %s: %s", self.metadata_path, err)
