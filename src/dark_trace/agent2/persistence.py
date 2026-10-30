"""Artifact persistence and loading for Agent 2 models.

Saves and loads TrainedAnomalyModel artifacts including the underlying Isolation Forest
estimator, fitted AnomalyPreprocessor state, and training metadata.
"""

from copy import deepcopy
import json
import os
import shutil
from typing import Any, Dict, Optional

from dark_trace.agent2.config import ModelConfig
from dark_trace.agent2.model import DependencyMissingError, IsolationForestModel
from dark_trace.agent2.preprocessor import AnomalyPreprocessor

# Check joblib availability
try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    joblib = None
    JOBLIB_AVAILABLE = False


METADATA_FILENAME = "metadata.json"
MODEL_BINARY_FILENAME = "model.joblib"


def save_trained_model(trained_model: Any, target_path: str) -> str:
    """Save a TrainedAnomalyModel bundle to disk.

    Creates a structured directory or file containing:
    1. 'model.joblib': Serialized scikit-learn IsolationForest estimator.
    2. 'metadata.json': Preprocessor state, feature list, hyperparameters,
       and training score statistics.

    Args:
        trained_model: TrainedAnomalyModel instance to persist.
        target_path: Destination path. If ending in '.joblib', saves alongside
            metadata. If a directory, saves inside that directory.

    Returns:
        str: Absolute path of the saved artifact directory or file.
    """
    if not JOBLIB_AVAILABLE:
        raise DependencyMissingError(
            package_name="joblib",
            purpose="model artifact serialization",
            install_cmd="pip install joblib",
        )

    # Determine directory
    if target_path.endswith(".joblib"):
        dir_path = os.path.dirname(os.path.abspath(target_path))
        base_name = os.path.basename(target_path)
    else:
        dir_path = os.path.abspath(target_path)
        base_name = MODEL_BINARY_FILENAME

    os.makedirs(dir_path, exist_ok=True)
    model_binary_path = os.path.join(dir_path, base_name)
    metadata_path = os.path.join(dir_path, METADATA_FILENAME)

    # 1. Serialize underlying scikit-learn model via joblib
    joblib.dump(trained_model.model.sklearn_model_, model_binary_path, compress=3)

    # 2. Serialize metadata and preprocessor state to JSON
    metadata: Dict[str, Any] = {
        "format_version": "1.0.0",
        "model_version": trained_model.model.model_version,
        "model_params": trained_model.model.get_params(),
        "preprocessor_state": trained_model.preprocessor.to_dict(),
        "training_metadata": deepcopy(trained_model.training_metadata),
        "model_binary_file": base_name,
    }

    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return model_binary_path


def load_trained_model(source_path: str) -> Any:
    """Load and reconstruct a TrainedAnomalyModel from disk.

    Args:
        source_path: Path to the model file (.joblib) or directory containing
            'model.joblib' and 'metadata.json'.

    Returns:
        TrainedAnomalyModel: Reconstructed model and preprocessor.

    Raises:
        FileNotFoundError: If the artifact or metadata file does not exist.
        ValueError: If the artifact metadata is corrupt or incompatible.
        DependencyMissingError: If joblib is not installed.
    """
    from dark_trace.agent2.trainer import TrainedAnomalyModel

    if not JOBLIB_AVAILABLE:
        raise DependencyMissingError(
            package_name="joblib",
            purpose="model artifact deserialization",
            install_cmd="pip install joblib",
        )

    if not os.path.exists(source_path):
        raise FileNotFoundError(f"Model artifact path does not exist: {source_path}")

    if os.path.isdir(source_path):
        dir_path = source_path
        metadata_path = os.path.join(dir_path, METADATA_FILENAME)
        model_binary_path = os.path.join(dir_path, MODEL_BINARY_FILENAME)
    else:
        dir_path = os.path.dirname(os.path.abspath(source_path))
        metadata_path = os.path.join(dir_path, METADATA_FILENAME)
        model_binary_path = source_path

    if not os.path.exists(metadata_path):
        raise FileNotFoundError(
            f"Missing required metadata file '{METADATA_FILENAME}' at: {metadata_path}"
        )
    if not os.path.exists(model_binary_path):
        raise FileNotFoundError(
            f"Missing required model binary file at: {model_binary_path}"
        )

    # 1. Load metadata
    try:
        with open(metadata_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)
    except Exception as err:
        raise ValueError(f"Corrupted metadata JSON in '{metadata_path}': {err}")

    # Validate essential metadata keys
    for req in ["model_params", "preprocessor_state"]:
        if req not in metadata:
            raise ValueError(f"Incomplete model artifact: missing '{req}' in {metadata_path}")

    # 2. Reconstruct preprocessor
    preprocessor = AnomalyPreprocessor.from_dict(metadata["preprocessor_state"])

    # 3. Reconstruct model wrapper
    params = metadata["model_params"]
    config = ModelConfig(
        n_estimators=params.get("n_estimators", 100),
        max_samples=params.get("max_samples", "auto"),
        contamination=params.get("contamination", "auto"),
        random_state=params.get("random_state", 42),
        n_jobs=params.get("n_jobs", -1),
        raw_decision_threshold=params.get("raw_decision_threshold", 0.0),
        model_version=metadata.get("model_version", "iforest_v1.0.0"),
    )
    model = IsolationForestModel(config=config)

    # 4. Deserialize scikit-learn model
    try:
        sklearn_obj = joblib.load(model_binary_path)
    except Exception as err:
        raise ValueError(f"Failed to load serialized model binary '{model_binary_path}': {err}")

    model.sklearn_model_ = sklearn_obj
    model.n_features_in_ = params.get("n_features_in", len(preprocessor.feature_names_))
    model.is_fitted_ = True

    return TrainedAnomalyModel(
        model=model,
        preprocessor=preprocessor,
        training_metadata=metadata.get("training_metadata", {}),
    )

