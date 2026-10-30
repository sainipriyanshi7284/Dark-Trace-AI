"""Agent 2: Intelligent Anomaly Detection and Threat Intelligence."""

from dark_trace.agent2.agent import AnomalyAgent2
from dark_trace.agent2.agent3_contract import create_agent3_composite_handover, format_agent2_for_agent3
from dark_trace.agent2.batch import BatchAnomalyProcessor, BatchProcessingResult
from dark_trace.agent2.config import Agent2Config, ModelConfig, PreprocessingConfig, ThreatIntelConfig
from dark_trace.agent2.explainability import AnomalyExplainer, FeatureDeviation
from dark_trace.agent2.model import DependencyMissingError, IsolationForestModel
from dark_trace.agent2.persistence import load_trained_model, save_trained_model
from dark_trace.agent2.preprocessor import AnomalyPreprocessor, NotFittedError
from dark_trace.agent2.scoring import compute_normalized_anomaly_score, interpret_anomaly_label
from dark_trace.agent2.trainer import ModelTrainer, TrainedAnomalyModel

__all__ = [
    "Agent2Config",
    "ModelConfig",
    "PreprocessingConfig",
    "ThreatIntelConfig",
    "IsolationForestModel",
    "DependencyMissingError",
    "AnomalyPreprocessor",
    "NotFittedError",
    "ModelTrainer",
    "TrainedAnomalyModel",
    "compute_normalized_anomaly_score",
    "interpret_anomaly_label",
    "save_trained_model",
    "load_trained_model",
    "AnomalyExplainer",
    "FeatureDeviation",
    "BatchAnomalyProcessor",
    "BatchProcessingResult",
    "format_agent2_for_agent3",
    "create_agent3_composite_handover",
    "AnomalyAgent2",
]
