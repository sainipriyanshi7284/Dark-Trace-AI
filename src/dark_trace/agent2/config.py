"""Configuration parameters, feature definitions, and guardrail settings for Agent 2."""

from dataclasses import dataclass, field
import os
from typing import FrozenSet, List, Optional


# Canonical numerical flow features used in standard intrusion detection benchmarks
DEFAULT_NUMERICAL_FEATURES: List[str] = [
    "flow_duration_ms",
    "total_fwd_packets",
    "total_bwd_packets",
    "fwd_packet_length_mean",
    "bwd_packet_length_mean",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "flow_iat_mean_ms",
    "syn_flag_count",
    "rst_flag_count",
    "ack_flag_count",
]

# Prohibited columns to prevent target leakage in unsupervised anomaly detection
DEFAULT_EXCLUDED_LABELS: FrozenSet[str] = frozenset(
    [
        "label",
        "attack_cat",
        "is_attack",
        "target",
        "class",
        "Label",
        "Attack",
        "classification",
        "anomaly",
    ]
)

# Non-numerical metadata columns to exclude from numerical model feature matrices
DEFAULT_EXCLUDED_METADATA: FrozenSet[str] = frozenset(
    [
        "flow_id",
        "timestamp",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "metadata",
        "force_threat_intel",
    ]
)


@dataclass
class PreprocessingConfig:
    """Settings governing feature extraction, validation, and imputation."""

    imputation_strategy: str = "median"  # 'median', 'mean', or 'zero'
    clip_infinities: bool = True
    finite_clip_min: float = -1e9
    finite_clip_max: float = 1e9
    scale_features: bool = False  # False by default for tree-based Isolation Forest
    feature_columns: Optional[List[str]] = None
    excluded_labels: FrozenSet[str] = DEFAULT_EXCLUDED_LABELS
    excluded_metadata: FrozenSet[str] = DEFAULT_EXCLUDED_METADATA


@dataclass
class ModelConfig:
    """Hyperparameters and operational configuration for Isolation Forest."""

    n_estimators: int = 100
    max_samples: str = "auto"
    contamination: str = "auto"  # 'auto' or float in (0.0, 0.5]
    random_state: int = 42
    n_jobs: int = -1
    raw_decision_threshold: float = 0.0
    model_version: str = "iforest_v1.0.0"


@dataclass
class ThreatIntelConfig:
    """Configuration for external threat intelligence investigation (TinyFish)."""

    enabled: bool = True
    severity_trigger_threshold: float = 0.75  # Min normalized score to trigger lookup
    cache_ttl_seconds: int = 3600  # 1 hour LRU TTL
    request_timeout_seconds: float = 5.0
    max_retries: int = 2
    api_key_env_var: str = "TINYFISH_API_KEY"

    @property
    def api_key(self) -> Optional[str]:
        """Fetch API key from environment dynamically."""
        return os.environ.get(self.api_key_env_var)


@dataclass
class Agent2Config:
    """Master configuration encapsulating preprocessing, ML model, and threat intel."""

    preprocessing: PreprocessingConfig = field(default_factory=PreprocessingConfig)
    model: ModelConfig = field(default_factory=ModelConfig)
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)

