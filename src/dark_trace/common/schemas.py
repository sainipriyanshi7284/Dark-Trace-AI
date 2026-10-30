"""Data contracts and schemas for network flow ingestion and Agent 2 evidence output.

This module provides strongly-typed, validated data schemas for:
1. `NetworkFlow`: Ingestion contract for live or offline network flow records.
2. `Agent2Evidence`: Unified output contract providing anomaly detection evidence
   and external threat intelligence context for downstream consumption by Agent 3.

Implementation note:
These schemas are implemented using Python's standard library `dataclasses` and
explicit validation methods to ensure zero-dependency execution in restricted or
proxy-isolated environments, while maintaining full compatibility with Pydantic v2
serialization conventions.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import math
from typing import Any, Dict, List, Optional, Union

from dark_trace.common.ip_utils import is_valid_ip


class ValidationError(ValueError):
    """Raised when an ingested network flow or evidence record fails schema validation."""

    def __init__(self, field_name: str, message: str, invalid_value: Any = None):
        super().__init__(f"Validation error on '{field_name}': {message} (got {invalid_value!r})")
        self.field_name = field_name
        self.message = message
        self.invalid_value = invalid_value


def _validate_port(port: Any, field_name: str) -> int:
    """Validate that port is an integer in range [0, 65535]."""
    try:
        port_int = int(port)
    except (TypeError, ValueError):
        raise ValidationError(field_name, "Port must be an integer", port)
    if not (0 <= port_int <= 65535):
        raise ValidationError(field_name, "Port must be between 0 and 65535", port)
    return port_int


def _validate_ip_field(ip_val: Any, field_name: str) -> str:
    """Validate that ip_val is a valid IPv4 or IPv6 string."""
    if not ip_val or not isinstance(ip_val, (str, bytes)):
        raise ValidationError(field_name, "IP address must be a non-empty string", ip_val)
    ip_str = str(ip_val).strip()
    if not is_valid_ip(ip_str):
        raise ValidationError(field_name, "Invalid IPv4/IPv6 address format", ip_val)
    return ip_str


def _validate_features(features: Any) -> Dict[str, float]:
    """Validate that features is a dictionary mapping string keys to numeric values."""
    if features is None:
        return {}
    if not isinstance(features, dict):
        raise ValidationError("features", "Features must be a dictionary of feature names to values", features)

    validated: Dict[str, float] = {}
    for k, v in features.items():
        if not isinstance(k, str) or not k.strip():
            raise ValidationError("features", f"Feature key must be a non-empty string: {k!r}", k)
        if v is None:
            # None is allowed; will be imputed by preprocessor
            validated[k] = float("nan")
            continue
        try:
            val_float = float(v)
            validated[k] = val_float
        except (TypeError, ValueError):
            raise ValidationError("features", f"Feature '{k}' value must be numeric: {v!r}", v)
    return validated


@dataclass
class NetworkFlow:
    """Standardized network flow ingestion record.

    Attributes:
        flow_id: Unique identifier for the network flow.
        timestamp: ISO-8601 string or epoch timestamp string.
        src_ip: Validated source IPv4/IPv6 address.
        dst_ip: Validated destination IPv4/IPv6 address.
        src_port: Source port (0-65535).
        dst_port: Destination port (0-65535).
        protocol: Protocol identifier (e.g., 'TCP', 'UDP', 'ICMP', or integer code).
        features: Mapping of numerical flow characteristics (e.g. durations, packet counts, byte rates).
        force_threat_intel: Manual trigger override to request TinyFish threat investigation.
        metadata: Optional auxiliary flow or sensor metadata (not used in ML scoring).
    """

    flow_id: str
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: Union[str, int]
    features: Dict[str, float] = field(default_factory=dict)
    force_threat_intel: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate and sanitize fields upon instantiation."""
        if not self.flow_id or not str(self.flow_id).strip():
            raise ValidationError("flow_id", "flow_id must be a non-empty string", self.flow_id)
        self.flow_id = str(self.flow_id).strip()

        if not self.timestamp or not str(self.timestamp).strip():
            self.timestamp = datetime.now(timezone.utc).isoformat()
        else:
            self.timestamp = str(self.timestamp).strip()

        self.src_ip = _validate_ip_field(self.src_ip, "src_ip")
        self.dst_ip = _validate_ip_field(self.dst_ip, "dst_ip")
        self.src_port = _validate_port(self.src_port, "src_port")
        self.dst_port = _validate_port(self.dst_port, "dst_port")

        if isinstance(self.protocol, int):
            if not (0 <= self.protocol <= 255):
                raise ValidationError("protocol", "Protocol number must be between 0 and 255", self.protocol)
        elif isinstance(self.protocol, str):
            if not self.protocol.strip():
                raise ValidationError("protocol", "Protocol string must not be empty", self.protocol)
            self.protocol = self.protocol.strip().upper()
        else:
            raise ValidationError("protocol", "Protocol must be string or integer", self.protocol)

        self.features = _validate_features(self.features)
        self.force_threat_intel = bool(self.force_threat_intel)
        if self.metadata is None:
            self.metadata = {}
        elif not isinstance(self.metadata, dict):
            raise ValidationError("metadata", "Metadata must be a dictionary", self.metadata)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize NetworkFlow to a standard dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Serialize NetworkFlow to a JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NetworkFlow":
        """Instantiate and validate a NetworkFlow from a dictionary."""
        if not isinstance(data, dict):
            raise ValidationError("root", "Data must be a dictionary", data)

        required_keys = ["flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol"]
        for key in required_keys:
            if key not in data:
                raise ValidationError(key, f"Missing required field: '{key}'", None)

        return cls(
            flow_id=data["flow_id"],
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            src_ip=data["src_ip"],
            dst_ip=data["dst_ip"],
            src_port=data["src_port"],
            dst_port=data["dst_port"],
            protocol=data["protocol"],
            features=data.get("features", {}),
            force_threat_intel=data.get("force_threat_intel", False),
            metadata=data.get("metadata", {}),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "NetworkFlow":
        """Instantiate and validate a NetworkFlow from a JSON string."""
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as err:
            raise ValidationError("json", f"Malformed JSON string: {err}", json_str)
        return cls.from_dict(data)


@dataclass
class SupportingFeature:
    """Individual feature deviation evidence explaining an anomaly."""

    feature_name: str
    observed_value: float
    baseline_median: Optional[float] = None
    deviation_direction: str = "HIGH"  # HIGH | LOW | NORMAL

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AnomalyDetectionResult:
    """Machine learning anomaly detection evidence output."""

    is_anomaly: bool
    anomaly_label: str  # ANOMALOUS | NORMAL
    raw_anomaly_score: float  # Isolation Forest decision_function output
    normalized_anomaly_score: float  # Outlier severity index in [0.0, 1.0]
    threshold: float = 0.0
    supporting_features: List[SupportingFeature] = field(default_factory=list)
    model_version: str = "iforest_v1.0.0"
    inference_latency_ms: float = 0.0

    def __post_init__(self):
        self.is_anomaly = bool(self.is_anomaly)
        self.anomaly_label = str(self.anomaly_label).upper()
        self.raw_anomaly_score = float(self.raw_anomaly_score)
        norm_score = float(self.normalized_anomaly_score)
        # Clamp normalized score to [0.0, 1.0]
        self.normalized_anomaly_score = max(0.0, min(1.0, norm_score))
        self.threshold = float(self.threshold)
        self.model_version = str(self.model_version)
        self.inference_latency_ms = max(0.0, float(self.inference_latency_ms))

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        # Ensure supporting features serialize cleanly
        data["supporting_features"] = [
            f if isinstance(f, dict) else f.to_dict() for f in self.supporting_features
        ]
        return data


@dataclass
class ThreatIntelligenceResult:
    """External threat intelligence investigation evidence output."""

    provider: str = "tinyfish"
    investigation_status: str = "NOT_REQUESTED"  # NOT_REQUESTED | SKIPPED_PRIVATE_IP | SKIPPED_BELOW_THRESHOLD | COMPLETED | FAILED | UNAVAILABLE
    indicator: Optional[str] = None
    indicator_type: str = "NONE"  # NONE | PUBLIC_IP | DOMAIN | HASH
    findings: List[str] = field(default_factory=list)
    threat_context: List[Dict[str, Any]] = field(default_factory=list)
    attack_techniques: List[Dict[str, Any]] = field(default_factory=list)
    sources: List[Dict[str, str]] = field(default_factory=list)
    investigated_at: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Agent2Evidence:
    """Unified Agent 2 evidence record prepared for Agent 3 fusion."""

    flow_id: str
    timestamp: str
    anomaly_detection: AnomalyDetectionResult
    threat_intelligence: ThreatIntelligenceResult = field(default_factory=ThreatIntelligenceResult)
    agent_id: str = "A2"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.flow_id:
            raise ValidationError("flow_id", "flow_id must not be empty", self.flow_id)
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

        if isinstance(self.anomaly_detection, dict):
            # Convert nested supporting features if present
            supp = [
                SupportingFeature(**sf) if isinstance(sf, dict) else sf
                for sf in self.anomaly_detection.get("supporting_features", [])
            ]
            ad_copy = dict(self.anomaly_detection)
            ad_copy["supporting_features"] = supp
            self.anomaly_detection = AnomalyDetectionResult(**ad_copy)

        if isinstance(self.threat_intelligence, dict):
            self.threat_intelligence = ThreatIntelligenceResult(**self.threat_intelligence)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize complete evidence payload to a dictionary."""
        return {
            "agent_id": self.agent_id,
            "flow_id": self.flow_id,
            "timestamp": self.timestamp,
            "anomaly_detection": self.anomaly_detection.to_dict(),
            "threat_intelligence": self.threat_intelligence.to_dict(),
            "metadata": dict(self.metadata),
        }

    def to_json(self) -> str:
        """Serialize evidence payload to a JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Agent2Evidence":
        """Instantiate Agent2Evidence from a dictionary."""
        if not isinstance(data, dict):
            raise ValidationError("root", "Data must be a dictionary", data)

        for req in ["flow_id", "anomaly_detection"]:
            if req not in data:
                raise ValidationError(req, f"Missing required evidence field: '{req}'", None)

        return cls(
            agent_id=data.get("agent_id", "A2"),
            flow_id=data["flow_id"],
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            anomaly_detection=data["anomaly_detection"],
            threat_intelligence=data.get("threat_intelligence", ThreatIntelligenceResult()),
            metadata=data.get("metadata", {}),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "Agent2Evidence":
        """Instantiate Agent2Evidence from a JSON string."""
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as err:
            raise ValidationError("json", f"Malformed JSON string: {err}", json_str)
        return cls.from_dict(data)

