"""Quality Report Data Structures for CyberSentinel / Dark-Trace-AI.

Defines standardized data classes and enums for individual flow quality
reports and batch-level quality summaries.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class QualityStatus(str, Enum):
    """Enumeration of quality health statuses."""
    HEALTHY = "HEALTHY"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class QualityRecommendation(str, Enum):
    """Standardized operational recommendations for downstream pipeline."""
    ALLOW_PASS = "ALLOW_PASS_DOWNSTREAM"
    INSPECT_WITH_WARNINGS = "INSPECT_WITH_WARNINGS"
    DROP_DO_NOT_PROCESS = "DROP_DO_NOT_PROCESS"
    QUARANTINE_FOR_REVIEW = "QUARANTINE_FOR_HUMAN_REVIEW"


@dataclass
class FlowQualityReport:
    """Structured quality assessment report for an individual network flow.

    Attributes:
        flow_id: Identifier of the flow (e.g. record_id or generated UUID).
        quality_score: Deterministic health score from 0.0 (unusable) to 100.0 (pristine).
        quality_status: Operational tier (HEALTHY, WARNING, CRITICAL).
        issues: Human-readable list of all identified anomalies or rule violations.
        missing_fields: List of attribute names with null, missing, or empty values.
        invalid_fields: List of attribute names containing NaN, Inf, wrong types, or out-of-range values.
        duplicate_flow_id: True if this flow_id was observed previously or duplicated in batch.
        timestamp_valid: True if valid, False if provided but corrupted/invalid, None if not provided.
        drift_detected: True if feature drift observed against baseline, False if checked and normal,
                        None if no reference baseline was supplied (not evaluated).
        recommendation: Downstream routing guidance string.
        is_safe_downstream: Boolean flag indicating if flow is safe for downstream model inference.
        metadata: Optional dictionary preserving arbitrary context (e.g. partition, interface).
    """
    flow_id: Any
    quality_score: float
    quality_status: str
    issues: List[str] = field(default_factory=list)
    missing_fields: List[str] = field(default_factory=list)
    invalid_fields: List[str] = field(default_factory=list)
    duplicate_flow_id: bool = False
    timestamp_valid: Optional[bool] = None
    drift_detected: Optional[bool] = None
    recommendation: str = QualityRecommendation.ALLOW_PASS.value
    is_safe_downstream: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary representation."""
        return asdict(self)

    @property
    def is_healthy(self) -> bool:
        """Return True if status is HEALTHY."""
        return self.quality_status == QualityStatus.HEALTHY.value

    @property
    def is_critical(self) -> bool:
        """Return True if status is CRITICAL."""
        return self.quality_status == QualityStatus.CRITICAL.value


@dataclass
class BatchQualityReport:
    """Aggregated quality report for a batch of network flows.

    Attributes:
        total_flows: Total count of inspected flows.
        healthy_count: Number of flows with HEALTHY status.
        warning_count: Number of flows with WARNING status.
        critical_count: Number of flows with CRITICAL status.
        safe_count: Number of flows safe to pass downstream.
        average_quality_score: Mean quality score across all flows in batch.
        duplicate_count: Total duplicate flow instances detected.
        drift_detected: Overall drift indicator across batch, or None if no baseline.
        drift_details: Detailed feature-level drift metrics, if evaluated.
        flow_reports: Individual FlowQualityReport objects for each flow.
    """
    total_flows: int = 0
    healthy_count: int = 0
    warning_count: int = 0
    critical_count: int = 0
    safe_count: int = 0
    average_quality_score: float = 0.0
    duplicate_count: int = 0
    drift_detected: Optional[bool] = None
    drift_details: Optional[Dict[str, Any]] = None
    flow_reports: List[FlowQualityReport] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert batch report to dictionary representation."""
        data = asdict(self)
        # Convert nested flow reports to list of dicts
        data["flow_reports"] = [r.to_dict() for r in self.flow_reports]
        return data

    def summary(self) -> Dict[str, Any]:
        """Return high-level summary metrics without individual flow records."""
        return {
            "total_flows": self.total_flows,
            "healthy_count": self.healthy_count,
            "warning_count": self.warning_count,
            "critical_count": self.critical_count,
            "safe_count": self.safe_count,
            "pass_rate_pct": round((self.safe_count / self.total_flows * 100.0), 2) if self.total_flows > 0 else 0.0,
            "average_quality_score": round(self.average_quality_score, 2),
            "duplicate_count": self.duplicate_count,
            "drift_detected": self.drift_detected
        }

