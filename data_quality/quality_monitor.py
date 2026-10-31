"""Sensor & Data Quality Health Monitor for CyberSentinel / Dark-Trace-AI.

Feature E: Implements the DataQualityMonitor class providing deterministic,
modular telemetry health assessment, duplicate tracking, timestamp verification,
and reference distribution drift detection.
"""

import math
from typing import Any, Dict, List, Optional, Set, Tuple, Union

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

from .quality_report import (
    BatchQualityReport,
    FlowQualityReport,
    QualityRecommendation,
    QualityStatus,
)
from .validators import (
    DEFAULT_NUMERIC_CONSTRAINTS,
    detect_distribution_drift,
    extract_and_validate_timestamp,
    extract_flow_id,
    validate_flow_id,
    validate_missing_and_nulls,
    validate_nan_and_inf,
    validate_types_and_ranges,
)


class DataQualityMonitor:
    """Sensor and Data Quality Monitor for network flow telemetry.

    Evaluates network telemetry against data integrity standards before
    downstream consumption by threat detection models (Agent 1/2).

    Downstream Rules:
    - Deterministic, documented scoring (0.0 to 100.0).
    - Preserves original flow metadata and identifiers.
    - Never silently replaces invalid/missing values with zero.
    - Never classifies poor-quality data as BENIGN.
    - Flags critical quality degradation for human review or drop.
    """

    def __init__(
        self,
        baseline_stats: Optional[Dict[str, Dict[str, float]]] = None,
        expected_features: Optional[List[str]] = None,
        numeric_constraints: Optional[Dict[str, Tuple[Optional[float], Optional[float]]]] = None,
        drift_threshold: float = 3.0,
        track_history: bool = True
    ) -> None:
        """Initialize DataQualityMonitor.

        Args:
            baseline_stats: Optional dictionary of reference feature statistics
                            e.g. {"Flow Duration": {"mean": 500.0, "std": 100.0}}.
                            If None, distribution drift is NOT evaluated (no drift invented).
            expected_features: List of required feature column names (e.g. 78 CICIDS features).
            numeric_constraints: Custom boundary constraints per feature name.
            drift_threshold: Z-score divergence threshold for flagging feature drift.
            track_history: If True, caches seen flow IDs across invocations to detect duplicates.
        """
        self.baseline_stats: Optional[Dict[str, Dict[str, float]]] = baseline_stats
        self.expected_features: Optional[List[str]] = expected_features
        self.numeric_constraints = numeric_constraints or DEFAULT_NUMERIC_CONSTRAINTS
        self.drift_threshold = drift_threshold
        self.track_history = track_history
        self._seen_flow_ids: Set[Any] = set()

    def set_baseline(self, baseline_stats: Dict[str, Dict[str, float]]) -> None:
        """Set or update reference baseline statistics for drift detection."""
        self.baseline_stats = baseline_stats

    def clear_baseline(self) -> None:
        """Clear baseline statistics (disables drift detection)."""
        self.baseline_stats = None

    def reset_history(self) -> None:
        """Clear the historical set of seen flow IDs."""
        self._seen_flow_ids.clear()

    @property
    def seen_flow_count(self) -> int:
        """Return the count of unique historical flow IDs tracked."""
        return len(self._seen_flow_ids)

    def calculate_quality_score(
        self,
        missing_fields: List[str],
        invalid_fields: List[str],
        duplicate_flow_id: bool,
        timestamp_valid: Optional[bool],
        type_range_issues: List[str],
        total_attributes: int,
        drift_detected: Optional[bool] = None
    ) -> Tuple[float, QualityStatus, str, bool]:
        """Compute deterministic quality score, status, recommendation, and downstream safety flag.

        Scoring Model:
        - Base Score: 100.0
        - Penalties:
          1. Missing/Null values: Up to -40.0 pts proportional to missing ratio.
          2. NaN / Infinite values: Up to -40.0 pts proportional to invalid ratio.
          3. Domain/Type Violations: -10.0 pts per violation, capped at -30.0 pts.
          4. Duplicate Flow ID: -40.0 pts (automatically prevents HEALTHY status).
          5. Corrupt Timestamp (where provided): -15.0 pts (0 if timestamp not in schema).
          6. Distribution Drift (where baseline provided): -15.0 pts (0 if no baseline).
        - Clamped between 0.0 and 100.0.

        Status Thresholds:
        - HEALTHY: score >= 85.0 and no duplicate and no invalid fields and timestamp_valid is not False.
        - WARNING: 50.0 <= score < 85.0 and not CRITICAL.
        - CRITICAL: score < 50.0 or duplicate with errors or >30% invalid fields.

        Returns:
            (quality_score, status, recommendation, is_safe_downstream)
        """
        score = 100.0
        n_features = max(1, total_attributes)

        # 1. Missing fields deduction
        if missing_fields:
            missing_ratio = min(1.0, len(missing_fields) / n_features)
            score -= missing_ratio * 40.0

        # 2. NaN / Inf deduction
        if invalid_fields:
            invalid_ratio = min(1.0, len(invalid_fields) / n_features)
            score -= invalid_ratio * 40.0

        # 3. Domain range / type violations
        if type_range_issues:
            range_penalty = min(30.0, len(type_range_issues) * 10.0)
            score -= range_penalty

        # 4. Duplicate flow ID deduction
        if duplicate_flow_id:
            score -= 40.0

        # 5. Invalid timestamp deduction (only when provided and invalid)
        if timestamp_valid is False:
            score -= 15.0

        # 6. Distribution drift deduction (only when baseline supplied)
        if drift_detected is True:
            score -= 15.0

        # Clamp score
        final_score = round(max(0.0, min(100.0, score)), 2)

        # Determine status
        is_critical_error = (
            final_score < 50.0
            or (duplicate_flow_id and (len(missing_fields) > 0 or len(invalid_fields) > 0))
            or (len(invalid_fields) + len(missing_fields)) > (n_features * 0.35)
        )

        if is_critical_error:
            status = QualityStatus.CRITICAL
            recommendation = QualityRecommendation.DROP_DO_NOT_PROCESS.value
            is_safe_downstream = False
        elif (
            final_score >= 85.0
            and not duplicate_flow_id
            and len(invalid_fields) == 0
            and timestamp_valid is not False
        ):
            status = QualityStatus.HEALTHY
            recommendation = QualityRecommendation.ALLOW_PASS.value
            is_safe_downstream = True
        else:
            status = QualityStatus.WARNING
            recommendation = QualityRecommendation.INSPECT_WITH_WARNINGS.value
            # Safe for downstream with warnings if no duplicate and no NaN/Inf in active features
            is_safe_downstream = not duplicate_flow_id and len(invalid_fields) == 0

        return final_score, status, recommendation, is_safe_downstream

    def validate_flow(
        self,
        flow: Union[Dict[str, Any], Any],
        batch_seen_ids: Optional[Set[Any]] = None,
        index_hint: Optional[int] = None
    ) -> Tuple[Dict[str, Any], FlowQualityReport, bool]:
        """Validate an individual network flow record.

        Args:
            flow: Dictionary, pandas Series, or compatible flow record.
            batch_seen_ids: Optional set of IDs seen within the enclosing batch.
            index_hint: Optional sequential index used if record has no flow_id.

        Returns:
            (validated_data, report, is_safe_downstream)
        """
        # Handle malformed or empty flow input safely
        if flow is None:
            report = FlowQualityReport(
                flow_id="UNKNOWN_NULL_FLOW",
                quality_score=0.0,
                quality_status=QualityStatus.CRITICAL.value,
                issues=["Flow input is None or completely unallocated"],
                recommendation=QualityRecommendation.DROP_DO_NOT_PROCESS.value,
                is_safe_downstream=False
            )
            return {}, report, False

        # Convert pandas Series to dict if necessary
        if hasattr(flow, "to_dict"):
            record_dict = flow.to_dict()
        elif isinstance(flow, dict):
            record_dict = dict(flow)
        else:
            report = FlowQualityReport(
                flow_id=f"UNKNOWN_MALFORMED_{index_hint if index_hint is not None else 0}",
                quality_score=0.0,
                quality_status=QualityStatus.CRITICAL.value,
                issues=[f"Input of unexpected type '{type(flow).__name__}', expected dict or Series"],
                recommendation=QualityRecommendation.DROP_DO_NOT_PROCESS.value,
                is_safe_downstream=False
            )
            return {}, report, False

        if not record_dict:
            report = FlowQualityReport(
                flow_id=f"EMPTY_FLOW_{index_hint if index_hint is not None else 0}",
                quality_score=0.0,
                quality_status=QualityStatus.CRITICAL.value,
                issues=["Flow record dictionary is empty"],
                recommendation=QualityRecommendation.DROP_DO_NOT_PROCESS.value,
                is_safe_downstream=False
            )
            return {}, report, False

        # 1. Flow ID extraction & duplicate validation
        default_id = f"flow_{index_hint}" if index_hint is not None else "unspecified_id"
        flow_id = extract_flow_id(record_dict, default=default_id)

        all_seen = set()
        if batch_seen_ids is not None:
            all_seen.update(batch_seen_ids)
        if self.track_history:
            all_seen.update(self._seen_flow_ids)

        is_dup, dup_issue = validate_flow_id(flow_id, all_seen)

        issues: List[str] = []
        if is_dup and dup_issue:
            issues.append(dup_issue)

        # 2. Missing & Null values
        missing_fields, missing_issues = validate_missing_and_nulls(
            record_dict,
            required_fields=self.expected_features
        )
        issues.extend(missing_issues)

        # 3. NaN and Infinity validation
        invalid_nan_inf, nan_inf_issues = validate_nan_and_inf(
            record_dict,
            feature_fields=self.expected_features
        )
        issues.extend(nan_inf_issues)

        # 4. Unexpected types & domain range validation
        invalid_ranges, range_issues = validate_types_and_ranges(
            record_dict,
            constraints=self.numeric_constraints,
            expected_numeric_fields=self.expected_features
        )
        issues.extend(range_issues)

        invalid_fields = list(dict.fromkeys(invalid_nan_inf + invalid_ranges))

        # 5. Timestamp validation (where timestamps are provided)
        ts_valid, ts_issue = extract_and_validate_timestamp(record_dict)
        if ts_issue:
            issues.append(ts_issue)

        # 6. Drift evaluation: not applicable on individual row without batch context
        drift_detected = None

        # 7. Quality score calculation
        total_attribs = len(self.expected_features) if self.expected_features else len(record_dict)
        score, status, recommendation, is_safe = self.calculate_quality_score(
            missing_fields=missing_fields,
            invalid_fields=invalid_fields,
            duplicate_flow_id=is_dup,
            timestamp_valid=ts_valid,
            type_range_issues=range_issues,
            total_attributes=total_attribs,
            drift_detected=drift_detected
        )

        # Update historical seen flow IDs
        if flow_id and flow_id != default_id:
            if batch_seen_ids is not None:
                batch_seen_ids.add(flow_id)
            if self.track_history:
                self._seen_flow_ids.add(flow_id)

        report = FlowQualityReport(
            flow_id=flow_id,
            quality_score=score,
            quality_status=status.value,
            issues=issues,
            missing_fields=missing_fields,
            invalid_fields=invalid_fields,
            duplicate_flow_id=is_dup,
            timestamp_valid=ts_valid,
            drift_detected=drift_detected,
            recommendation=recommendation,
            is_safe_downstream=is_safe,
            metadata={"original_keys_count": len(record_dict)}
        )

        # Return validated data preserving all original metadata
        # (NEVER replacing invalid values with 0 or classifying as BENIGN)
        return record_dict, report, is_safe

    def validate_batch(
        self,
        flows: Union[Any, List[Dict[str, Any]]],
    ) -> Tuple[Union[Any, List[Dict[str, Any]]], BatchQualityReport, List[FlowQualityReport]]:
        """Validate a batch of network flows (DataFrame or list of dictionaries).

        Performs:
        - Row-by-row data quality assessment.
        - Batch-internal and cross-batch duplicate detection.
        - Distribution drift detection if baseline_stats is provided.
        - Clean downstream filtering (safe flows vs flagged flows).

        Args:
            flows: pandas DataFrame or list of flow dictionaries.

        Returns:
            (safe_flows, batch_report, individual_reports)
        """
        # Handle empty or malformed inputs
        if flows is None:
            empty_report = BatchQualityReport()
            return ([] if not HAS_PANDAS else pd.DataFrame()), empty_report, []

        is_dataframe = HAS_PANDAS and isinstance(flows, pd.DataFrame)
        if is_dataframe:
            if flows.empty:
                return flows.copy(), BatchQualityReport(), []
            records_list = flows.to_dict(orient="records")
        elif isinstance(flows, list):
            if not flows:
                return [], BatchQualityReport(), []
            records_list = flows
        else:
            # Single object or unrecognized batch container
            single_clean, single_rep, single_safe = self.validate_flow(flows)
            batch_rep = BatchQualityReport(
                total_flows=1,
                healthy_count=1 if single_rep.is_healthy else 0,
                warning_count=1 if single_rep.quality_status == QualityStatus.WARNING.value else 0,
                critical_count=1 if single_rep.is_critical else 0,
                safe_count=1 if single_safe else 0,
                average_quality_score=single_rep.quality_score,
                duplicate_count=1 if single_rep.duplicate_flow_id else 0,
                drift_detected=None,
                flow_reports=[single_rep]
            )
            return ([single_clean] if single_safe else []), batch_rep, [single_rep]

        # 1. Evaluate individual flows and track batch-internal duplicates
        batch_seen_ids: Set[Any] = set()
        individual_reports: List[FlowQualityReport] = []
        safe_indices: List[int] = []
        safe_records: List[Dict[str, Any]] = []

        # Feature accumulator for drift detection
        feature_columns_data: Dict[str, List[float]] = {}

        for idx, row in enumerate(records_list):
            clean_record, rep, is_safe = self.validate_flow(
                row,
                batch_seen_ids=batch_seen_ids,
                index_hint=idx
            )
            individual_reports.append(rep)

            if is_safe:
                safe_indices.append(idx)
                safe_records.append(clean_record)

            # Accumulate numeric features for drift analysis
            if isinstance(clean_record, dict):
                for k, v in clean_record.items():
                    if isinstance(v, (int, float)) and not isinstance(v, bool):
                        if not math.isnan(v) and not math.isinf(v):
                            feature_columns_data.setdefault(k, []).append(float(v))

        # 2. Evaluate Distribution Drift (ONLY if baseline_stats is provided)
        # "Do not invent a baseline or report drift when no baseline exists."
        drift_detected, drift_scores, drifted_features = detect_distribution_drift(
            batch_features=feature_columns_data,
            baseline_stats=self.baseline_stats,
            drift_threshold=self.drift_threshold
        )

        # If drift detected across batch, update individual reports with drift status
        if drift_detected is not None:
            for rep in individual_reports:
                rep.drift_detected = drift_detected
                if drift_detected:
                    rep.issues.append(
                        f"Distribution drift detected in features: {', '.join(drifted_features[:5])}"
                    )
                    # Deduct score if drift detected
                    rep.quality_score = max(0.0, round(rep.quality_score - 15.0, 2))
                    if rep.quality_status == QualityStatus.HEALTHY.value:
                        rep.quality_status = QualityStatus.WARNING.value
                        rep.recommendation = QualityRecommendation.INSPECT_WITH_WARNINGS.value

        # 3. Aggregate Batch Metrics
        total_flows = len(individual_reports)
        healthy_count = sum(1 for r in individual_reports if r.quality_status == QualityStatus.HEALTHY.value)
        warning_count = sum(1 for r in individual_reports if r.quality_status == QualityStatus.WARNING.value)
        critical_count = sum(1 for r in individual_reports if r.quality_status == QualityStatus.CRITICAL.value)
        dup_count = sum(1 for r in individual_reports if r.duplicate_flow_id)
        avg_score = sum(r.quality_score for r in individual_reports) / total_flows if total_flows > 0 else 0.0

        batch_report = BatchQualityReport(
            total_flows=total_flows,
            healthy_count=healthy_count,
            warning_count=warning_count,
            critical_count=critical_count,
            safe_count=len(safe_indices),
            average_quality_score=round(avg_score, 2),
            duplicate_count=dup_count,
            drift_detected=drift_detected,
            drift_details={
                "drift_scores": drift_scores,
                "drifted_features": drifted_features
            } if drift_scores else None,
            flow_reports=individual_reports
        )

        # 4. Construct safe flows downstream payload
        if is_dataframe:
            safe_flows_output = flows.iloc[safe_indices].copy() if safe_indices else flows.iloc[0:0].copy()
        else:
            safe_flows_output = safe_records

        return safe_flows_output, batch_report, individual_reports

