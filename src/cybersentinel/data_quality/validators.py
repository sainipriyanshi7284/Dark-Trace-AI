"""Validation Rules and Data Integrity Checkers for CyberSentinel.

Provides modular, deterministic validators for inspecting network flow
telemetry, timestamps, numeric constraints, duplicate identifiers, and
reference distribution drift.
"""

import math
import numbers
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple, Union


# Standard network domain constraints for CICIDS2017 / NDR telemetry
DEFAULT_NUMERIC_CONSTRAINTS: Dict[str, Tuple[Optional[float], Optional[float]]] = {
    "Destination Port": (0, 65535),
    "Flow Duration": (0, None),
    "Total Fwd Packets": (0, None),
    "Total Backward Packets": (0, None),
    "Total Length of Fwd Packets": (0, None),
    "Total Length of Bwd Packets": (0, None),
    "Fwd Packet Length Min": (0, None),
    "Bwd Packet Length Min": (0, None),
    "Min Packet Length": (0, None),
    "Down/Up Ratio": (0, None),
    "Init_Win_bytes_forward": (0, 65535),
    "Init_Win_bytes_backward": (0, 65535),
}

TIMESTAMP_CANDIDATE_KEYS = (
    "timestamp",
    "Timestamp",
    "time",
    "flow_timestamp",
    "start_time",
    "record_timestamp"
)

FLOW_ID_CANDIDATE_KEYS = (
    "flow_id",
    "record_id",
    "id",
    "Flow ID",
    "Flow_ID"
)


def extract_flow_id(record: Dict[str, Any], default: Optional[str] = None) -> Any:
    """Extract flow identifier from record using standard DarkTrace/CICIDS keys."""
    for key in FLOW_ID_CANDIDATE_KEYS:
        if key in record and record[key] is not None:
            return record[key]
    return default


def is_null_or_empty(val: Any) -> bool:
    """Check if value is None, empty string, or pandas/numpy null representation."""
    if val is None:
        return True
    if isinstance(val, str) and val.strip() == "":
        return True
    # Handle pandas / numpy NA without hard dependency if not installed
    val_str = str(val)
    if val_str in ("<NA>", "nan", "None", "NaT"):
        return True
    return False


def is_nan_or_infinite(val: Any) -> Tuple[bool, bool]:
    """Check if a numeric value is NaN or Infinite.

    Returns:
        (is_nan, is_inf)
    """
    if isinstance(val, numbers.Number) and not isinstance(val, bool):
        try:
            val_float = float(val)
            if math.isnan(val_float):
                return True, False
            if math.isinf(val_float):
                return False, True
        except (ValueError, TypeError, OverflowError):
            return False, False
    return False, False


def validate_flow_id(
    flow_id: Any,
    seen_ids: Optional[Set[Any]] = None
) -> Tuple[bool, Optional[str]]:
    """Validate presence and uniqueness of a flow identifier.

    Args:
        flow_id: Extracted identifier.
        seen_ids: Set of identifiers observed in current batch or session history.

    Returns:
        (is_duplicate, error_message)
    """
    if flow_id is None or (isinstance(flow_id, str) and flow_id.strip() == ""):
        return False, "Missing or empty flow_id"

    if seen_ids is not None:
        if flow_id in seen_ids:
            return True, f"Duplicate flow_id detected: '{flow_id}'"

    return False, None


def validate_missing_and_nulls(
    record: Dict[str, Any],
    required_fields: Optional[List[str]] = None
) -> Tuple[List[str], List[str]]:
    """Check for missing required fields and null/empty attributes.

    Returns:
        (missing_fields, issues)
    """
    missing_fields: List[str] = []
    issues: List[str] = []

    # Check mandatory fields existence
    if required_fields:
        for field in required_fields:
            if field not in record or is_null_or_empty(record[field]):
                missing_fields.append(field)
                issues.append(f"Required field '{field}' is missing or null")

    # Check all fields for null/empty values
    for k, v in record.items():
        if k not in missing_fields and is_null_or_empty(v):
            missing_fields.append(k)
            issues.append(f"Field '{k}' has null or empty value")

    return missing_fields, issues


def validate_nan_and_inf(
    record: Dict[str, Any],
    feature_fields: Optional[List[str]] = None
) -> Tuple[List[str], List[str]]:
    """Detect NaN and +/- Infinite values in numerical attributes.

    Returns:
        (invalid_fields, issues)
    """
    invalid_fields: List[str] = []
    issues: List[str] = []
    keys_to_check = feature_fields if feature_fields is not None else list(record.keys())

    for key in keys_to_check:
        if key not in record:
            continue
        val = record[key]
        is_nan, is_inf = is_nan_or_infinite(val)
        if is_nan:
            invalid_fields.append(key)
            issues.append(f"Field '{key}' has NaN value")
        elif is_inf:
            invalid_fields.append(key)
            issues.append(f"Field '{key}' has Infinite value ({val})")

    return invalid_fields, issues


def validate_types_and_ranges(
    record: Dict[str, Any],
    constraints: Optional[Dict[str, Tuple[Optional[float], Optional[float]]]] = None,
    expected_numeric_fields: Optional[List[str]] = None
) -> Tuple[List[str], List[str]]:
    """Validate data types and domain boundary constraints.

    Returns:
        (invalid_fields, issues)
    """
    invalid_fields: List[str] = []
    issues: List[str] = []
    effective_constraints = constraints if constraints is not None else DEFAULT_NUMERIC_CONSTRAINTS

    # 1. Type validation for expected numeric columns
    if expected_numeric_fields:
        for field in expected_numeric_fields:
            if field in record and not is_null_or_empty(record[field]):
                val = record[field]
                is_nan, is_inf = is_nan_or_infinite(val)
                if not is_nan and not is_inf:
                    if not isinstance(val, (numbers.Number, float, int)) or isinstance(val, bool):
                        # Try parsing as float
                        try:
                            float(val)
                        except (ValueError, TypeError):
                            invalid_fields.append(field)
                            issues.append(
                                f"Field '{field}' has unexpected type '{type(val).__name__}' (expected numeric)"
                            )

    # 2. Domain boundary constraints (e.g. non-negative packets, valid ports)
    for field, (min_val, max_val) in effective_constraints.items():
        if field in record and not is_null_or_empty(record[field]):
            val = record[field]
            try:
                num_val = float(val)
                if not math.isnan(num_val) and not math.isinf(num_val):
                    if min_val is not None and num_val < min_val:
                        invalid_fields.append(field)
                        issues.append(
                            f"Field '{field}' value {num_val} violates lower bound ({min_val})"
                        )
                    elif max_val is not None and num_val > max_val:
                        invalid_fields.append(field)
                        issues.append(
                            f"Field '{field}' value {num_val} violates upper bound ({max_val})"
                        )
            except (ValueError, TypeError):
                # Type error already captured or non-parseable
                pass

    return list(dict.fromkeys(invalid_fields)), issues


def validate_timestamp(timestamp_val: Any) -> Tuple[Optional[bool], Optional[str]]:
    """Validate timestamp where timestamps are provided.

    Args:
        timestamp_val: Timestamp value (ISO string, epoch int/float, datetime, or None).

    Returns:
        (timestamp_valid, issue_or_none)
        - (None, None): If timestamp is absent or not provided.
        - (True, None): If timestamp is valid and parseable.
        - (False, reason): If timestamp is present but invalid/corrupt.
    """
    if timestamp_val is None or (isinstance(timestamp_val, str) and timestamp_val.strip() == ""):
        return None, None

    # Datetime object
    if isinstance(timestamp_val, datetime):
        if timestamp_val.year < 1970 or timestamp_val.year > 2100:
            return False, f"Timestamp year out of plausible range (1970-2100): {timestamp_val.year}"
        return True, None

    # Numeric epoch (seconds or milliseconds)
    if isinstance(timestamp_val, (int, float)) and not isinstance(timestamp_val, bool):
        if timestamp_val < 0:
            return False, f"Timestamp epoch cannot be negative ({timestamp_val})"
        # Check plausible epoch bounds (0 to year 2100 in sec or ms)
        if timestamp_val > 4102444800000:  # > year 2100 in ms
            return False, f"Timestamp epoch exceeds year 2100 bounds ({timestamp_val})"
        return True, None

    # String representation
    if isinstance(timestamp_val, str):
        cleaned = timestamp_val.strip()
        # Check numeric epoch as string
        try:
            num = float(cleaned)
            return validate_timestamp(num)
        except ValueError:
            pass

        # Try standard ISO and common cybersecurity datetime formats
        formats_to_try = [
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%d/%m/%Y %H:%M:%S",
            "%d/%m/%Y %H:%M",
            "%m/%d/%Y %I:%M:%S %p",
        ]
        # Python 3.11+ fromisoformat handles standard ISO strings
        try:
            parsed = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
            if parsed.year < 1970 or parsed.year > 2100:
                return False, f"Timestamp year out of range: {parsed.year}"
            return True, None
        except (ValueError, TypeError):
            pass

        for fmt in formats_to_try:
            try:
                parsed = datetime.strptime(cleaned, fmt)
                if parsed.year < 1970 or parsed.year > 2100:
                    return False, f"Timestamp year out of range: {parsed.year}"
                return True, None
            except ValueError:
                continue

        return False, f"Unparseable timestamp string: '{timestamp_val}'"

    return False, f"Invalid timestamp type '{type(timestamp_val).__name__}'"


def extract_and_validate_timestamp(record: Dict[str, Any]) -> Tuple[Optional[bool], Optional[str]]:
    """Locate candidate timestamp in record and validate if present."""
    for key in TIMESTAMP_CANDIDATE_KEYS:
        if key in record:
            val = record[key]
            if val is not None and not (isinstance(val, str) and val.strip() == ""):
                return validate_timestamp(val)
            else:
                # Field key is explicitly present in schema but value is empty/null
                return False, f"Timestamp field '{key}' is present but empty or null"
    # No timestamp field provided in this schema
    return None, None


def detect_distribution_drift(
    batch_features: Dict[str, List[float]],
    baseline_stats: Optional[Dict[str, Dict[str, float]]],
    drift_threshold: float = 3.0
) -> Tuple[Optional[bool], Optional[Dict[str, float]], List[str]]:
    """Detect statistical distribution drift when a reference baseline is supplied.

    Important:
        When baseline_stats is None or empty, returns (None, None, [])
        per rule: "Do not invent a baseline or report drift when no baseline exists."

    Args:
        batch_features: Dictionary of feature_name -> list of numeric values.
        baseline_stats: Dictionary containing reference stats per feature:
                        e.g. {"Flow Duration": {"mean": 500.0, "std": 100.0}}
        drift_threshold: Number of standard deviations / z-divergence before flagging drift.

    Returns:
        (drift_detected, drift_scores, drifted_features)
    """
    if baseline_stats is None or len(baseline_stats) == 0:
        return None, None, []

    drift_scores: Dict[str, float] = {}
    drifted_features: List[str] = []

    for feature, values in batch_features.items():
        if feature not in baseline_stats:
            continue

        clean_vals = [
            float(v) for v in values
            if isinstance(v, (int, float)) and not math.isnan(v) and not math.isinf(v)
        ]
        if len(clean_vals) < 3:
            continue

        ref_mean = baseline_stats[feature].get("mean")
        ref_std = baseline_stats[feature].get("std", 1.0)

        if ref_mean is None or ref_std is None or ref_std <= 0:
            continue

        batch_mean = sum(clean_vals) / len(clean_vals)
        z_score = abs(batch_mean - ref_mean) / ref_std
        drift_scores[feature] = round(z_score, 4)

        if z_score >= drift_threshold:
            drifted_features.append(feature)

    is_drifted = len(drifted_features) > 0
    return is_drifted, drift_scores, drifted_features

