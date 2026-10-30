"""Anomaly scoring, calibration, and severity interpretation utilities.

This module governs score semantics for Agent 2:
1. `raw_anomaly_score`: Direct scikit-learn `decision_function(X)` output.
   - Negative values indicate anomalous samples under the fitted threshold (default 0.0).
   - Positive values indicate standard inlier samples.
2. `normalized_anomaly_score`: A bounded outlier severity index in [0.0, 1.0].
   - 0.0: High normal inlier (well within training distribution).
   - 1.0: Severe outlier (far outside training reference distribution).
   - CRITICAL CYBERSECURITY RULE: This score represents statistical deviation severity,
     NOT a calibrated posterior probability of attack or a "confidence percentage".
3. `anomaly_label`: Categorical designation ("ANOMALOUS" vs "NORMAL").
"""

from typing import Any, Dict, Optional


def compute_normalized_anomaly_score(
    raw_score: float,
    training_score_stats: Optional[Dict[str, float]] = None,
    raw_threshold: float = 0.0,
) -> float:
    """Transform a raw Isolation Forest decision score into a [0.0, 1.0] severity index.

    The transformation is monotonic:
    - Lower (more negative) raw scores yield higher normalized severity scores.
    - If raw_score <= threshold, severity is in range [0.5, 1.0].
    - If raw_score > threshold, severity is in range [0.0, 0.5).

    Args:
        raw_score: Output of IsolationForest.decision_function(X).
        training_score_stats: Optional baseline score statistics from ModelTrainer
            containing 'min_score', 'median_score', and 'max_score'.
        raw_threshold: Decision boundary (default 0.0 in scikit-learn).

    Returns:
        float: Bounded outlier severity index in [0.0, 1.0].
    """
    if training_score_stats and "min_score" in training_score_stats:
        min_score = training_score_stats.get("min_score", -0.5)
        max_score = training_score_stats.get("max_score", 0.5)

        # Ensure non-zero denominator
        score_span = max(1e-6, max_score - min_score)

        # Invert score so that lower raw score -> higher severity
        # raw_score == min_score -> 1.0 (most severe outlier)
        # raw_score == max_score -> 0.0 (most typical inlier)
        severity = (max_score - raw_score) / score_span
    else:
        # Default piecewise linear mapping around threshold 0.0
        # Typical decision_function values range from roughly -0.5 to +0.5
        if raw_score <= raw_threshold:
            # Anomalous region: maps [-0.5, 0.0] -> [1.0, 0.5]
            # If raw_score < -0.5, capped at 1.0
            severity = 0.5 + min(0.5, max(0.0, -raw_score))
        else:
            # Normal region: maps (0.0, 0.5] -> [0.5, 0.0]
            # If raw_score > 0.5, capped at 0.0
            severity = 0.5 - min(0.5, max(0.0, raw_score))

    # Strict clamping to [0.0, 1.0]
    return float(max(0.0, min(1.0, severity)))


def interpret_anomaly_label(
    is_anomaly: bool,
) -> str:
    """Return standard string label for anomaly status.

    Args:
        is_anomaly: True if the sample is detected as an anomaly.

    Returns:
        "ANOMALOUS" if is_anomaly else "NORMAL"
    """
    return "ANOMALOUS" if is_anomaly else "NORMAL"

