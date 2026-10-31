"""Reliable CSV Export Layer for CyberSentinel Hackathon Deliverables.

Exports:
  1. classification.csv:
     - Columns: record_id,predicted_class,anomaly_score,evidence_status
     - Exactly one row per test record.
     - Supported 5 classes: BENIGN, DOS, DDOS, PORT_SCAN, BRUTE_FORCE.
     - Strictly no actual/ground-truth labels.
  2. policies.csv (and policy.csv):
     - Columns: policy_id,activated_after_record_id,scope_type,scope_value,expires_after_record_id
     - Optional policy_action column included for policy.csv format.
     - One row per activated policy.
  3. replay.csv:
     - Columns: record_id,action,active_policy_id (with applied_policy_id compatibility)
     - Preserves organizer chronological order.
     - ALLOW has empty policy ID; BLOCK references valid active policy.
"""

from __future__ import annotations

import csv
import io
import os
from typing import Any, Dict, List, Optional, Sequence


# Canonical 5 classes required by evaluation
CANONICAL_5_CLASSES = {
    "BENIGN": "BENIGN",
    "DOS": "DOS",
    "DDOS": "DDOS",
    "PORT_SCAN": "PORT_SCAN",
    "PORT SCAN": "PORT_SCAN",
    "BRUTE_FORCE": "BRUTE_FORCE",
    "BRUTE FORCE": "BRUTE_FORCE",
}


def normalize_class_name(raw_name: Any) -> str:
    """Normalize class name into the organizer-supported 5-class contract."""
    clean = str(raw_name or "BENIGN").strip().upper().replace(" ", "_")
    return CANONICAL_5_CLASSES.get(clean, "BENIGN")


def export_classification_csv(
    records: Sequence[Dict[str, Any]],
    output_path: str,
) -> str:
    """Export classification predictions to CSV.

    Columns: record_id,predicted_class,anomaly_score,evidence_status
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    fieldnames = ["record_id", "predicted_class", "anomaly_score", "evidence_status"]

    with open(output_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            pred_class = normalize_class_name(r.get("predicted_class"))
            try:
                score = round(float(r.get("anomaly_score", 0.0)), 4)
            except (ValueError, TypeError):
                score = 0.0
            ev_status = str(r.get("evidence_status", "INSUFFICIENT_EVIDENCE")).upper()

            writer.writerow({
                "record_id": str(r["record_id"]),
                "predicted_class": pred_class,
                "anomaly_score": f"{score:.4f}",
                "evidence_status": ev_status,
            })

    return os.path.abspath(output_path)


def export_policies_csv(
    policies: Sequence[Any],
    output_path: str,
    include_action_column: bool = False,
) -> str:
    """Export activated defense policies to CSV.

    Columns:
      If include_action_column:
        policy_id,activated_after_record_id,scope_type,scope_value,expires_after_record_id,policy_action
      Else (default organizer template):
        policy_id,activated_after_record_id,scope_type,scope_value,expires_after_record_id
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    if include_action_column:
        fieldnames = [
            "policy_id",
            "activated_after_record_id",
            "scope_type",
            "scope_value",
            "expires_after_record_id",
            "policy_action",
        ]
    else:
        fieldnames = [
            "policy_id",
            "activated_after_record_id",
            "scope_type",
            "scope_value",
            "expires_after_record_id",
        ]

    with open(output_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for p in policies:
            p_dict = p.to_dict() if hasattr(p, "to_dict") else dict(p)
            row = {
                "policy_id": str(p_dict.get("policy_id", "")),
                "activated_after_record_id": str(p_dict.get("activated_after_record_id", "")),
                "scope_type": str(p_dict.get("scope_type", "SOURCE_IP")),
                "scope_value": str(p_dict.get("scope_value", "")),
                "expires_after_record_id": str(p_dict.get("expires_after_record_id", "")),
            }
            if include_action_column:
                row["policy_action"] = str(p_dict.get("policy_action", "BLOCK"))
            writer.writerow(row)

    return os.path.abspath(output_path)


def export_replay_csv(
    decisions: Sequence[Any],
    output_path: str,
    policy_id_column_name: str = "active_policy_id",
) -> str:
    """Export replay decisions to CSV.

    Columns: record_id,action,{policy_id_column_name}
    Default organizer template uses 'active_policy_id'.
    'applied_policy_id' is also supported via argument.
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    fieldnames = ["record_id", "action", policy_id_column_name]

    with open(output_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for d in decisions:
            d_dict = d.to_dict() if hasattr(d, "to_dict") else dict(d)
            act = str(d_dict.get("action", "ALLOW")).upper()
            pol_id = str(d_dict.get("applied_policy_id") or d_dict.get("active_policy_id") or "")
            if act == "ALLOW":
                pol_id = ""

            writer.writerow({
                "record_id": str(d_dict["record_id"]),
                "action": act,
                policy_id_column_name: pol_id,
            })

    return os.path.abspath(output_path)
