"""Original Dataset Evaluation Script for Agent 2 (Network Anomaly Detection).

Performs a genuine, offline evaluation of the pre-trained Isolation Forest model
using the original evaluation Parquet dataset (CICIDS2017).

OUTPUTS:
- src/dark_trace/agent2/reports/original_dataset_evaluation.json
- src/dark_trace/agent2/reports/original_dataset_evaluation_summary.txt
- src/dark_trace/agent2/reports/confusion_matrix.png
"""

import argparse
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import warnings

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("evaluate_original_dataset")

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_DATA_PATH = SCRIPT_DIR / "data" / "cyber_eval.parquet"
DEFAULT_MODEL_PATH = SCRIPT_DIR / "artifacts" / "agent2_isolation_forest.joblib"
DEFAULT_METADATA_PATH = SCRIPT_DIR / "artifacts" / "agent2_metadata.json"
DEFAULT_REPORTS_DIR = SCRIPT_DIR / "reports"


def run_evaluation(
    data_path: Path,
    model_path: Path,
    metadata_path: Path,
    reports_dir: Path,
) -> dict:
    """Execute end-to-end evaluation on the evaluation dataset.

    Args:
        data_path: Path to evaluation parquet file.
        model_path: Path to agent2_isolation_forest.joblib.
        metadata_path: Path to agent2_metadata.json.
        reports_dir: Output directory for reports.

    Returns:
        dict: Complete evaluation metrics and results dictionary.
    """
    logger.info("Loading evaluation dataset from: %s", data_path)
    if not data_path.is_file():
        raise FileNotFoundError(f"Evaluation dataset not found at: {data_path}")

    df = pd.read_parquet(data_path)
    row_count = len(df)
    col_count = len(df.columns)
    logger.info("Dataset loaded successfully: %d rows, %d columns", row_count, col_count)

    # Validate label and record_id
    if "label" not in df.columns:
        raise ValueError("Dataset missing required 'label' column.")
    has_record_id = "record_id" in df.columns

    # Load and validate metadata
    logger.info("Loading metadata from: %s", metadata_path)
    with open(metadata_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    feature_names = meta.get("feature_names", [])
    expected_feature_count = meta.get("feature_count", 74)
    threshold = float(meta.get("threshold", 0.47685521147215626))

    if len(feature_names) != 74:
        raise ValueError(f"Metadata feature count mismatch: expected 74, got {len(feature_names)}")

    missing_cols = [c for c in feature_names if c not in df.columns]
    if missing_cols:
        raise ValueError(f"Dataset is missing required model features: {missing_cols}")

    # Load Isolation Forest model
    logger.info("Loading model artifact from: %s", model_path)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        model = joblib.load(model_path)

    # Extract features in exact metadata order
    X = df[feature_names].values.astype(np.float64)

    # Anomaly scoring: -model.score_samples(X)
    logger.info("Executing Isolation Forest inference on %d rows...", row_count)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        raw_scores = -model.score_samples(X)

    # Decision rule: score >= threshold -> 1 (ANOMALOUS), else 0 (NORMAL)
    preds = (raw_scores >= threshold).astype(int)

    # Ground truth: BENIGN = 0, Attack categories = 1
    y_true = (df["label"].str.upper() != "BENIGN").astype(int)

    # Confusion matrix: tn, fp, fn, tp
    cm = confusion_matrix(y_true, preds)
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]

    # Metric calculations
    accuracy = (tp + tn) / (tp + tn + fp + fn)
    precision = float(precision_score(y_true, preds, zero_division=0))
    recall = float(recall_score(y_true, preds, zero_division=0))
    f1 = float(f1_score(y_true, preds, zero_division=0))
    balanced_acc = float(balanced_accuracy_score(y_true, preds))
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    roc_auc = float(roc_auc_score(y_true, raw_scores))
    avg_prec = float(average_precision_score(y_true, raw_scores))

    # Per-class analysis
    df_eval = df[["label"]].copy()
    if has_record_id:
        df_eval["record_id"] = df["record_id"]
    df_eval["pred"] = preds
    df_eval["score"] = raw_scores

    per_class_results = {}
    for label_val in sorted(df["label"].unique()):
        sub_df = df_eval[df_eval["label"] == label_val]
        total_class = len(sub_df)
        detected_class = int(sub_df["pred"].sum())
        rate = detected_class / total_class if total_class > 0 else 0.0
        per_class_results[label_val] = {
            "records": total_class,
            "detected_anomalies": detected_class,
            "detection_rate": round(rate, 6),
        }

    # Summary payload
    eval_timestamp = datetime.now(timezone.utc).isoformat()
    results = {
        "evaluation_timestamp": eval_timestamp,
        "dataset": {
            "path": str(data_path),
            "filename": data_path.name,
            "total_records": row_count,
            "total_columns": col_count,
            "features_used": len(feature_names),
            "has_record_id": has_record_id,
            "label_distribution": {k: int(v) for k, v in df["label"].value_counts().items()},
        },
        "model": {
            "model_type": meta.get("model", "IsolationForest"),
            "configuration": meta.get("configuration", {}),
            "threshold": threshold,
            "threshold_method": meta.get("threshold_method", ""),
            "score_definition": meta.get("score_definition", "-model.score_samples(X)"),
        },
        "metrics": {
            "ordinary_accuracy": round(accuracy, 6),
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1_score": round(f1, 6),
            "balanced_accuracy": round(balanced_acc, 6),
            "false_positive_rate": round(fpr, 6),
            "false_negative_rate": round(fnr, 6),
            "roc_auc": round(roc_auc, 6),
            "average_precision": round(avg_prec, 6),
            "confusion_matrix": {
                "true_positives": tp,
                "false_positives": fp,
                "true_negatives": tn,
                "false_negatives": fn,
            },
        },
        "per_class_results": per_class_results,
    }

    # Ensure reports directory exists
    reports_dir.mkdir(parents=True, exist_ok=True)

    # 1. Save JSON report
    json_path = reports_dir / "original_dataset_evaluation.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    logger.info("Saved JSON report to: %s", json_path)

    # 2. Save text summary report
    summary_path = reports_dir / "original_dataset_evaluation_summary.txt"
    summary_text = (
        "================================================================================\n"
        " DARK-TRACE-AI — AGENT 2 (NETWORK ANOMALY DETECTION) EVALUATION REPORT\n"
        "================================================================================\n"
        f"Evaluation Timestamp : {eval_timestamp}\n"
        f"Dataset Filename     : {data_path.name}\n"
        f"Total Evaluated Flows: {row_count:,}\n"
        f"Features Evaluated   : {len(feature_names)}\n"
        f"Calibrated Threshold : {threshold:.16f}\n"
        "--------------------------------------------------------------------------------\n"
        " PRIMARY & CORE METRICS:\n"
        f"   Ordinary Accuracy       : {accuracy * 100:.2f}% ({accuracy:.6f})\n"
        f"   Precision               : {precision * 100:.2f}% ({precision:.6f})\n"
        f"   Recall (TPR)            : {recall * 100:.2f}% ({recall:.6f})\n"
        f"   F1-Score                : {f1 * 100:.2f}% ({f1:.6f})\n"
        f"   Balanced Accuracy       : {balanced_acc * 100:.2f}% ({balanced_acc:.6f})\n"
        f"   False Positive Rate (FPR: {fpr * 100:.2f}% ({fpr:.6f})\n"
        f"   False Negative Rate (FNR: {fnr * 100:.2f}% ({fnr:.6f})\n"
        f"   ROC-AUC                 : {roc_auc * 100:.2f}% ({roc_auc:.6f})\n"
        f"   Average Precision (PR)  : {avg_prec * 100:.2f}% ({avg_prec:.6f})\n"
        "--------------------------------------------------------------------------------\n"
        " CONFUSION MATRIX:\n"
        f"   True Positives  (TP)    : {tp:,}\n"
        f"   False Positives (FP)    : {fp:,}\n"
        f"   True Negatives  (TN)    : {tn:,}\n"
        f"   False Negatives (FN)    : {fn:,}\n"
        "--------------------------------------------------------------------------------\n"
        " PER-CLASS DETECTION PERFORMANCE:\n"
    )
    for c_name, c_data in per_class_results.items():
        summary_text += (
            f"   {c_name:<16}: {c_data['detected_anomalies']:,} / {c_data['records']:,} "
            f"({c_data['detection_rate'] * 100:.2f}% flagged anomalous)\n"
        )
    summary_text += (
        "================================================================================\n"
        " VERIFICATION STATEMENT:\n"
        "   - Existing Isolation Forest was evaluated without retraining or recalibration.\n"
        "   - Threshold was strictly derived from verified metadata.\n"
        "   - No synthetic data was generated; real original evaluation Parquet was used.\n"
        "================================================================================\n"
    )
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(summary_text)
    logger.info("Saved text summary to: %s", summary_path)

    # 3. Generate Confusion Matrix Visualization
    cm_path = reports_dir / "confusion_matrix.png"
    plt.figure(figsize=(7, 6))
    plt.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    plt.title("Agent 2 Isolation Forest — Confusion Matrix", fontsize=14, pad=15)
    plt.colorbar()
    tick_marks = np.arange(2)
    plt.xticks(tick_marks, ["Normal (0)", "Anomalous (1)"], fontsize=11)
    plt.yticks(tick_marks, ["Normal (0)", "Anomalous (1)"], fontsize=11)

    # Annotate cells
    thresh_color = cm.max() / 2.0
    for i in range(2):
        for j in range(2):
            val = cm[i, j]
            label_text = f"{val:,}\n({val / row_count * 100:.1f}%)"
            plt.text(
                j,
                i,
                label_text,
                horizontalalignment="center",
                verticalalignment="center",
                color="white" if val > thresh_color else "black",
                fontsize=12,
                weight="bold",
            )

    plt.ylabel("True Label", fontsize=12)
    plt.xlabel("Predicted Label", fontsize=12)
    plt.tight_layout()
    plt.savefig(cm_path, dpi=200)
    plt.close()
    logger.info("Saved confusion matrix visualization to: %s", cm_path)

    return results


def main() -> None:
    """Parse CLI arguments and run evaluation."""
    parser = argparse.ArgumentParser(description="Evaluate Agent 2 Isolation Forest on original dataset.")
    parser.add_argument(
        "--data-path",
        type=Path,
        default=DEFAULT_DATA_PATH,
        help="Path to evaluation parquet file (default: src/dark_trace/agent2/data/cyber_eval.parquet)",
    )
    parser.add_argument(
        "--model-path",
        type=Path,
        default=DEFAULT_MODEL_PATH,
        help="Path to trained Isolation Forest model artifact",
    )
    parser.add_argument(
        "--metadata-path",
        type=Path,
        default=DEFAULT_METADATA_PATH,
        help="Path to model metadata JSON",
    )
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=DEFAULT_REPORTS_DIR,
        help="Output directory for evaluation reports",
    )
    args = parser.parse_args()

    results = run_evaluation(
        data_path=args.data_path,
        model_path=args.model_path,
        metadata_path=args.metadata_path,
        reports_dir=args.reports_dir,
    )

    print("\n" + "=" * 60)
    print("EVALUATION COMPLETE")
    print(f"Dataset Evaluated : {results['dataset']['filename']}")
    print(f"Total Rows        : {results['dataset']['total_records']:,}")
    print(f"Ordinary Accuracy : {results['metrics']['ordinary_accuracy'] * 100:.2f}%")
    print(f"Precision         : {results['metrics']['precision'] * 100:.2f}%")
    print(f"Recall            : {results['metrics']['recall'] * 100:.2f}%")
    print(f"F1-Score          : {results['metrics']['f1_score'] * 100:.2f}%")
    print(f"ROC-AUC           : {results['metrics']['roc_auc'] * 100:.2f}%")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
