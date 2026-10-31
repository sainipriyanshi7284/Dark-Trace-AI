"""
CyberSentinel Agent 1 - Detection Coverage Gap Analyzer
========================================================
Reusable module that audits per-class detection quality,
identifies false positive/negative hotspots, and flags
classes with weak or missing coverage.

Author: CyberSentinel / Agent 1
Usage:
    from agent1.coverage_gap_analyzer import CoverageGapAnalyzer
    analyzer = CoverageGapAnalyzer(threshold=0.80)
    report = analyzer.analyze(y_true, y_pred, classes=model.classes_)
    analyzer.print_report(report)
"""

from __future__ import annotations

import warnings
from typing import List, Optional, Sequence

import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


class CoverageGapAnalyzer:
    """
    Analyses per-class detection coverage and surfaces gaps.

    Parameters
    ----------
    threshold : float
        Minimum acceptable F1-score per class (default 0.80).
        Classes below this value are flagged as weak.
    """

    def __init__(self, threshold: float = 0.80) -> None:
        if not 0.0 < threshold <= 1.0:
            raise ValueError("threshold must be in (0, 1]")
        self.threshold = threshold

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(
        self,
        y_true: Sequence,
        y_pred: Sequence,
        classes: Optional[List[str]] = None,
    ) -> dict:
        """
        Run full coverage gap analysis.

        Parameters
        ----------
        y_true   : Ground-truth labels.
        y_pred   : Model-predicted labels.
        classes  : Ordered list of class names.
                   If None, inferred from y_true ∪ y_pred.

        Returns
        -------
        dict with keys: summary, confusion, gaps, absent_classes,
                        commonly_confused, raw_report
        """
        y_true = np.asarray(y_true)
        y_pred = np.asarray(y_pred)

        all_labels = sorted(set(y_true) | set(y_pred))
        if classes is None:
            classes = all_labels

        # ── 1. Per-class metrics ──────────────────────────────────────
        report_dict = classification_report(
            y_true,
            y_pred,
            labels=classes,
            output_dict=True,
            zero_division=0,
        )

        rows = []
        for cls in classes:
            m = report_dict.get(cls, {})
            support = int(m.get("support", 0))
            precision = float(m.get("precision", 0.0))
            recall = float(m.get("recall", 0.0))
            f1 = float(m.get("f1-score", 0.0))

            # FP / FN counts
            true_mask = y_true == cls
            pred_mask = y_pred == cls
            tp = int(np.sum(true_mask & pred_mask))
            fp = int(np.sum(~true_mask & pred_mask))
            fn = int(np.sum(true_mask & ~pred_mask))

            rows.append(
                {
                    "class": cls,
                    "precision": round(precision, 4),
                    "recall": round(recall, 4),
                    "f1": round(f1, 4),
                    "support": support,
                    "TP": tp,
                    "FP": fp,
                    "FN": fn,
                    "weak": f1 < self.threshold,
                    "absent_from_eval": support == 0,
                }
            )

        summary_df = pd.DataFrame(rows)

        # ── 2. Confusion matrix ──────────────────────────────────────
        cm = confusion_matrix(y_true, y_pred, labels=classes)
        cm_df = pd.DataFrame(cm, index=classes, columns=classes)

        # ── 3. Commonly confused pairs ────────────────────────────────
        commonly_confused = self._find_confused_pairs(cm, classes)

        # ── 4. Absent classes ─────────────────────────────────────────
        absent_classes = list(
            summary_df[summary_df["absent_from_eval"]]["class"]
        )

        # ── 5. Weak classes ───────────────────────────────────────────
        weak_classes = list(
            summary_df[summary_df["weak"] & ~summary_df["absent_from_eval"]][
                "class"
            ]
        )

        # ── 6. Global metrics ─────────────────────────────────────────
        macro_f1 = round(f1_score(y_true, y_pred, average="macro", zero_division=0), 4)
        weighted_f1 = round(
            f1_score(y_true, y_pred, average="weighted", zero_division=0), 4
        )

        return {
            "summary": summary_df,
            "confusion": cm_df,
            "gaps": {
                "weak_classes": weak_classes,
                "absent_classes": absent_classes,
                "threshold_used": self.threshold,
            },
            "commonly_confused": commonly_confused,
            "global_metrics": {
                "macro_f1": macro_f1,
                "weighted_f1": weighted_f1,
            },
            "raw_report": report_dict,
        }

    def print_report(self, report: dict) -> None:
        """Pretty-print a report dict produced by analyze()."""
        sep = "=" * 65
        dash = "-" * 65
        print(sep)
        print("  DETECTION COVERAGE GAP REPORT")
        print(f"  Performance threshold: F1 >= {report['gaps']['threshold_used']:.2f}")
        print(sep)

        # Global
        gm = report["global_metrics"]
        print(f"\n  Macro  F1   : {gm['macro_f1']:.4f}")
        print(f"  Weighted F1 : {gm['weighted_f1']:.4f}")

        # Per-class summary
        print(f"\n{dash}")
        print("  Per-Class Breakdown")
        print(dash)
        df = report["summary"].copy()
        df.columns = [c.upper() if c == "class" else c for c in df.columns]
        print(df.to_string(index=False))

        # Confusion matrix
        print(f"\n{dash}")
        print("  Confusion Matrix (rows=actual, cols=predicted)")
        print(dash)
        print(report["confusion"].to_string())

        # Commonly confused
        print(f"\n{dash}")
        print("  Most Confused Class Pairs")
        print(dash)
        for item in report["commonly_confused"]:
            print(
                f"  {item['actual']:>12} -> {item['predicted']:<12}  "
                f"count={item['count']:>6}"
            )

        # Gaps
        gaps = report["gaps"]
        print()
        if gaps["weak_classes"]:
            print(f"  [WEAK] CLASSES with F1 < {gaps['threshold_used']:.2f}: "
                  f"{gaps['weak_classes']}")
        else:
            print(f"  [OK] All classes meet the F1 >= {gaps['threshold_used']:.2f} threshold.")

        if gaps["absent_classes"]:
            print(f"  [INFO] ABSENT FROM EVAL: {gaps['absent_classes']}")

        print(sep)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_confused_pairs(
        cm: np.ndarray, classes: List[str], top_n: int = 5
    ) -> List[dict]:
        """Return top-N off-diagonal confusion matrix entries."""
        pairs = []
        n = len(classes)
        for i in range(n):
            for j in range(n):
                if i != j and cm[i, j] > 0:
                    pairs.append(
                        {
                            "actual": classes[i],
                            "predicted": classes[j],
                            "count": int(cm[i, j]),
                        }
                    )
        pairs.sort(key=lambda x: x["count"], reverse=True)
        return pairs[:top_n]

