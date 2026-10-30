"""Policy What-If Simulator and Response Impact Analysis for CyberSentinel Agent 4.

Allows security analysts and architects to evaluate sets of Agent 3 threat
assessments simultaneously across all operational policy profiles (STRICT,
BALANCED, CONSERVATIVE) without modifying underlying policy rules.

Provides:
  - Profile What-If Simulation
  - Offline Security Evaluation (TP, FP, TN, FN, Precision, Recall, F1, FPR, FBR, Review Rate)
  - SOC Response Impact Analysis (Analyst workload, false blocks, operational risk)
  - Profile Divergence & Comparison Reporting
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from cybersentinel.agent4.adaptive_policy import AdaptivePolicyEngine
from cybersentinel.agent4.contract import PolicyAction, PolicyDecision, PolicyProfile
from cybersentinel.agent4.exceptions import SimulationError

logger = logging.getLogger(__name__)

# Canonical profiles evaluated by the What-If Simulator
SIMULATED_PROFILES = [
    PolicyProfile.STRICT,
    PolicyProfile.BALANCED,
    PolicyProfile.CONSERVATIVE,
]

# Set of labels recognized as Benign in intrusion detection datasets
BENIGN_LABELS = frozenset({"BENIGN", "NORMAL", "SAFE", "CLEAN", "0", "FALSE", "NONE", ""})


def is_malicious_label(label: Any) -> bool:
    """Determine whether a ground truth label indicates malicious activity.

    Args:
        label: Ground truth label (str, bool, int, or None).

    Returns:
        bool: True if malicious/attack; False if benign/normal.
    """
    if label is None:
        return False
    if isinstance(label, bool):
        return label
    if isinstance(label, (int, float)):
        return bool(label)
    clean = str(label).strip().upper()
    return clean not in BENIGN_LABELS


@dataclass
class ProfileMetrics:
    """Quantitative decision metrics evaluated for a single policy profile."""
    profile: str
    total_flows: int
    allow_count: int
    alert_count: int
    review_count: int
    block_count: int
    review_rate_pct: float
    block_rate_pct: float
    decision_distribution: Dict[str, Dict[str, Union[int, float]]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return asdict(self)


@dataclass
class SecurityEvaluationMetrics:
    """Offline intrusion detection metrics evaluated against ground truth labels.

    Semantic Definitions:
      - Positive Decision (detection/intervention): action in {ALERT, REVIEW, BLOCK}
      - Negative Decision (allow): action == ALLOW
      - True Positive (TP): Ground truth is Malicious AND action is {ALERT, REVIEW, BLOCK}
      - False Positive (FP): Ground truth is Benign BUT action is {ALERT, REVIEW, BLOCK}
      - True Negative (TN): Ground truth is Benign AND action is ALLOW
      - False Negative (FN): Ground truth is Malicious BUT action is ALLOW
      - Precision: TP / (TP + FP) (proportion of intervened flows that were malicious)
      - Recall: TP / (TP + FN) (proportion of all malicious flows detected)
      - F1 Score: 2 * Precision * Recall / (Precision + Recall)
      - False-Positive Rate (FPR): FP / (FP + TN) (fraction of benign traffic falsely flagged)
      - False-Block Rate (FBR): Benign flows blocked / Total Benign (critical disruption metric)
      - Review Rate: Total flows routed to human review / Total flows
      - Accuracy: (TP + TN) / Total flows
    """
    profile: str
    total_flows: int
    total_malicious: int
    total_benign: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    false_block_rate: float
    review_rate: float
    accuracy: float
    true_blocks: int
    false_blocks: int
    true_block_rate: float

    def to_dict(self) -> Dict[str, Any]:
        """Convert evaluation metrics to dictionary."""
        return asdict(self)


@dataclass
class ResponseImpactMetrics:
    """Operational and business impact analysis for SOC security teams."""
    profile: str
    total_flows: int
    review_count: int
    review_rate_pct: float
    estimated_analyst_hours: float
    simulated_blocks_count: int
    block_rate_pct: float
    false_blocks_count: int
    false_block_rate_pct: float
    containment_coverage_pct: float
    operational_risk_level: str
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert impact metrics to dictionary."""
        return asdict(self)


@dataclass
class FlowSimulationRecord:
    """Simulation outcomes for an individual flow evaluated across all profiles."""
    flow_id: str
    input_assessment: Dict[str, Any]
    ground_truth: Optional[str]
    is_malicious: Optional[bool]
    decisions: Dict[str, PolicyDecision]

    def to_dict(self) -> Dict[str, Any]:
        """Convert record to dictionary with serialized decisions."""
        return {
            "flow_id": self.flow_id,
            "ground_truth": self.ground_truth,
            "is_malicious": self.is_malicious,
            "decisions": {p: d.to_dict() for p, d in self.decisions.items()},
        }


@dataclass
class SimulationResult:
    """Comprehensive container for policy simulation, evaluation, and impact results."""
    flow_records: List[FlowSimulationRecord]
    profile_metrics: Dict[str, ProfileMetrics]
    security_metrics: Optional[Dict[str, SecurityEvaluationMetrics]]
    impact_metrics: Dict[str, ResponseImpactMetrics]
    profile_comparison: Dict[str, Any]
    total_flows: int
    divergent_flows_count: int
    divergence_rate_pct: float
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize complete simulation result to a clean dictionary."""
        sec_dict = (
            {k: v.to_dict() for k, v in self.security_metrics.items()}
            if self.security_metrics
            else None
        )
        return {
            "total_flows": self.total_flows,
            "divergent_flows_count": self.divergent_flows_count,
            "divergence_rate_pct": self.divergence_rate_pct,
            "generated_at": self.generated_at,
            "profile_metrics": {k: v.to_dict() for k, v in self.profile_metrics.items()},
            "security_metrics": sec_dict,
            "impact_metrics": {k: v.to_dict() for k, v in self.impact_metrics.items()},
            "profile_comparison": self.profile_comparison,
            "flow_records": [r.to_dict() for r in self.flow_records],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize complete simulation result to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def generate_comparison_report(self) -> str:
        """Generate a human-readable text comparison report."""
        lines: List[str] = [
            "=" * 78,
            "CYBERSENTINEL AGENT 4 — POLICY WHAT-IF SIMULATION & IMPACT REPORT",
            "=" * 78,
            f"Generated At: {self.generated_at}",
            f"Total Flows Evaluated: {self.total_flows}",
            f"Divergent Flows Across Profiles: {self.divergent_flows_count} ({self.divergence_rate_pct:.1f}%)",
            "-" * 78,
            "1. PROFILE ENFORCEMENT DISTRIBUTION",
            "-" * 78,
            f"{'Profile':<14} {'Total':<8} {'ALLOW':<10} {'ALERT':<10} {'REVIEW':<10} {'BLOCK':<10} {'Review%':<9} {'Block%':<8}",
            f"{'-'*14} {'-'*8} {'-'*10} {'-'*10} {'-'*10} {'-'*10} {'-'*9} {'-'*8}",
        ]

        for prof in ["STRICT", "BALANCED", "CONSERVATIVE"]:
            if prof in self.profile_metrics:
                m = self.profile_metrics[prof]
                lines.append(
                    f"{m.profile:<14} {m.total_flows:<8} {m.allow_count:<10} {m.alert_count:<10} "
                    f"{m.review_count:<10} {m.block_count:<10} {m.review_rate_pct:>6.1f}%  {m.block_rate_pct:>6.1f}%"
                )

        if self.security_metrics:
            lines.extend([
                "-" * 78,
                "2. OFFLINE SECURITY PERFORMANCE EVALUATION (GROUND TRUTH)",
                "-" * 78,
                f"{'Profile':<14} {'Prec':<8} {'Recall':<8} {'F1':<8} {'FPR':<8} {'False-Block':<13} {'ReviewRate':<11} {'Accuracy':<8}",
                f"{'-'*14} {'-'*8} {'-'*8} {'-'*8} {'-'*8} {'-'*13} {'-'*11} {'-'*8}",
            ])
            for prof in ["STRICT", "BALANCED", "CONSERVATIVE"]:
                if prof in self.security_metrics:
                    sm = self.security_metrics[prof]
                    lines.append(
                        f"{sm.profile:<14} {sm.precision:>6.3f}  {sm.recall:>6.3f}  {sm.f1_score:>6.3f}  "
                        f"{sm.false_positive_rate:>6.3f}  {sm.false_block_rate:>10.4f}   {sm.review_rate:>8.3f}   {sm.accuracy:>6.3f}"
                    )

        lines.extend([
            "-" * 78,
            "3. SOC OPERATIONAL & RESPONSE IMPACT ANALYSIS",
            "-" * 78,
            f"{'Profile':<14} {'Reviews':<9} {'Analyst(h)':<12} {'Blocks':<8} {'FalseBlocks':<13} {'Risk Level':<12}",
            f"{'-'*14} {'-'*9} {'-'*12} {'-'*8} {'-'*13} {'-'*12}",
        ])
        for prof in ["STRICT", "BALANCED", "CONSERVATIVE"]:
            if prof in self.impact_metrics:
                im = self.impact_metrics[prof]
                lines.append(
                    f"{im.profile:<14} {im.review_count:<9} {im.estimated_analyst_hours:>9.1f}h  "
                    f"{im.simulated_blocks_count:<8} {im.false_blocks_count:<13} {im.operational_risk_level:<12}"
                )

        lines.extend([
            "-" * 78,
            "4. OPERATIONAL RECOMMENDATIONS",
            "-" * 78,
        ])
        for prof in ["STRICT", "BALANCED", "CONSERVATIVE"]:
            if prof in self.impact_metrics:
                im = self.impact_metrics[prof]
                lines.append(f"[{im.profile}]: {im.recommendation}")

        lines.append("=" * 78)
        return "\n".join(lines)


class PolicySimulator:
    """Policy What-If Simulator for CyberSentinel Agent 4.

    Evaluates sets of Agent 3 threat assessments across operational policy profiles
    (STRICT, BALANCED, CONSERVATIVE) using the existing AdaptivePolicyEngine.
    """

    def __init__(
        self,
        engine: Optional[AdaptivePolicyEngine] = None,
        profiles: Optional[Sequence[Union[str, PolicyProfile]]] = None,
        review_time_minutes_per_flow: float = 10.0,
    ) -> None:
        """Initialize PolicySimulator.

        Args:
            engine: Optional AdaptivePolicyEngine instance. If omitted, initializes
                    a default engine without active audit logger.
            profiles: Optional sequence of profiles to simulate. Defaults to
                      STRICT, BALANCED, CONSERVATIVE.
            review_time_minutes_per_flow: Estimated average SOC analyst review time
                                          per escalated flow in minutes.
        """
        self.engine = engine or AdaptivePolicyEngine()
        if profiles:
            self.profiles = [
                self.engine._normalize_profile(p).value for p in profiles
            ]
        else:
            self.profiles = [p.value for p in SIMULATED_PROFILES]
        self.review_time_minutes_per_flow = max(0.1, float(review_time_minutes_per_flow))

    def simulate(
        self,
        assessments: Sequence[Any],
        ground_truth: Optional[Sequence[Any]] = None,
    ) -> SimulationResult:
        """Execute what-if simulation on a batch of assessments across profiles.

        Args:
            assessments: Sequence of Agent 3 threat assessments (objects, dicts, or JSON).
            ground_truth: Optional parallel sequence of ground-truth labels.
                          If omitted, checks if individual assessments contain
                          embedded ground-truth fields.

        Returns:
            SimulationResult: Complete simulation, evaluation, and impact results.

        Raises:
            SimulationError: If assessment sequence is empty or invalid.
        """
        if assessments is None:
            raise SimulationError("Cannot simulate empty assessment list (None).")

        flows_list = list(assessments)
        total_flows = len(flows_list)

        # Validate ground_truth length if explicitly provided
        if ground_truth is not None and len(ground_truth) != total_flows:
            raise SimulationError(
                f"Ground truth length ({len(ground_truth)}) does not match assessments count ({total_flows})."
            )

        flow_records: List[FlowSimulationRecord] = []
        divergent_count = 0
        has_any_ground_truth = ground_truth is not None

        # ---------------------------------------------------------------------
        # 1. Run simulation across all profiles for each flow
        # ---------------------------------------------------------------------
        for idx, item in enumerate(flows_list):
            raw_truth: Optional[Any] = (
                ground_truth[idx] if ground_truth is not None else self._extract_ground_truth(item)
            )
            if raw_truth is not None:
                has_any_ground_truth = True
                is_mal = is_malicious_label(raw_truth)
                str_truth = str(raw_truth)
            else:
                is_mal = None
                str_truth = None

            flow_decisions: Dict[str, PolicyDecision] = {}
            actions_seen = set()

            for prof in self.profiles:
                decision = self.engine.evaluate(item, profile=prof, raise_on_error=False)
                flow_decisions[prof] = decision
                actions_seen.add(decision.action.value)

            if len(actions_seen) > 1:
                divergent_count += 1

            # Resolve flow_id for record
            flow_id = (
                flow_decisions.get("BALANCED", list(flow_decisions.values())[0]).flow_id
                if flow_decisions
                else f"FLOW-{idx+1:04d}"
            )

            flow_records.append(
                FlowSimulationRecord(
                    flow_id=flow_id,
                    input_assessment=item if isinstance(item, dict) else (
                        item.to_dict() if hasattr(item, "to_dict") else {"raw": str(item)}
                    ),
                    ground_truth=str_truth,
                    is_malicious=is_mal,
                    decisions=flow_decisions,
                )
            )

        # ---------------------------------------------------------------------
        # 2. Compute Profile Metrics
        # ---------------------------------------------------------------------
        profile_metrics: Dict[str, ProfileMetrics] = {}
        for prof in self.profiles:
            profile_decisions = [r.decisions[prof] for r in flow_records]
            profile_metrics[prof] = self._calculate_profile_metrics(
                profile_decisions, prof, total_flows
            )

        # ---------------------------------------------------------------------
        # 3. Compute Security Metrics (if ground truth available)
        # ---------------------------------------------------------------------
        security_metrics: Optional[Dict[str, SecurityEvaluationMetrics]] = None
        if has_any_ground_truth and total_flows > 0:
            security_metrics = {}
            for prof in self.profiles:
                security_metrics[prof] = self._calculate_security_metrics(
                    prof, flow_records, total_flows
                )

        # ---------------------------------------------------------------------
        # 4. Compute Response Impact Metrics
        # ---------------------------------------------------------------------
        impact_metrics: Dict[str, ResponseImpactMetrics] = {}
        for prof in self.profiles:
            p_met = profile_metrics[prof]
            s_met = security_metrics.get(prof) if security_metrics else None
            impact_metrics[prof] = self._calculate_impact_metrics(p_met, s_met)

        # ---------------------------------------------------------------------
        # 5. Build Profile Comparison Summary
        # ---------------------------------------------------------------------
        profile_comparison = self._build_comparison_summary(
            profile_metrics, security_metrics, impact_metrics, flow_records
        )

        divergence_rate_pct = (divergent_count / total_flows * 100.0) if total_flows > 0 else 0.0

        return SimulationResult(
            flow_records=flow_records,
            profile_metrics=profile_metrics,
            security_metrics=security_metrics,
            impact_metrics=impact_metrics,
            profile_comparison=profile_comparison,
            total_flows=total_flows,
            divergent_flows_count=divergent_count,
            divergence_rate_pct=divergence_rate_pct,
        )

    def compare_profiles(self, assessments: Sequence[Any]) -> Dict[str, Any]:
        """Convenience method returning serialized comparison across profiles."""
        result = self.simulate(assessments)
        return result.profile_comparison

    def evaluate_security(
        self,
        assessments: Sequence[Any],
        ground_truth: Sequence[Any],
        profile: Optional[Union[str, PolicyProfile]] = None,
    ) -> Dict[str, Any]:
        """Convenience method returning offline security evaluation metrics.

        Args:
            assessments: Sequence of Agent 3 assessments.
            ground_truth: Parallel sequence of ground truth labels.
            profile: Specific profile to evaluate. If omitted, returns metrics for all profiles.

        Returns:
            Dict[str, Any]: Serialized dictionary of security metrics.
        """
        result = self.simulate(assessments, ground_truth=ground_truth)
        if not result.security_metrics:
            return {}
        if profile is not None:
            prof_name = self.engine._normalize_profile(profile).value
            metrics = result.security_metrics.get(prof_name)
            return metrics.to_dict() if metrics else {}
        return {k: v.to_dict() for k, v in result.security_metrics.items()}

    def analyze_response_impact(
        self,
        assessments: Sequence[Any],
        ground_truth: Optional[Sequence[Any]] = None,
    ) -> Dict[str, Any]:
        """Convenience method returning response impact analysis across profiles."""
        result = self.simulate(assessments, ground_truth=ground_truth)
        return {k: v.to_dict() for k, v in result.impact_metrics.items()}

    # -------------------------------------------------------------------------
    # Internal Computation Helpers
    # -------------------------------------------------------------------------
    @staticmethod
    def _extract_ground_truth(assessment: Any) -> Optional[Any]:
        """Extract embedded ground truth from assessment object or dictionary."""
        if isinstance(assessment, dict):
            for key in ("ground_truth", "true_label", "actual_class", "label", "is_malicious"):
                if key in assessment:
                    return assessment[key]
        elif hasattr(assessment, "ground_truth"):
            return getattr(assessment, "ground_truth")
        elif hasattr(assessment, "true_label"):
            return getattr(assessment, "true_label")
        elif hasattr(assessment, "label"):
            return getattr(assessment, "label")
        return None

    @staticmethod
    def _calculate_profile_metrics(
        decisions: List[PolicyDecision], profile_name: str, total_flows: int
    ) -> ProfileMetrics:
        """Calculate counts and percentage distributions for a profile's decisions."""
        allow_count = sum(1 for d in decisions if d.action == PolicyAction.ALLOW)
        alert_count = sum(1 for d in decisions if d.action == PolicyAction.ALERT)
        review_count = sum(1 for d in decisions if d.action == PolicyAction.REVIEW)
        block_count = sum(1 for d in decisions if d.action == PolicyAction.BLOCK)

        review_rate_pct = (review_count / total_flows * 100.0) if total_flows > 0 else 0.0
        block_rate_pct = (block_count / total_flows * 100.0) if total_flows > 0 else 0.0

        decision_dist = {
            "ALLOW": {
                "count": allow_count,
                "percentage": (allow_count / total_flows * 100.0) if total_flows > 0 else 0.0,
            },
            "ALERT": {
                "count": alert_count,
                "percentage": (alert_count / total_flows * 100.0) if total_flows > 0 else 0.0,
            },
            "REVIEW": {
                "count": review_count,
                "percentage": (review_count / total_flows * 100.0) if total_flows > 0 else 0.0,
            },
            "BLOCK": {
                "count": block_count,
                "percentage": (block_count / total_flows * 100.0) if total_flows > 0 else 0.0,
            },
        }

        return ProfileMetrics(
            profile=profile_name,
            total_flows=total_flows,
            allow_count=allow_count,
            alert_count=alert_count,
            review_count=review_count,
            block_count=block_count,
            review_rate_pct=review_rate_pct,
            block_rate_pct=block_rate_pct,
            decision_distribution=decision_dist,
        )

    @staticmethod
    def _calculate_security_metrics(
        profile_name: str, records: List[FlowSimulationRecord], total_flows: int
    ) -> SecurityEvaluationMetrics:
        """Calculate IDS performance metrics against ground truth.

        Semantic Definitions:
          - Positive Decision (detection/intervention): action in {ALERT, REVIEW, BLOCK}
          - Negative Decision: action == ALLOW
          - TP: Malicious flow receiving {ALERT, REVIEW, BLOCK}
          - FP: Benign flow receiving {ALERT, REVIEW, BLOCK}
          - TN: Benign flow receiving ALLOW
          - FN: Malicious flow receiving ALLOW
          - False Block: Benign flow receiving BLOCK
          - True Block: Malicious flow receiving BLOCK
        """
        tp = 0
        fp = 0
        tn = 0
        fn = 0
        true_blocks = 0
        false_blocks = 0
        total_malicious = 0
        total_benign = 0
        review_count = 0

        for r in records:
            dec = r.decisions[profile_name]
            act = dec.action
            is_mal = bool(r.is_malicious)

            if is_mal:
                total_malicious += 1
            else:
                total_benign += 1

            if act == PolicyAction.REVIEW:
                review_count += 1

            # Detection mapping
            if act in (PolicyAction.ALERT, PolicyAction.REVIEW, PolicyAction.BLOCK):
                if is_mal:
                    tp += 1
                else:
                    fp += 1
            else:  # ALLOW
                if is_mal:
                    fn += 1
                else:
                    tn += 1

            # Blocking specifics
            if act == PolicyAction.BLOCK:
                if is_mal:
                    true_blocks += 1
                else:
                    false_blocks += 1

        precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1_score = (
            (2.0 * precision * recall / (precision + recall))
            if (precision + recall) > 0
            else 0.0
        )
        fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        false_block_rate = (false_blocks / total_benign) if total_benign > 0 else 0.0
        true_block_rate = (true_blocks / total_malicious) if total_malicious > 0 else 0.0
        review_rate = (review_count / total_flows) if total_flows > 0 else 0.0
        accuracy = ((tp + tn) / total_flows) if total_flows > 0 else 0.0

        return SecurityEvaluationMetrics(
            profile=profile_name,
            total_flows=total_flows,
            total_malicious=total_malicious,
            total_benign=total_benign,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f1_score=f1_score,
            false_positive_rate=fpr,
            false_block_rate=false_block_rate,
            review_rate=review_rate,
            accuracy=accuracy,
            true_blocks=true_blocks,
            false_blocks=false_blocks,
            true_block_rate=true_block_rate,
        )

    def _calculate_impact_metrics(
        self, p_metrics: ProfileMetrics, s_metrics: Optional[SecurityEvaluationMetrics]
    ) -> ResponseImpactMetrics:
        """Calculate SOC workload and operational risk metrics."""
        hours = (p_metrics.review_count * self.review_time_minutes_per_flow) / 60.0

        false_blocks = s_metrics.false_blocks if s_metrics else 0
        false_block_rate_pct = (
            (s_metrics.false_block_rate * 100.0) if s_metrics else 0.0
        )
        containment_coverage_pct = (
            ((s_metrics.true_positives / s_metrics.total_malicious) * 100.0)
            if s_metrics and s_metrics.total_malicious > 0
            else p_metrics.block_rate_pct + p_metrics.review_rate_pct
        )

        # Operational risk evaluation
        prof = p_metrics.profile
        if prof == "STRICT":
            risk = "MEDIUM" if false_blocks > 0 else "LOW"
            rec = (
                "Best suited for high-threat environments or perimeter ingress. "
                "Generates high analyst triage volume but achieves early threat containment."
            )
        elif prof == "CONSERVATIVE":
            risk = "LOW"
            rec = (
                "Best suited for critical internal infrastructure and latency-sensitive services. "
                "Eliminates false blocks while routing ambiguous cases to alerts."
            )
        else:  # BALANCED
            risk = "LOW"
            rec = (
                "Recommended standard baseline. Delivers strong attack mitigation with "
                "controlled SOC analyst overhead and minimal false containment."
            )

        return ResponseImpactMetrics(
            profile=prof,
            total_flows=p_metrics.total_flows,
            review_count=p_metrics.review_count,
            review_rate_pct=p_metrics.review_rate_pct,
            estimated_analyst_hours=hours,
            simulated_blocks_count=p_metrics.block_count,
            block_rate_pct=p_metrics.block_rate_pct,
            false_blocks_count=false_blocks,
            false_block_rate_pct=false_block_rate_pct,
            containment_coverage_pct=containment_coverage_pct,
            operational_risk_level=risk,
            recommendation=rec,
        )

    @staticmethod
    def _build_comparison_summary(
        profile_metrics: Dict[str, ProfileMetrics],
        security_metrics: Optional[Dict[str, SecurityEvaluationMetrics]],
        impact_metrics: Dict[str, ResponseImpactMetrics],
        records: List[FlowSimulationRecord],
    ) -> Dict[str, Any]:
        """Construct detailed comparison structures highlighting profile divergences."""
        summary: Dict[str, Any] = {
            "metrics_by_profile": {k: v.to_dict() for k, v in profile_metrics.items()},
            "impact_by_profile": {k: v.to_dict() for k, v in impact_metrics.items()},
        }

        if security_metrics:
            summary["security_by_profile"] = {
                k: v.to_dict() for k, v in security_metrics.items()
            }

        # Compare STRICT vs BALANCED vs CONSERVATIVE deltas
        if "STRICT" in profile_metrics and "BALANCED" in profile_metrics:
            strict_m = profile_metrics["STRICT"]
            bal_m = profile_metrics["BALANCED"]
            summary["strict_vs_balanced"] = {
                "additional_reviews": strict_m.review_count - bal_m.review_count,
                "block_difference": strict_m.block_count - bal_m.block_count,
            }

        if "CONSERVATIVE" in profile_metrics and "BALANCED" in profile_metrics:
            cons_m = profile_metrics["CONSERVATIVE"]
            bal_m = profile_metrics["BALANCED"]
            summary["conservative_vs_balanced"] = {
                "review_difference": cons_m.review_count - bal_m.review_count,
                "block_difference": cons_m.block_count - bal_m.block_count,
            }

        # Identify sample divergent flows
        divergent_samples: List[Dict[str, Any]] = []
        for r in records:
            actions = {p: d.action.value for p, d in r.decisions.items()}
            if len(set(actions.values())) > 1:
                divergent_samples.append({
                    "flow_id": r.flow_id,
                    "ground_truth": r.ground_truth,
                    "actions": actions,
                })
                if len(divergent_samples) >= 10:
                    break

        summary["sample_divergent_flows"] = divergent_samples
        return summary


# =============================================================================
# Standalone Convenience Functions
# =============================================================================
def simulate_policy(
    assessments: Sequence[Any],
    ground_truth: Optional[Sequence[Any]] = None,
    engine: Optional[AdaptivePolicyEngine] = None,
) -> SimulationResult:
    """Convenience functional interface to simulate policies across all profiles.

    Args:
        assessments: Sequence of Agent 3 assessments.
        ground_truth: Optional sequence of ground truth labels.
        engine: Optional AdaptivePolicyEngine instance.

    Returns:
        SimulationResult: Complete simulation result.
    """
    simulator = PolicySimulator(engine=engine)
    return simulator.simulate(assessments, ground_truth=ground_truth)


def calculate_security_metrics(
    decisions: Sequence[PolicyDecision],
    ground_truth: Sequence[Any],
    profile_name: str = "EVALUATION",
) -> SecurityEvaluationMetrics:
    """Calculate standalone security evaluation metrics for a list of decisions.

    Args:
        decisions: Sequence of evaluated PolicyDecision objects.
        ground_truth: Parallel sequence of ground-truth labels.
        profile_name: Optional profile name label.

    Returns:
        SecurityEvaluationMetrics: Computed metrics.
    """
    if len(decisions) != len(ground_truth):
        raise SimulationError(
            f"Decisions count ({len(decisions)}) does not match ground truth count ({len(ground_truth)})."
        )

    records = [
        FlowSimulationRecord(
            flow_id=d.flow_id,
            input_assessment={},
            ground_truth=str(g),
            is_malicious=is_malicious_label(g),
            decisions={profile_name: d},
        )
        for d, g in zip(decisions, ground_truth)
    ]

    return PolicySimulator._calculate_security_metrics(profile_name, records, len(decisions))

