"""Deterministic, explainable fusion scoring engine for CyberSentinel Agent 3 (Block 4).

Combines:
  - Agent 1: Classification evidence (1 - P(BENIGN))
  - Agent 2: Normalized continuous anomaly evidence
  - Block 3: Multi-agent evidence correlation (R)

Features:
  - Configurable weights via FusionConfig (default: 50% classifier, 30% anomaly, 20% correlation).
  - Dynamic weight renormalization when evidence sources are unavailable.
  - Disagreement safeguards (zero-day detection, signature preservation, missing evidence tracking).
  - Explicit risk level (LOW, MEDIUM, HIGH, CRITICAL) and confidence level (HIGH, MEDIUM, LOW).
  - Structured, explainable output conforming to the required contract.
"""

from __future__ import annotations

import math
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

from cybersentinel.agent3.contract import (
    A1DetectionResult,
    A2DetectionResult,
    Agent3Input,
    Agent3Output,
    AgentStatus,
    FlowContext,
    FusionStatus,
    RecommendedAction,
    Verdict,
)
from cybersentinel.agent3.evidence_correlator import (
    CorrelationResult,
    CorrelationScenario,
    EvidenceCorrelator,
    EvidenceStatus,
    InvestigationPriority,
    correlate_evidence,
)
from cybersentinel.agent3.explainer import ExplanationResult, ThreatExplainer
from cybersentinel.agent3.schemas import (
    Agent1ThreatPrediction,
    Agent2AnomalyAssessment,
    Agent3FusionInput,
    Agent3ThreatAssessment,
)
from cybersentinel.agent3.validator import (
    A1_CLASS_NORMALIZATION,
    CANONICAL_A1_CLASSES,
    validate_agent1_output,
    validate_agent2_output,
    validate_fusion_input,
)


class RiskLevel(str, Enum):
    """Calibrated security risk verdict levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class ConfidenceLevel(str, Enum):
    """Categorical confidence in the combined multi-agent assessment."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AssessmentVerdict(str, Enum):
    """Overall security triage conclusion."""
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    BENIGN = "BENIGN"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class FusionConfig:
    """Configurable weights, normalization ranges, and thresholds for Agent 3 Fusion."""
    # Configurable weights (default: 50% classifier, 30% anomaly, 20% correlation)
    classifier_weight: float = 0.50
    anomaly_weight: float = 0.30
    correlation_weight: float = 0.20

    # Risk score boundaries:
    # 0.00–0.24 = LOW
    # 0.25–0.49 = MEDIUM
    # 0.50–0.74 = HIGH
    # 0.75–1.00 = CRITICAL
    low_cutoff: float = 0.25
    medium_cutoff: float = 0.50
    high_cutoff: float = 0.75

    # Anomaly score normalization configuration
    anomaly_min: float = 0.0
    anomaly_max: float = 1.0
    anomaly_higher_is_more_anomalous: bool = True
    anomaly_convention_known: bool = True
    strong_anomaly_threshold: float = 0.70

    # Classifier confidence and margin thresholds
    classifier_confidence_threshold: float = 0.60
    margin_threshold: float = 0.15

    def validate(self) -> None:
        """Validate configuration parameters."""
        if self.classifier_weight < 0 or self.anomaly_weight < 0 or self.correlation_weight < 0:
            raise ValueError("Fusion weights must be non-negative.")
        if (self.classifier_weight + self.anomaly_weight + self.correlation_weight) <= 0:
            raise ValueError("Sum of fusion weights must be strictly positive.")


@dataclass
class FusionResult:
    """Structured result produced by the Intelligent Fusion Scorer.

    Conforms to the required Block 4 output contract.
    """
    agent_id: str
    flow_id: str
    final_class: str
    assessment: str
    evidence_status: str
    agent_agreement: Optional[bool]
    classifier_score: Optional[float]
    anomaly_score_normalized: Optional[float]
    correlation_score: Optional[float]
    fusion_score: Optional[float]
    configured_weights: Dict[str, float]
    effective_weights: Dict[str, float]
    risk_level: str
    confidence_level: str
    supporting_evidence: List[str]
    conflicting_evidence: List[str]
    uncertainty: List[str]
    reasoning: str
    investigation_priority: str
    timestamp: Optional[str] = None
    predicted_class_confidence: Optional[float] = None
    top_two_margin: Optional[float] = None
    class_probabilities: Optional[Dict[str, float]] = None
    recommended_action: Optional[str] = None
    explanation: Optional[Dict[str, str]] = None

    @property
    def score_breakdown(self) -> Dict[str, Any]:
        """Convenience property returning structured score contributions and weights."""
        return {
            "classifier_score": self.classifier_score,
            "anomaly_score": self.anomaly_score_normalized,
            "correlation_score": self.correlation_score,
            "configured_weights": dict(self.configured_weights),
            "effective_weights": dict(self.effective_weights),
        }

    def __getitem__(self, item: str) -> Any:
        """Allow subscript indexing on FusionResult."""
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def get(self, key: str, default: Any = None) -> Any:
        """Allow dict-like get method on FusionResult."""
        return getattr(self, key, default)

    def to_threat_assessment(self, processing_time_ms: float = 0.0) -> Agent3ThreatAssessment:
        """Convert FusionResult to formal Agent3ThreatAssessment schema."""
        return Agent3ThreatAssessment(
            agent_id=self.agent_id,
            flow_id=self.flow_id,
            final_class=self.final_class,
            assessment=self.assessment,
            evidence_status=self.evidence_status,
            agent_agreement=self.agent_agreement,
            fusion_score=self.fusion_score,
            risk_level=self.risk_level,
            confidence_level=self.confidence_level,
            supporting_evidence=list(self.supporting_evidence),
            conflicting_evidence=list(self.conflicting_evidence),
            uncertainty=list(self.uncertainty),
            score_breakdown=self.score_breakdown,
            reasoning=self.reasoning,
            investigation_priority=self.investigation_priority,
            timestamp=self.timestamp,
            recommended_action=self.recommended_action,
            explanation=self.explanation,
            processing_time_ms=processing_time_ms,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to clean dictionary matching contract specification."""
        return {
            "agent_id": self.agent_id,
            "flow_id": self.flow_id,
            "final_class": self.final_class,
            "assessment": self.assessment,
            "evidence_status": self.evidence_status,
            "agent_agreement": self.agent_agreement,
            "fusion_score": self.fusion_score,
            "risk_level": self.risk_level,
            "confidence_level": self.confidence_level,
            "supporting_evidence": list(self.supporting_evidence),
            "conflicting_evidence": list(self.conflicting_evidence),
            "uncertainty": list(self.uncertainty),
            "score_breakdown": self.score_breakdown,
            "reasoning": self.reasoning,
            "investigation_priority": self.investigation_priority,
            # Preserved for backward compatibility
            "classifier_score": self.classifier_score,
            "anomaly_score_normalized": self.anomaly_score_normalized,
            "correlation_score": self.correlation_score,
            "configured_weights": dict(self.configured_weights),
            "effective_weights": dict(self.effective_weights),
            "explanation": self.explanation,
        }

    def to_agent3_output(self, processing_time_ms: float = 0.0) -> Agent3Output:
        """Convert FusionResult to Block 1 Agent3Output for backward compatibility."""
        # Map assessment to Verdict enum
        verdict_map = {
            "MALICIOUS": Verdict.MALICIOUS,
            "SUSPICIOUS": Verdict.SUSPICIOUS,
            "BENIGN": Verdict.BENIGN,
            "INCONCLUSIVE": Verdict.INCONCLUSIVE,
        }
        verdict = verdict_map.get(self.assessment, Verdict.INCONCLUSIVE)

        # Map risk level to RecommendedAction
        action_map = {
            "CRITICAL": RecommendedAction.DROP,
            "HIGH": RecommendedAction.ALERT,
            "MEDIUM": RecommendedAction.RATE_LIMIT,
            "LOW": RecommendedAction.LOG_ALLOW,
        }
        rec_action = action_map.get(self.risk_level, RecommendedAction.LOG_ALLOW)

        # Contributing agents
        contributing: List[str] = []
        if self.classifier_score is not None:
            contributing.append("agent_1")
        if self.anomaly_score_normalized is not None:
            contributing.append("agent_2")

        # FusionStatus
        if "agent_1" in contributing and "agent_2" in contributing:
            f_status = FusionStatus.DUAL_AGENT
        elif "agent_1" in contributing:
            f_status = FusionStatus.SINGLE_AGENT_A1_ONLY
        elif "agent_2" in contributing:
            f_status = FusionStatus.SINGLE_AGENT_A2_ONLY
        else:
            f_status = FusionStatus.NO_AGENT_DATA

        # Confidence numeric representation
        conf_num = 0.90 if self.confidence_level == "HIGH" else (
            0.60 if self.confidence_level == "MEDIUM" else 0.30
        )

        return Agent3Output(
            incident_id=f"inc-{uuid.uuid4().hex[:12]}",
            flow_id=self.flow_id,
            timestamp=self.timestamp or "",
            verdict=verdict,
            fused_risk_score=self.fusion_score if self.fusion_score is not None else 0.0,
            confidence=conf_num,
            contributing_agents=contributing,
            fusion_status=f_status,
            threat_summary=self.reasoning,
            details=self.to_dict(),
            recommended_policy_action=rec_action,
            processing_time_ms=processing_time_ms,
        )


class FusionScorer:
    """Deterministic, explainable fusion-scoring engine for Agent 3."""

    def __init__(self, config: Optional[FusionConfig] = None) -> None:
        """Initialize the fusion scorer with optional custom configuration."""
        self.config = config or FusionConfig()
        self.config.validate()
        self.correlator = EvidenceCorrelator(
            low_confidence_threshold=self.config.classifier_confidence_threshold,
            strong_anomaly_threshold=self.config.strong_anomaly_threshold,
        )
        self.explainer = ThreatExplainer()

    def _extract_classifier_score(
        self,
        a1: Optional[Union[Agent1ThreatPrediction, A1DetectionResult, Dict[str, Any]]],
    ) -> Tuple[bool, Optional[float], Optional[str], Optional[float], Optional[float], Optional[Dict[str, float]]]:
        """Compute Classifier Score C = 1 - P(BENIGN) and extract classification metadata."""
        if a1 is None:
            return False, None, None, None, None, None

        # Validate A1 payload
        val_res = validate_agent1_output(a1)
        if not val_res.is_valid:
            return False, None, None, None, None, None

        # Extract raw class, confidence, probabilities
        if isinstance(a1, dict):
            raw_cls = (
                a1.get("predicted_class")
                or a1.get("threat_class")
                or a1.get("class")
                or a1.get("threat_type")
            )
            raw_conf = a1.get("confidence")
            probs = a1.get("probabilities")
        else:
            raw_cls = (
                getattr(a1, "predicted_class", None)
                or getattr(a1, "threat_class", None)
                or getattr(a1, "threat_type", None)
            )
            raw_conf = getattr(a1, "confidence", None)
            probs = getattr(a1, "probabilities", None)

        is_legacy_threat_detected_false = False
        if raw_cls is None:
            if getattr(a1, "threat_detected", None) is False or (isinstance(a1, dict) and a1.get("threat_detected") is False):
                raw_cls = "BENIGN"
                is_legacy_threat_detected_false = True
            else:
                return False, None, None, None, None, None

        if raw_conf is None:
            raw_conf = 0.0

        norm_cls = A1_CLASS_NORMALIZATION.get(str(raw_cls).strip().upper(), str(raw_cls))
        conf = float(raw_conf)

        # Calculate C = 1 - P(BENIGN)
        c_score: float
        top_two_margin: Optional[float] = None

        if probs is not None and isinstance(probs, dict):
            # Check for BENIGN in probability distribution
            p_benign = probs.get("BENIGN")
            if p_benign is None:
                p_benign = probs.get("benign")

            if p_benign is not None and isinstance(p_benign, (int, float)) and math.isfinite(p_benign):
                c_score = 1.0 - float(p_benign)
            else:
                c_score = 1.0 - conf if norm_cls == "BENIGN" else conf

            # Compute top-two margin
            valid_p_vals = [
                float(v) for v in probs.values()
                if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)
            ]
            if len(valid_p_vals) >= 2:
                valid_p_vals.sort(reverse=True)
                top_two_margin = round(valid_p_vals[0] - valid_p_vals[1], 4)
        else:
            # When probabilities distribution is absent:
            if is_legacy_threat_detected_false:
                c_score = conf
            elif norm_cls == "BENIGN":
                c_score = 1.0 - conf
            else:
                c_score = conf

        c_clamped = round(max(0.0, min(1.0, c_score)), 4)
        return True, c_clamped, norm_cls, conf, top_two_margin, probs

    def _extract_anomaly_score(
        self,
        a2: Optional[Union[Agent2AnomalyAssessment, A2DetectionResult, Dict[str, Any]]],
    ) -> Tuple[bool, Optional[float], bool, List[str]]:
        """Normalize Agent 2 anomaly score to [0.0, 1.0] using configured conventions."""
        if a2 is None:
            return False, None, False, []

        val_res = validate_agent2_output(a2)
        if not val_res.is_valid:
            return False, None, False, []

        if isinstance(a2, dict):
            raw_score = a2.get("anomaly_score")
            detected = a2.get("anomaly_detected")
            if detected is None:
                detected = a2.get("is_anomaly")
            ev_raw = a2.get("evidence", [])
        else:
            raw_score = getattr(a2, "anomaly_score", None)
            detected = getattr(a2, "anomaly_detected", getattr(a2, "is_anomaly", None))
            ev_raw = getattr(a2, "evidence", [])

        if raw_score is None or isinstance(raw_score, bool) or not isinstance(raw_score, (int, float)):
            return False, None, False, []

        score_float = float(raw_score)
        if not math.isfinite(score_float):
            return False, None, False, []

        # If anomaly convention is marked unknown or invalid, do not guess
        if not self.config.anomaly_convention_known:
            return False, None, False, []

        is_anom = bool(detected) if detected is not None else (score_float >= self.config.strong_anomaly_threshold)
        ev_list = list(ev_raw) if isinstance(ev_raw, list) else []

        # Continuous normalization
        a_min = self.config.anomaly_min
        a_max = self.config.anomaly_max

        if self.config.anomaly_higher_is_more_anomalous:
            if a_max > a_min:
                norm_a = (score_float - a_min) / (a_max - a_min)
            else:
                norm_a = score_float
        else:
            if a_max > a_min:
                norm_a = (a_max - score_float) / (a_max - a_min)
            else:
                norm_a = 1.0 - score_float

        a_clamped = round(max(0.0, min(1.0, norm_a)), 4)
        return True, a_clamped, is_anom, ev_list

    def _extract_correlation_score(
        self,
        correlation_result: CorrelationResult,
    ) -> Tuple[bool, Optional[float]]:
        """Map Block 3 EvidenceStatus and agent_agreement to Correlation Score R."""
        ev_status = correlation_result.evidence_status

        if ev_status == EvidenceStatus.AGREEMENT:
            if correlation_result.scenario == CorrelationScenario.BOTH_MALICIOUS:
                return True, 1.0
            elif correlation_result.scenario == CorrelationScenario.BOTH_BENIGN:
                return True, 0.0
            else:
                return True, 1.0 if correlation_result.agent_agreement is True else 0.0

        elif ev_status == EvidenceStatus.DISAGREEMENT:
            return True, 0.5

        elif ev_status == EvidenceStatus.PARTIAL_EVIDENCE:
            return True, 0.5

        elif ev_status == EvidenceStatus.INSUFFICIENT_EVIDENCE:
            return False, None

        return False, None

    def score(
        self,
        flow_context: Optional[FlowContext] = None,
        a1_prediction: Optional[Union[Agent1ThreatPrediction, A1DetectionResult, Dict[str, Any]]] = None,
        a2_assessment: Optional[Union[Agent2AnomalyAssessment, A2DetectionResult, Dict[str, Any]]] = None,
        *,
        input_data: Optional[Union[Agent3FusionInput, Agent3Input, Dict[str, Any]]] = None,
        flow_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> FusionResult:
        """Execute deterministic fusion scoring across all available evidence sources.

        Args:
            flow_context: FlowContext defining network flow metadata.
            a1_prediction: Agent 1 threat prediction dataclass or dict.
            a2_assessment: Agent 2 anomaly assessment dataclass or dict.
            input_data: Optional combined input (Agent3FusionInput or Agent3Input).
            flow_id: Optional explicit flow identifier.
            timestamp: Optional explicit timestamp string.

        Returns:
            FusionResult containing full score breakdown, weights, and explanation.
        """
        # Resolve inputs from combined input_data if provided
        if input_data is not None:
            if isinstance(input_data, dict):
                flow_raw = input_data.get("flow_context")
                if isinstance(flow_raw, dict):
                    flow_id = flow_id or flow_raw.get("flow_id")
                    timestamp = timestamp or flow_raw.get("timestamp")
                a1_prediction = a1_prediction or input_data.get("a1_prediction") or input_data.get("a1_result")
                a2_assessment = a2_assessment or input_data.get("a2_assessment") or input_data.get("a2_result")
            else:
                flow_ctx = getattr(input_data, "flow_context", None)
                if flow_ctx is not None:
                    flow_id = flow_id or getattr(flow_ctx, "flow_id", None)
                    timestamp = timestamp or getattr(flow_ctx, "timestamp", None)
                a1_prediction = a1_prediction or getattr(input_data, "a1_prediction", None) or getattr(input_data, "a1_result", None)
                a2_assessment = a2_assessment or getattr(input_data, "a2_assessment", None) or getattr(input_data, "a2_result", None)

        if flow_context is not None:
            flow_id = flow_id or flow_context.flow_id
            timestamp = timestamp or flow_context.timestamp

        fid = flow_id or f"FLOW-{uuid.uuid4().hex[:8]}"
        configured_weights = {
            "classifier": round(self.config.classifier_weight, 4),
            "anomaly": round(self.config.anomaly_weight, 4),
            "correlation": round(self.config.correlation_weight, 4),
        }

        # ---------------------------------------------------------------------
        # 1. Extract Scores from Individual Sources
        # ---------------------------------------------------------------------
        a1_ok, c_score, a1_cls, a1_conf, a1_margin, a1_probs = self._extract_classifier_score(a1_prediction)
        a2_ok, a_score, a2_anom, a2_ev = self._extract_anomaly_score(a2_assessment)

        # Execute Block 3 correlation
        correlation_res = self.correlator.correlate(
            a1_prediction=a1_prediction if a1_ok else None,
            a2_assessment=a2_assessment if a2_ok else None,
        )
        r_ok, r_score = self._extract_correlation_score(correlation_res)

        # ---------------------------------------------------------------------
        # Safeguard 5: If both agents are missing or unusable
        # ---------------------------------------------------------------------
        if not a1_ok and not a2_ok:
            exp_res = self.explainer.explain(
                a1_present=False,
                a1_class=None,
                a1_confidence=None,
                a2_present=False,
                a2_anomalous=False,
                a2_score=None,
                correlation_result=correlation_res,
                fusion_score=None,
                configured_weights=configured_weights,
                effective_weights={"classifier": 0.0, "anomaly": 0.0, "correlation": 0.0},
                risk_level=RiskLevel.UNKNOWN.value,
                confidence_level=ConfidenceLevel.LOW.value,
                assessment=AssessmentVerdict.INCONCLUSIVE.value,
                uncertainties=["Both Agent 1 and Agent 2 evidence missing or unusable."],
                final_class="UNKNOWN",
            )
            return FusionResult(
                agent_id="A3",
                flow_id=fid,
                final_class="UNKNOWN",
                assessment=AssessmentVerdict.INCONCLUSIVE.value,
                evidence_status=EvidenceStatus.INSUFFICIENT_EVIDENCE.value,
                agent_agreement=None,
                classifier_score=None,
                anomaly_score_normalized=None,
                correlation_score=None,
                fusion_score=None,
                configured_weights=configured_weights,
                effective_weights={"classifier": 0.0, "anomaly": 0.0, "correlation": 0.0},
                risk_level=RiskLevel.UNKNOWN.value,
                confidence_level=ConfidenceLevel.LOW.value,
                supporting_evidence=[],
                conflicting_evidence=[],
                uncertainty=["Both Agent 1 and Agent 2 evidence missing or unusable."],
                reasoning=exp_res.full_reasoning,
                investigation_priority=InvestigationPriority.LOW.value,
                timestamp=timestamp,
                explanation=exp_res.to_dict(),
            )

        # ---------------------------------------------------------------------
        # 2. Dynamic Weight Renormalization & Fusion Score Calculation
        # ---------------------------------------------------------------------
        available_weights: Dict[str, float] = {}
        available_scores: Dict[str, float] = {}

        if a1_ok and c_score is not None:
            available_weights["classifier"] = self.config.classifier_weight
            available_scores["classifier"] = c_score

        if a2_ok and a_score is not None:
            available_weights["anomaly"] = self.config.anomaly_weight
            available_scores["anomaly"] = a_score

        if r_ok and r_score is not None:
            available_weights["correlation"] = self.config.correlation_weight
            available_scores["correlation"] = r_score

        sum_w = sum(available_weights.values())
        if sum_w <= 0:
            fusion_score = 0.0
            effective_weights = {k: 0.0 for k in configured_weights}
        else:
            raw_score = sum(available_weights[k] * available_scores[k] for k in available_weights) / sum_w
            fusion_score = round(max(0.0, min(1.0, raw_score)), 4)
            effective_weights = {
                k: round(available_weights.get(k, 0.0) / sum_w, 4)
                for k in configured_weights
            }

        # ---------------------------------------------------------------------
        # 3. Base Risk Level Mapping
        # ---------------------------------------------------------------------
        # 0.00–0.24 = LOW, 0.25–0.49 = MEDIUM, 0.50–0.74 = HIGH, 0.75–1.00 = CRITICAL
        if fusion_score < self.config.low_cutoff:
            risk_level = RiskLevel.LOW
        elif fusion_score < self.config.medium_cutoff:
            risk_level = RiskLevel.MEDIUM
        elif fusion_score < self.config.high_cutoff:
            risk_level = RiskLevel.HIGH
        else:
            risk_level = RiskLevel.CRITICAL

        # ---------------------------------------------------------------------
        # 4. Final Class & Disagreement Safeguards
        # ---------------------------------------------------------------------
        uncertainties: List[str] = []
        supporting = list(correlation_res.supporting_evidence)
        conflicting = list(correlation_res.conflicting_evidence)

        # Class Mapping rule
        if not a1_ok or a1_cls is None:
            final_class = "UNKNOWN"
            uncertainties.append("Agent 1 classifier unavailable; final class marked UNKNOWN.")
        else:
            final_class = a1_cls
            if a1_conf is not None and a1_conf < self.config.classifier_confidence_threshold:
                uncertainties.append(
                    f"Agent 1 confidence ({a1_conf:.2f}) is below threshold "
                    f"({self.config.classifier_confidence_threshold:.2f}); classification uncertainty marked."
                )

        # Baseline Assessment
        if risk_level == RiskLevel.CRITICAL:
            assessment = AssessmentVerdict.MALICIOUS
        elif risk_level == RiskLevel.HIGH:
            assessment = AssessmentVerdict.MALICIOUS if (a1_cls != "BENIGN") else AssessmentVerdict.SUSPICIOUS
        elif risk_level == RiskLevel.MEDIUM:
            assessment = AssessmentVerdict.SUSPICIOUS
        else:
            assessment = AssessmentVerdict.BENIGN

        # --- Safeguard 1: A1 predicts BENIGN but A2 reports strong anomaly ---
        is_strong_a2 = (a2_ok and a_score is not None and a_score >= self.config.strong_anomaly_threshold)
        if a1_ok and a1_cls == "BENIGN" and (is_strong_a2 or a2_anom):
            # Preserve disagreement, do not produce automatic LOW, set minimum risk level HIGH
            if risk_level in (RiskLevel.LOW, RiskLevel.MEDIUM):
                risk_level = RiskLevel.HIGH
            assessment = AssessmentVerdict.SUSPICIOUS
            uncertainties.append(
                f"Disagreement: Agent 1 predicted BENIGN, but Agent 2 detected strong anomaly "
                f"(score: {a_score:.2f}). Potential zero-day or signature evasion."
            )

        # --- Safeguard 2: A1 predicts attack but A2 reports normal behavior ---
        if a1_ok and a1_cls != "BENIGN" and a2_ok and not a2_anom:
            final_class = a1_cls  # Preserve A1 attack classification
            if assessment == AssessmentVerdict.BENIGN:
                assessment = AssessmentVerdict.SUSPICIOUS
            if risk_level == RiskLevel.LOW:
                risk_level = RiskLevel.MEDIUM
            uncertainties.append(
                f"Disagreement: Agent 1 identified {a1_cls} attack signature, but Agent 2 reported "
                f"normal baseline. Malicious signature match is preserved."
            )

        # --- Safeguard 3: A1 is missing ---
        if not a1_ok:
            final_class = "UNKNOWN"
            uncertainties.append("Missing Agent 1 classification evidence; evaluating on partial anomaly evidence.")
            if a2_anom or (a_score is not None and a_score >= self.config.medium_cutoff):
                assessment = AssessmentVerdict.SUSPICIOUS
            else:
                assessment = AssessmentVerdict.INCONCLUSIVE

        # --- Safeguard 4: A2 is missing ---
        if a1_ok and not a2_ok:
            uncertainties.append("Missing Agent 2 anomaly evidence; evaluating on partial classifier evidence.")
            if a1_cls != "BENIGN":
                assessment = AssessmentVerdict.SUSPICIOUS
            else:
                assessment = AssessmentVerdict.BENIGN

        # ---------------------------------------------------------------------
        # 5. Confidence Level Mapping
        # ---------------------------------------------------------------------
        # HIGH: Both agents available, sufficient evidence, and agreement
        # MEDIUM: Both available but evidence incomplete or moderately conflicting
        # LOW: Only one agent available, insufficient evidence, or significant disagreement
        if not a1_ok or not a2_ok:
            confidence_level = ConfidenceLevel.LOW
        elif correlation_res.evidence_status == EvidenceStatus.DISAGREEMENT:
            if a1_conf and a1_conf < self.config.classifier_confidence_threshold:
                confidence_level = ConfidenceLevel.MEDIUM
            else:
                confidence_level = ConfidenceLevel.LOW
        elif correlation_res.evidence_status == EvidenceStatus.AGREEMENT:
            if a1_conf and a1_conf >= self.config.classifier_confidence_threshold and (
                a1_margin is None or a1_margin >= self.config.margin_threshold
            ):
                confidence_level = ConfidenceLevel.HIGH
            else:
                confidence_level = ConfidenceLevel.MEDIUM
        else:
            confidence_level = ConfidenceLevel.LOW

        # ---------------------------------------------------------------------
        # 6. Structured Explanation & Reasoning
        # ---------------------------------------------------------------------
        exp_res = self.explainer.explain(
            a1_present=a1_ok,
            a1_class=final_class if a1_ok else None,
            a1_confidence=a1_conf,
            a1_probabilities=a1_probs,
            a1_margin=a1_margin,
            a2_present=a2_ok,
            a2_anomalous=a2_anom,
            a2_score=a_score,
            a2_evidence=a2_ev,
            correlation_result=correlation_res,
            fusion_score=fusion_score,
            c_score=c_score,
            a_score=a_score,
            r_score=r_score,
            configured_weights=configured_weights,
            effective_weights=effective_weights,
            risk_level=risk_level.value,
            confidence_level=confidence_level.value,
            assessment=assessment.value,
            uncertainties=uncertainties,
            final_class=final_class,
        )
        full_reasoning = exp_res.full_reasoning

        # Investigation Priority aligns with risk and correlation
        if risk_level == RiskLevel.CRITICAL:
            priority = InvestigationPriority.CRITICAL.value
        elif risk_level == RiskLevel.HIGH:
            priority = InvestigationPriority.HIGH.value
        elif risk_level == RiskLevel.MEDIUM:
            priority = InvestigationPriority.MEDIUM.value
        else:
            priority = InvestigationPriority.LOW.value

        return FusionResult(
            agent_id="A3",
            flow_id=fid,
            final_class=final_class,
            assessment=assessment.value,
            evidence_status=correlation_res.evidence_status.value,
            agent_agreement=correlation_res.agent_agreement,
            classifier_score=c_score,
            anomaly_score_normalized=a_score,
            correlation_score=r_score,
            fusion_score=fusion_score,
            configured_weights=configured_weights,
            effective_weights=effective_weights,
            risk_level=risk_level.value,
            confidence_level=confidence_level.value,
            supporting_evidence=supporting,
            conflicting_evidence=conflicting,
            uncertainty=uncertainties,
            reasoning=full_reasoning,
            investigation_priority=priority,
            timestamp=timestamp,
            predicted_class_confidence=a1_conf,
            top_two_margin=a1_margin,
            class_probabilities=a1_probs,
            explanation=exp_res.to_dict(),
        )


def compute_fusion_score(
    flow_context: Optional[FlowContext] = None,
    a1_prediction: Optional[Union[Agent1ThreatPrediction, A1DetectionResult, Dict[str, Any]]] = None,
    a2_assessment: Optional[Union[Agent2AnomalyAssessment, A2DetectionResult, Dict[str, Any]]] = None,
    *,
    input_data: Optional[Union[Agent3FusionInput, Agent3Input, Dict[str, Any]]] = None,
    config: Optional[FusionConfig] = None,
    flow_id: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> FusionResult:
    """Convenience functional interface for intelligent fusion scoring."""
    scorer = FusionScorer(config=config)
    return scorer.score(
        flow_context=flow_context,
        a1_prediction=a1_prediction,
        a2_assessment=a2_assessment,
        input_data=input_data,
        flow_id=flow_id,
        timestamp=timestamp,
    )
