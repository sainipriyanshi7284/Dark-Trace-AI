"""Evidence correlation engine for CyberSentinel Agent 3 (Block 3).

Independently compares, correlates, and reconciles detection evidence from:
  - Agent 1: Line-rate signature matching and threat classification.
  - Agent 2: Deep behavioral and statistical anomaly assessment.

Identifies multi-agent consensus, conflicting indicators, and incomplete evidence
scenarios without erasing malicious findings or converting missing data to BENIGN.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

from cybersentinel.agent3.contract import A1DetectionResult, A2DetectionResult
from cybersentinel.agent3.schemas import (
    Agent1ThreatPrediction,
    Agent2AnomalyAssessment,
    Agent3FusionInput,
)
from cybersentinel.agent3.validator import (
    A1_CLASS_NORMALIZATION,
    CANONICAL_A1_CLASSES,
)


class EvidenceStatus(str, Enum):
    """Categorical agreement status between Agent 1 and Agent 2 evidence."""
    AGREEMENT = "AGREEMENT"
    DISAGREEMENT = "DISAGREEMENT"
    PARTIAL_EVIDENCE = "PARTIAL_EVIDENCE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class InvestigationPriority(str, Enum):
    """Calibrated security analyst investigation priority level."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CorrelationScenario(str, Enum):
    """Enumeration of the 8 canonical multi-agent correlation scenarios."""
    BOTH_MALICIOUS = "BOTH_MALICIOUS"
    BOTH_BENIGN = "BOTH_BENIGN"
    A1_BENIGN_A2_ANOMALY = "A1_BENIGN_A2_ANOMALY"
    A1_ATTACK_A2_NORMAL = "A1_ATTACK_A2_NORMAL"
    A1_LOW_CONF_A2_SUSPICIOUS = "A1_LOW_CONF_A2_SUSPICIOUS"
    A1_MISSING = "A1_MISSING"
    A2_MISSING = "A2_MISSING"
    BOTH_INCOMPLETE = "BOTH_INCOMPLETE"


@dataclass
class CorrelationResult:
    """Structured correlation result comparing Agent 1 and Agent 2 evidence.

    Attributes:
        evidence_status: Overall evidence relationship (AGREEMENT, DISAGREEMENT,
                         PARTIAL_EVIDENCE, INSUFFICIENT_EVIDENCE).
        agent_agreement: True if both agents agree, False if in conflict,
                         or None (null) if evidence is partial/insufficient.
        supporting_evidence: List of indicators supporting the dominant verdict.
        conflicting_evidence: List of indicators opposing or challenging the verdict.
        investigation_priority: Triage urgency (LOW, MEDIUM, HIGH, CRITICAL).
        correlation_reason: Detailed textual explanation of the correlation logic.
        scenario: Canonical scenario identifier.
        scenario_index: Integer index (1 to 8) matching documented scenarios.
    """
    evidence_status: EvidenceStatus
    agent_agreement: Optional[bool]
    supporting_evidence: List[str]
    conflicting_evidence: List[str]
    investigation_priority: InvestigationPriority
    correlation_reason: str
    scenario: CorrelationScenario
    scenario_index: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert correlation result to dictionary representation."""
        return {
            "evidence_status": self.evidence_status.value,
            "agent_agreement": self.agent_agreement,
            "supporting_evidence": list(self.supporting_evidence),
            "conflicting_evidence": list(self.conflicting_evidence),
            "investigation_priority": self.investigation_priority.value,
            "correlation_reason": self.correlation_reason,
            "scenario": self.scenario.value,
            "scenario_index": self.scenario_index,
        }


class EvidenceCorrelator:
    """Core evidence correlation engine for CyberSentinel Agent 3.

    Core Invariants:
      1. Low anomaly does NOT prove benign traffic.
      2. Missing evidence must NEVER become BENIGN.
      3. A malicious A1 prediction must NOT be erased just because A2 reports normal behavior.
      4. An anomaly reported by A2 with A1 benign indicates potential zero-day or evasion.
    """

    def __init__(
        self,
        low_confidence_threshold: float = 0.60,
        anomaly_threshold: float = 0.50,
        strong_anomaly_threshold: float = 0.70,
    ) -> None:
        """Initialize the evidence correlator.

        Args:
            low_confidence_threshold: Threshold below which A1 confidence is considered low.
            anomaly_threshold: Baseline score above which A2 traffic is considered anomalous.
            strong_anomaly_threshold: Threshold for identifying strong/severe anomalies.
        """
        self.low_confidence_threshold = low_confidence_threshold
        self.anomaly_threshold = anomaly_threshold
        self.strong_anomaly_threshold = strong_anomaly_threshold

    def _extract_a1(
        self,
        a1: Optional[Union[Agent1ThreatPrediction, A1DetectionResult, Dict[str, Any]]],
        explicit_class: Optional[str] = None,
        explicit_conf: Optional[float] = None,
        explicit_probs: Optional[Dict[str, float]] = None,
    ) -> Tuple[bool, Optional[str], float, Optional[Dict[str, float]]]:
        """Extract normalized Agent 1 indicators."""
        if explicit_class is not None:
            norm_cls = A1_CLASS_NORMALIZATION.get(explicit_class.strip().upper(), explicit_class)
            conf = float(explicit_conf) if explicit_conf is not None else 0.0
            return True, norm_cls, conf, explicit_probs

        if a1 is None:
            return False, None, 0.0, None

        if isinstance(a1, dict):
            if not a1:
                return False, None, 0.0, None
            raw_cls = (
                a1.get("predicted_class")
                or a1.get("threat_class")
                or a1.get("class")
                or a1.get("threat_type")
            )
            if not raw_cls:
                return False, None, 0.0, None
            norm_cls = A1_CLASS_NORMALIZATION.get(str(raw_cls).strip().upper(), str(raw_cls))
            conf = float(a1.get("confidence", 0.0))
            probs = a1.get("probabilities")
            return True, norm_cls, conf, probs

        raw_cls = (
            getattr(a1, "predicted_class", None)
            or getattr(a1, "threat_class", None)
            or getattr(a1, "threat_type", None)
        )
        if not raw_cls:
            return False, None, 0.0, None
        norm_cls = A1_CLASS_NORMALIZATION.get(str(raw_cls).strip().upper(), str(raw_cls))
        conf = float(getattr(a1, "confidence", 0.0))
        probs = getattr(a1, "probabilities", None)
        return True, norm_cls, conf, probs

    def _extract_a2(
        self,
        a2: Optional[Union[Agent2AnomalyAssessment, A2DetectionResult, Dict[str, Any]]],
        explicit_status: Optional[Any] = None,
        explicit_score: Optional[float] = None,
        explicit_evidence: Optional[List[str]] = None,
    ) -> Tuple[bool, bool, float, List[str]]:
        """Extract normalized Agent 2 indicators."""
        if explicit_score is not None or explicit_status is not None:
            is_anom = bool(explicit_status) if explicit_status is not None else (
                float(explicit_score or 0.0) >= self.anomaly_threshold
            )
            score = float(explicit_score or 0.0)
            ev = list(explicit_evidence) if explicit_evidence is not None else []
            return True, is_anom, score, ev

        if a2 is None:
            return False, False, 0.0, []

        if isinstance(a2, dict):
            if not a2:
                return False, False, 0.0, []
            score = float(a2.get("anomaly_score", 0.0))
            detected = a2.get("anomaly_detected")
            if detected is None:
                detected = a2.get("is_anomaly")
            is_anom = bool(detected) if detected is not None else (score >= self.anomaly_threshold)
            ev_raw = a2.get("evidence", [])
            ev = list(ev_raw) if isinstance(ev_raw, list) else []
            return True, is_anom, score, ev

        score = float(getattr(a2, "anomaly_score", 0.0))
        detected = getattr(a2, "anomaly_detected", getattr(a2, "is_anomaly", None))
        is_anom = bool(detected) if detected is not None else (score >= self.anomaly_threshold)
        ev_raw = getattr(a2, "evidence", [])
        ev = list(ev_raw) if isinstance(ev_raw, list) else []
        return True, is_anom, score, ev

    def correlate(
        self,
        a1_prediction: Optional[Union[Agent1ThreatPrediction, A1DetectionResult, Dict[str, Any]]] = None,
        a2_assessment: Optional[Union[Agent2AnomalyAssessment, A2DetectionResult, Dict[str, Any]]] = None,
        *,
        fusion_input: Optional[Union[Agent3FusionInput, Any]] = None,
        a1_class: Optional[str] = None,
        a1_confidence: Optional[float] = None,
        a1_probabilities: Optional[Dict[str, float]] = None,
        a2_status: Optional[Any] = None,
        a2_score: Optional[float] = None,
        a2_evidence: Optional[List[str]] = None,
    ) -> CorrelationResult:
        """Compare and correlate Agent 1 and Agent 2 evidence.

        Evaluates evidence across the 8 canonical multi-agent scenarios.

        Returns:
            CorrelationResult detailing consensus, priority, and evidence synthesis.
        """
        # If fusion_input is passed, extract components
        if fusion_input is not None:
            if hasattr(fusion_input, "a1_prediction") and fusion_input.a1_prediction is not None:
                a1_prediction = fusion_input.a1_prediction
            elif hasattr(fusion_input, "a1_result") and fusion_input.a1_result is not None:
                a1_prediction = fusion_input.a1_result

            if hasattr(fusion_input, "a2_assessment") and fusion_input.a2_assessment is not None:
                a2_assessment = fusion_input.a2_assessment
            elif hasattr(fusion_input, "a2_result") and fusion_input.a2_result is not None:
                a2_assessment = fusion_input.a2_result

        # Extract indicators
        a1_present, a1_cls, a1_conf, a1_probs = self._extract_a1(
            a1_prediction, a1_class, a1_confidence, a1_probabilities
        )
        a2_present, a2_anom, a2_score, a2_ev = self._extract_a2(
            a2_assessment, a2_status, a2_score, a2_evidence
        )

        # ---------------------------------------------------------------------
        # Scenario 8: Both agents provide incomplete or missing evidence
        # ---------------------------------------------------------------------
        if not a1_present and not a2_present:
            return CorrelationResult(
                evidence_status=EvidenceStatus.INSUFFICIENT_EVIDENCE,
                agent_agreement=None,
                supporting_evidence=[],
                conflicting_evidence=[],
                investigation_priority=InvestigationPriority.LOW,
                correlation_reason=(
                    "Both agents provided incomplete or missing evidence. "
                    "Insufficient data to establish threat posture."
                ),
                scenario=CorrelationScenario.BOTH_INCOMPLETE,
                scenario_index=8,
            )

        # ---------------------------------------------------------------------
        # Scenario 6: Agent 1 is missing
        # ---------------------------------------------------------------------
        if not a1_present and a2_present:
            supp = [f"Agent 2 reported anomaly_score={a2_score}"]
            if a2_ev:
                supp.extend([f"Agent 2 evidence: {e}" for e in a2_ev])

            priority = (
                InvestigationPriority.HIGH if a2_anom or a2_score >= self.strong_anomaly_threshold
                else InvestigationPriority.MEDIUM
            )
            reason = (
                f"Agent 1 evidence missing; degraded single-agent evaluation on Agent 2 "
                f"(anomaly_detected={a2_anom}, score={a2_score}). "
                f"Missing evidence must never be converted to BENIGN."
            )
            return CorrelationResult(
                evidence_status=EvidenceStatus.PARTIAL_EVIDENCE,
                agent_agreement=None,
                supporting_evidence=supp,
                conflicting_evidence=[],
                investigation_priority=priority,
                correlation_reason=reason,
                scenario=CorrelationScenario.A1_MISSING,
                scenario_index=6,
            )

        # ---------------------------------------------------------------------
        # Scenario 7: Agent 2 is missing
        # ---------------------------------------------------------------------
        if a1_present and not a2_present:
            a1_is_attack = a1_cls != "BENIGN"
            supp = [f"Agent 1 predicted {a1_cls} (confidence: {a1_conf})"]
            if a1_probs:
                supp.append(f"Agent 1 probabilities: {a1_probs}")

            if a1_is_attack:
                priority = (
                    InvestigationPriority.CRITICAL if a1_conf >= 0.85
                    else InvestigationPriority.HIGH
                )
            else:
                priority = InvestigationPriority.LOW

            reason = (
                f"Agent 2 evidence missing; degraded single-agent evaluation on Agent 1 "
                f"(threat_class={a1_cls}, confidence={a1_conf}). "
                f"Missing evidence must never be converted to BENIGN."
            )
            return CorrelationResult(
                evidence_status=EvidenceStatus.PARTIAL_EVIDENCE,
                agent_agreement=None,
                supporting_evidence=supp,
                conflicting_evidence=[],
                investigation_priority=priority,
                correlation_reason=reason,
                scenario=CorrelationScenario.A2_MISSING,
                scenario_index=7,
            )

        # At this stage, both agents are present and valid
        assert a1_cls is not None
        a1_is_attack = (a1_cls != "BENIGN")
        a1_low_conf = (a1_conf < self.low_confidence_threshold)
        a2_is_suspicious = a2_anom or (a2_score >= self.anomaly_threshold)
        a2_strong_anomaly = a2_anom and (a2_score >= self.strong_anomaly_threshold or bool(a2_ev))

        # ---------------------------------------------------------------------
        # Scenario 5: A1 has low confidence and A2 reports suspicious activity
        # ---------------------------------------------------------------------
        if a1_low_conf and a2_is_suspicious:
            supp = [
                f"Agent 2 flagged suspicious behavioral activity (score: {a2_score})",
            ]
            if a2_ev:
                supp.extend([f"Agent 2 evidence: {e}" for e in a2_ev])
            conflicts = [
                f"Agent 1 confidence is weak ({a1_conf:.2f} for predicted class '{a1_cls}')"
            ]
            return CorrelationResult(
                evidence_status=EvidenceStatus.DISAGREEMENT,
                agent_agreement=False,
                supporting_evidence=supp,
                conflicting_evidence=conflicts,
                investigation_priority=InvestigationPriority.HIGH,
                correlation_reason=(
                    f"Agent 1 has low confidence ({a1_conf:.2f}) while Agent 2 reports "
                    f"suspicious behavioral activity (score: {a2_score}). "
                    f"Escalated for deeper correlation and investigation."
                ),
                scenario=CorrelationScenario.A1_LOW_CONF_A2_SUSPICIOUS,
                scenario_index=5,
            )

        # ---------------------------------------------------------------------
        # Scenario 1: Both agents support malicious activity
        # ---------------------------------------------------------------------
        if a1_is_attack and a2_is_suspicious:
            supp = [
                f"Agent 1 detected {a1_cls} signature (confidence: {a1_conf:.2f})",
                f"Agent 2 corroborated anomaly (score: {a2_score:.2f})",
            ]
            if a2_ev:
                supp.extend([f"Agent 2 evidence: {e}" for e in a2_ev])

            return CorrelationResult(
                evidence_status=EvidenceStatus.AGREEMENT,
                agent_agreement=True,
                supporting_evidence=supp,
                conflicting_evidence=[],
                investigation_priority=InvestigationPriority.CRITICAL,
                correlation_reason=(
                    f"Multi-agent consensus: Both Agent 1 ({a1_cls}, conf={a1_conf:.2f}) and "
                    f"Agent 2 (anomaly_score={a2_score:.2f}) support malicious activity."
                ),
                scenario=CorrelationScenario.BOTH_MALICIOUS,
                scenario_index=1,
            )

        # ---------------------------------------------------------------------
        # Scenario 2: Both agents support benign / normal behaviour
        # ---------------------------------------------------------------------
        if not a1_is_attack and not a2_is_suspicious:
            supp = [
                f"Agent 1 classified traffic as BENIGN (confidence: {a1_conf:.2f})",
                f"Agent 2 observed normal baseline (anomaly_score: {a2_score:.2f})",
            ]
            return CorrelationResult(
                evidence_status=EvidenceStatus.AGREEMENT,
                agent_agreement=True,
                supporting_evidence=supp,
                conflicting_evidence=[],
                investigation_priority=InvestigationPriority.LOW,
                correlation_reason=(
                    f"Multi-agent consensus: Both Agent 1 (BENIGN, conf={a1_conf:.2f}) and "
                    f"Agent 2 (normal baseline, score={a2_score:.2f}) confirm benign traffic."
                ),
                scenario=CorrelationScenario.BOTH_BENIGN,
                scenario_index=2,
            )

        # ---------------------------------------------------------------------
        # Scenario 3: A1 predicts BENIGN but A2 detects a strong anomaly
        # ---------------------------------------------------------------------
        if not a1_is_attack and a2_is_suspicious:
            supp = [
                f"Agent 2 detected strong behavioral anomaly (score: {a2_score:.2f})",
            ]
            if a2_ev:
                supp.extend([f"Agent 2 evidence: {e}" for e in a2_ev])
            conflicts = [
                f"Agent 1 predicted BENIGN (confidence: {a1_conf:.2f})",
            ]
            return CorrelationResult(
                evidence_status=EvidenceStatus.DISAGREEMENT,
                agent_agreement=False,
                supporting_evidence=supp,
                conflicting_evidence=conflicts,
                investigation_priority=InvestigationPriority.HIGH,
                correlation_reason=(
                    f"Indicator divergence: Agent 1 predicted BENIGN, but Agent 2 detected a "
                    f"strong anomaly (score: {a2_score:.2f}). Indicates potential zero-day, "
                    f"novel attack pattern, or signature evasion."
                ),
                scenario=CorrelationScenario.A1_BENIGN_A2_ANOMALY,
                scenario_index=3,
            )

        # ---------------------------------------------------------------------
        # Scenario 4: A1 predicts an attack but A2 reports normal behaviour
        # ---------------------------------------------------------------------
        if a1_is_attack and not a2_is_suspicious:
            supp = [
                f"Agent 1 identified specific threat signature: {a1_cls} (confidence: {a1_conf:.2f})",
            ]
            conflicts = [
                f"Agent 2 reports normal baseline behavior (score: {a2_score:.2f})",
            ]
            return CorrelationResult(
                evidence_status=EvidenceStatus.DISAGREEMENT,
                agent_agreement=False,
                supporting_evidence=supp,
                conflicting_evidence=conflicts,
                investigation_priority=InvestigationPriority.HIGH,
                correlation_reason=(
                    f"Indicator divergence: Agent 1 identified attack signature {a1_cls} "
                    f"(confidence: {a1_conf:.2f}) while Agent 2 reports normal behavior. "
                    f"A malicious A1 prediction must not be erased because A2 observed normal behavior."
                ),
                scenario=CorrelationScenario.A1_ATTACK_A2_NORMAL,
                scenario_index=4,
            )

        # Fallback (safety net)
        return CorrelationResult(
            evidence_status=EvidenceStatus.PARTIAL_EVIDENCE,
            agent_agreement=None,
            supporting_evidence=[],
            conflicting_evidence=[],
            investigation_priority=InvestigationPriority.MEDIUM,
            correlation_reason="Inconclusive correlation under current evidence thresholds.",
            scenario=CorrelationScenario.BOTH_INCOMPLETE,
            scenario_index=8,
        )


def correlate_evidence(
    a1_prediction: Optional[Union[Agent1ThreatPrediction, A1DetectionResult, Dict[str, Any]]] = None,
    a2_assessment: Optional[Union[Agent2AnomalyAssessment, A2DetectionResult, Dict[str, Any]]] = None,
    *,
    fusion_input: Optional[Union[Agent3FusionInput, Any]] = None,
    a1_class: Optional[str] = None,
    a1_confidence: Optional[float] = None,
    a1_probabilities: Optional[Dict[str, float]] = None,
    a2_status: Optional[Any] = None,
    a2_score: Optional[float] = None,
    a2_evidence: Optional[List[str]] = None,
    low_confidence_threshold: float = 0.60,
    anomaly_threshold: float = 0.50,
    strong_anomaly_threshold: float = 0.70,
) -> CorrelationResult:
    """Convenience functional interface to correlate Agent 1 and Agent 2 evidence."""
    correlator = EvidenceCorrelator(
        low_confidence_threshold=low_confidence_threshold,
        anomaly_threshold=anomaly_threshold,
        strong_anomaly_threshold=strong_anomaly_threshold,
    )
    return correlator.correlate(
        a1_prediction=a1_prediction,
        a2_assessment=a2_assessment,
        fusion_input=fusion_input,
        a1_class=a1_class,
        a1_confidence=a1_confidence,
        a1_probabilities=a1_probabilities,
        a2_status=a2_status,
        a2_score=a2_score,
        a2_evidence=a2_evidence,
    )

