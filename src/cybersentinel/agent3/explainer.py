"""Deterministic, template-based explanation engine for CyberSentinel Agent 3.

Provides transparent, human-readable, and machine-interpretable explanations of:
  - Agent 1 threat classification evidence and confidence.
  - Agent 2 behavioral anomaly indicators and normalized loss.
  - Multi-agent consensus, divergence, and disagreement rationales.
  - Fusion score calculation and dynamic weight renormalization.
  - Risk verdict mapping and safeguard activations.
  - SOC analyst investigation recommendations and priority.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

from cybersentinel.agent3.evidence_correlator import (
    CorrelationResult,
    CorrelationScenario,
    EvidenceStatus,
    InvestigationPriority,
)


@dataclass
class ExplanationResult:
    """Structured explanation result detailing multi-agent triage reasoning.

    Attributes:
        summary: Concise executive summary (2-3 sentences) suitable for dashboard alert headers.
        full_reasoning: Complete evidence-based narrative paragraph explaining all factors.
        agent1_explanation: Specific explanation of Agent 1 classifier detection.
        agent2_explanation: Specific explanation of Agent 2 behavioral anomaly detection.
        correlation_explanation: Rationale for consensus or divergence between agents.
        scoring_explanation: Formula, evidence contributions, and dynamic weights used.
        risk_explanation: Reason for assigned risk level and any safeguards triggered.
        investigation_recommendation: Actionable recommendation for SOC triage.
    """
    summary: str
    full_reasoning: str
    agent1_explanation: str
    agent2_explanation: str
    correlation_explanation: str
    scoring_explanation: str
    risk_explanation: str
    investigation_recommendation: str

    def to_dict(self) -> Dict[str, str]:
        """Convert explanation result to dictionary."""
        return asdict(self)


class ThreatExplainer:
    """Deterministic, template-based explanation engine for CyberSentinel Agent 3.

    Translates multi-agent detection indicators, correlation scenarios, and fusion
    scores into transparent, actionable cybersecurity explanations without relying
    on external LLM APIs.
    """

    def explain_agent1(
        self,
        a1_present: bool,
        a1_class: Optional[str],
        a1_confidence: Optional[float],
        a1_probabilities: Optional[Dict[str, float]] = None,
        a1_margin: Optional[float] = None,
        a1_rule_id: Optional[str] = None,
    ) -> str:
        """Generate explanation of Agent 1 classification evidence."""
        if not a1_present or a1_class is None:
            return "Agent 1 signature classification is unavailable or missing."

        # Qualitative confidence descriptor
        conf = float(a1_confidence or 0.0)
        if conf >= 0.80:
            conf_desc = "high confidence"
        elif conf >= 0.60:
            conf_desc = "moderate confidence"
        else:
            conf_desc = "low confidence"

        if a1_class.upper() == "BENIGN":
            explanation = f"Agent 1 classified this flow as BENIGN with {conf_desc} ({conf:.2f})."
        else:
            explanation = f"Agent 1 classified this flow as {a1_class} with {conf_desc} ({conf:.2f})."

        if a1_rule_id:
            explanation += f" Triggered signature rule '{a1_rule_id}'."

        if a1_margin is not None:
            explanation += f" Top-two class margin is {a1_margin:.2f}."

        return explanation

    def explain_agent2(
        self,
        a2_present: bool,
        a2_anomalous: bool,
        a2_score: Optional[float],
        a2_evidence: Optional[List[str]] = None,
        raw_anomaly_score: Optional[float] = None,
    ) -> str:
        """Generate explanation of Agent 2 behavioral anomaly evidence."""
        if not a2_present or a2_score is None:
            return "Agent 2 behavioral anomaly assessment is unavailable or missing."

        score_val = float(a2_score)
        ev_list = [str(e) for e in (a2_evidence or [])]

        if a2_anomalous or score_val >= 0.70:
            severity = "strong" if score_val >= 0.70 else "moderate"
            explanation = f"Agent 2 independently detected {severity} anomalous behaviour (normalized score: {score_val:.2f})."
            if ev_list:
                ev_str = "; ".join(ev_list[:3])
                explanation += f" Anomalous indicators: {ev_str}."
        elif score_val >= 0.25:
            explanation = f"Agent 2 detected mild/baseline behavioral fluctuations (normalized score: {score_val:.2f})."
            if ev_list:
                ev_str = "; ".join(ev_list[:2])
                explanation += f" Monitored indicators: {ev_str}."
        else:
            explanation = f"Agent 2 reported normal baseline behaviour (normalized score: {score_val:.2f})."

        return explanation

    def explain_correlation(
        self,
        correlation_result: Optional[CorrelationResult],
        a1_class: Optional[str],
        a1_confidence: Optional[float],
        a2_anomalous: bool,
        a2_score: Optional[float],
    ) -> Tuple[str, str]:
        """Generate summary and detailed explanation of agent correlation and consensus."""
        if correlation_result is None:
            return (
                "Multi-agent correlation could not be performed.",
                "Correlation data was not available for evaluation.",
            )

        scenario = correlation_result.scenario
        ev_status = correlation_result.evidence_status

        if scenario == CorrelationScenario.BOTH_MALICIOUS:
            summary = "Both agents support malicious activity."
            detail = (
                f"Both agents agree and corroborate malicious activity. "
                f"Agent 1 detected a {a1_class or 'threat'} signature and Agent 2 independently "
                f"verified anomalous network behavior."
            )

        elif scenario == CorrelationScenario.BOTH_BENIGN:
            summary = "Both agents support benign activity."
            detail = (
                "Both agents agree that the flow conforms to normal benign network patterns with "
                "no anomalous deviations or threat signatures."
            )

        elif scenario == CorrelationScenario.A1_BENIGN_A2_ANOMALY:
            summary = (
                "Agent 1 classified this flow as BENIGN, while Agent 2 detected strong anomalous behaviour. "
                "The agents disagree."
            )
            score_str = f" (score: {a2_score:.2f})" if a2_score is not None else ""
            detail = (
                f"The agents disagree: Agent 1 observed no known attack signature (BENIGN), "
                f"while Agent 2 detected strong anomalous activity{score_str}. "
                f"This divergence indicates a potential zero-day exploit, novel attack vector, "
                f"or signature evasion."
            )

        elif scenario == CorrelationScenario.A1_ATTACK_A2_NORMAL:
            attack_name = a1_class or "attack"
            summary = (
                f"Agent 1 identified a {attack_name} attack, while Agent 2 reported normal behaviour. "
                "The agents disagree."
            )
            detail = (
                f"The agents disagree: Agent 1 identified a {attack_name} signature, "
                f"but Agent 2 reported baseline traffic metrics. "
                f"The malicious classification is preserved because stealthy or low-rate attacks "
                f"often evade volumetric anomaly detection."
            )

        elif scenario == CorrelationScenario.A1_LOW_CONF_A2_SUSPICIOUS:
            attack_name = a1_class or "threat"
            conf_str = f"{a1_confidence:.2f}" if a1_confidence is not None else "low"
            summary = (
                f"Agent 1 reported low-confidence {attack_name} ({conf_str}) and Agent 2 detected anomalous behaviour."
            )
            detail = (
                f"The agents show partial alignment with uncertainty: Agent 1 reported a low-confidence ({conf_str}) "
                f"{attack_name} prediction while Agent 2 detected elevated behavioral anomalies, "
                f"indicating ambiguous activity or early reconnaissance probing."
            )

        elif scenario == CorrelationScenario.A1_MISSING:
            summary = "Agent 1 classification evidence is missing; Agent 2 behavioral assessment is available."
            detail = (
                "Agent 1 signature classification is unavailable. "
                "Operating under partial behavioral evaluation with an UNKNOWN attack class."
            )

        elif scenario == CorrelationScenario.A2_MISSING:
            attack_name = a1_class or "flow"
            summary = "Agent 2 anomaly assessment is missing; Agent 1 classifier assessment is available."
            detail = (
                f"Agent 2 anomaly assessment is unavailable. "
                f"Operating under partial classifier evaluation for {attack_name} without behavioral corroboration."
            )

        else:  # BOTH_INCOMPLETE / INSUFFICIENT_EVIDENCE
            summary = "Both agents provide insufficient evidence."
            detail = (
                "Both Agent 1 and Agent 2 evidence are missing or unusable. "
                "Insufficient evidence to establish threat indicators or consensus."
            )

        return summary, detail

    def explain_scoring(
        self,
        fusion_score: Optional[float],
        c_score: Optional[float],
        a_score: Optional[float],
        r_score: Optional[float],
        configured_weights: Dict[str, float],
        effective_weights: Dict[str, float],
    ) -> str:
        """Generate explanation of the fusion score calculation and dynamic weight renormalization."""
        if fusion_score is None:
            return "Fusion score could not be calculated due to lack of available evidence."

        contributors: List[str] = []
        if effective_weights.get("classifier", 0.0) > 0 and c_score is not None:
            pct = effective_weights["classifier"] * 100.0
            contributors.append(f"Classifier C={c_score:.2f} (weight: {pct:.1f}%)")

        if effective_weights.get("anomaly", 0.0) > 0 and a_score is not None:
            pct = effective_weights["anomaly"] * 100.0
            contributors.append(f"Anomaly A={a_score:.2f} (weight: {pct:.1f}%)")

        if effective_weights.get("correlation", 0.0) > 0 and r_score is not None:
            pct = effective_weights["correlation"] * 100.0
            contributors.append(f"Correlation R={r_score:.2f} (weight: {pct:.1f}%)")

        missing_sources = [k for k, w in effective_weights.items() if w == 0.0]

        if not missing_sources:
            return (
                f"The fusion score of {fusion_score:.2f} was calculated using full multi-source evidence: "
                f"{', '.join(contributors)}."
            )
        else:
            missing_str = ", ".join(missing_sources)
            return (
                f"Due to missing evidence ({missing_str}), weights were dynamically renormalized across "
                f"available sources: {', '.join(contributors)}, yielding a fusion score of {fusion_score:.2f}."
            )

    def explain_risk_and_safeguards(
        self,
        risk_level: str,
        assessment: str,
        fusion_score: Optional[float],
        uncertainties: List[str],
        final_class: str,
    ) -> str:
        """Generate explanation of risk level assignment and triggered safeguards."""
        score_str = f"fusion score {fusion_score:.2f}" if fusion_score is not None else "no score"

        if risk_level == "CRITICAL":
            base = f"Assigned CRITICAL risk level ({score_str} >= 0.75), indicating an imminent, high-severity threat."
        elif risk_level == "HIGH":
            base = f"Assigned HIGH risk level ({score_str}), indicating significant malicious or suspicious activity requiring immediate attention."
        elif risk_level == "MEDIUM":
            base = f"Assigned MEDIUM risk level ({score_str}), indicating moderate risk or uncorroborated indicators."
        elif risk_level == "LOW":
            base = f"Assigned LOW risk level ({score_str}), indicating benign baseline traffic."
        else:
            base = "Assigned UNKNOWN risk level due to lack of usable detection evidence."

        safeguard_notes: List[str] = []
        for u in uncertainties:
            if "Potential zero-day or signature evasion" in u or "Agent 1 predicted BENIGN, but Agent 2 detected strong anomaly" in u:
                safeguard_notes.append("Risk elevated to at least HIGH due to strong anomaly override against benign classification.")
            elif "Malicious signature match is preserved" in u:
                safeguard_notes.append(f"Attack signature ({final_class}) preserved without downgrade to BENIGN.")
            elif "Missing Agent 1" in u or "final class marked UNKNOWN" in u:
                safeguard_notes.append("Final attack class designated as UNKNOWN to prevent fabricating signatures from anomaly evidence.")
            elif "Missing Agent 2" in u:
                safeguard_notes.append("Assessment designated as SUSPICIOUS due to uncorroborated single-agent detection.")

        if safeguard_notes:
            return f"{base} Safeguard notice: {' '.join(safeguard_notes)}"
        return base

    def explain_investigation(
        self,
        investigation_priority: Optional[str] = None,
        priority: Optional[str] = None,
    ) -> str:
        """Generate actionable analyst recommendation based on investigation priority."""
        prio = str(priority or investigation_priority or "LOW").upper()
        if prio == "CRITICAL":
            return (
                "Immediate containment and incident response required (Priority: CRITICAL). "
                "Recommended action: DROP flow and alert SOC tier-2 analysts."
            )
        elif prio == "HIGH":
            return (
                "Further analyst investigation strongly recommended to verify anomalous indicators "
                "and inspect packet payloads (Priority: HIGH). Recommended action: ALERT and isolate host."
            )
        elif prio == "MEDIUM":
            return (
                "Analyst review and traffic rate-limiting recommended (Priority: MEDIUM). "
                "Recommended action: RATE_LIMIT flow and monitor host egress."
            )
        else:
            return (
                "Routine logging and monitoring; no immediate analyst intervention required (Priority: LOW). "
                "Recommended action: LOG_ALLOW."
            )

    def explain(
        self,
        a1_present: bool,
        a1_class: Optional[str],
        a1_confidence: Optional[float],
        a1_probabilities: Optional[Dict[str, float]] = None,
        a1_margin: Optional[float] = None,
        a1_rule_id: Optional[str] = None,
        a2_present: bool = False,
        a2_anomalous: bool = False,
        a2_score: Optional[float] = None,
        a2_evidence: Optional[List[str]] = None,
        correlation_result: Optional[CorrelationResult] = None,
        fusion_score: Optional[float] = None,
        c_score: Optional[float] = None,
        a_score: Optional[float] = None,
        r_score: Optional[float] = None,
        configured_weights: Optional[Dict[str, float]] = None,
        effective_weights: Optional[Dict[str, float]] = None,
        risk_level: str = "UNKNOWN",
        confidence_level: str = "LOW",
        assessment: str = "INCONCLUSIVE",
        uncertainties: Optional[List[str]] = None,
        final_class: Optional[str] = None,
    ) -> ExplanationResult:
        """Compile a complete, deterministic, evidence-based ExplanationResult."""
        cfg_w = configured_weights or {"classifier": 0.50, "anomaly": 0.30, "correlation": 0.20}
        eff_w = effective_weights or {"classifier": 0.0, "anomaly": 0.0, "correlation": 0.0}
        uncert = uncertainties or []
        f_class = final_class or a1_class or "UNKNOWN"

        exp_a1 = self.explain_agent1(
            a1_present=a1_present,
            a1_class=a1_class,
            a1_confidence=a1_confidence,
            a1_probabilities=a1_probabilities,
            a1_margin=a1_margin,
            a1_rule_id=a1_rule_id,
        )

        exp_a2 = self.explain_agent2(
            a2_present=a2_present,
            a2_anomalous=a2_anomalous,
            a2_score=a2_score,
            a2_evidence=a2_evidence,
        )

        corr_summary, exp_corr = self.explain_correlation(
            correlation_result=correlation_result,
            a1_class=a1_class,
            a1_confidence=a1_confidence,
            a2_anomalous=a2_anomalous,
            a2_score=a2_score,
        )

        exp_score = self.explain_scoring(
            fusion_score=fusion_score,
            c_score=c_score,
            a_score=a_score,
            r_score=r_score,
            configured_weights=cfg_w,
            effective_weights=eff_w,
        )

        exp_risk = self.explain_risk_and_safeguards(
            risk_level=risk_level,
            assessment=assessment,
            fusion_score=fusion_score,
            uncertainties=uncert,
            final_class=f_class,
        )

        inv_prio = (
            correlation_result.investigation_priority.value
            if correlation_result is not None
            else InvestigationPriority.LOW.value
        )
        if risk_level == "CRITICAL":
            inv_prio = InvestigationPriority.CRITICAL.value
        elif risk_level == "HIGH":
            inv_prio = InvestigationPriority.HIGH.value

        exp_inv = self.explain_investigation(priority=inv_prio)

        # ---------------------------------------------------------------------
        # Build Executive Summary (matching specified canonical patterns)
        # ---------------------------------------------------------------------
        summary_sentences: List[str] = []

        if not a1_present and not a2_present:
            summary = "Both Agent 1 and Agent 2 evidence are missing or unusable. Insufficient evidence to produce a triage verdict."
        elif a1_present and a1_class != "BENIGN" and a2_present and a2_anomalous:
            summary = (
                f"Agent 1 classified this flow as {a1_class} with high confidence ({a1_confidence:.2f}). "
                f"Agent 2 independently detected strong anomalous behaviour. "
                f"Both agents support malicious activity. "
                f"The combined evidence produced a high fusion score ({fusion_score:.2f}), "
                f"resulting in a {risk_level} risk assessment."
            )
        elif a1_present and a1_class == "BENIGN" and a2_present and a2_anomalous:
            summary = (
                f"Agent 1 classified this flow as BENIGN, while Agent 2 detected strong anomalous behaviour. "
                f"The agents disagree. The flow is flagged as suspicious and requires further investigation."
            )
        elif a1_present and a1_class != "BENIGN" and a2_present and not a2_anomalous:
            summary = (
                f"Agent 1 identified a {a1_class} attack, while Agent 2 reported normal behaviour. "
                f"The agents disagree. The attack prediction is preserved with {risk_level} risk."
            )
        elif a1_present and a1_class == "BENIGN" and a2_present and not a2_anomalous:
            summary = (
                f"Both Agent 1 and Agent 2 support benign activity. "
                f"Flow classified as BENIGN with LOW risk."
            )
        elif not a1_present and a2_present:
            summary = (
                f"Agent 1 evidence is missing; Agent 2 detected {'anomalous' if a2_anomalous else 'normal'} behaviour. "
                f"Operating on partial anomaly evidence with UNKNOWN attack class (Risk: {risk_level})."
            )
        elif a1_present and not a2_present:
            summary = (
                f"Agent 1 classified flow as {a1_class}; Agent 2 anomaly assessment is missing. "
                f"Operating on partial classifier evidence (Risk: {risk_level}, Assessment: {assessment})."
            )
        else:
            summary = (
                f"{corr_summary} Flow evaluated with fusion score {fusion_score if fusion_score is not None else 0.0:.2f} "
                f"resulting in a {risk_level} risk assessment."
            )

        # ---------------------------------------------------------------------
        # Full Reasoning Paragraph
        # ---------------------------------------------------------------------
        full_reasoning_parts = [
            exp_a1,
            exp_a2,
            exp_corr,
            exp_score,
            exp_risk,
            exp_inv,
        ]
        full_reasoning = " ".join(part for part in full_reasoning_parts if part)

        return ExplanationResult(
            summary=summary,
            full_reasoning=full_reasoning,
            agent1_explanation=exp_a1,
            agent2_explanation=exp_a2,
            correlation_explanation=exp_corr,
            scoring_explanation=exp_score,
            risk_explanation=exp_risk,
            investigation_recommendation=exp_inv,
        )


def explain_threat(
    a1_present: bool,
    a1_class: Optional[str],
    a1_confidence: Optional[float],
    a1_probabilities: Optional[Dict[str, float]] = None,
    a1_margin: Optional[float] = None,
    a1_rule_id: Optional[str] = None,
    a2_present: bool = False,
    a2_anomalous: bool = False,
    a2_score: Optional[float] = None,
    a2_evidence: Optional[List[str]] = None,
    correlation_result: Optional[CorrelationResult] = None,
    fusion_score: Optional[float] = None,
    c_score: Optional[float] = None,
    a_score: Optional[float] = None,
    r_score: Optional[float] = None,
    configured_weights: Optional[Dict[str, float]] = None,
    effective_weights: Optional[Dict[str, float]] = None,
    risk_level: str = "UNKNOWN",
    confidence_level: str = "LOW",
    assessment: str = "INCONCLUSIVE",
    uncertainties: Optional[List[str]] = None,
    final_class: Optional[str] = None,
) -> ExplanationResult:
    """Convenience functional interface for generating threat explanations."""
    explainer = ThreatExplainer()
    return explainer.explain(
        a1_present=a1_present,
        a1_class=a1_class,
        a1_confidence=a1_confidence,
        a1_probabilities=a1_probabilities,
        a1_margin=a1_margin,
        a1_rule_id=a1_rule_id,
        a2_present=a2_present,
        a2_anomalous=a2_anomalous,
        a2_score=a2_score,
        a2_evidence=a2_evidence,
        correlation_result=correlation_result,
        fusion_score=fusion_score,
        c_score=c_score,
        a_score=a_score,
        r_score=r_score,
        configured_weights=configured_weights,
        effective_weights=effective_weights,
        risk_level=risk_level,
        confidence_level=confidence_level,
        assessment=assessment,
        uncertainties=uncertainties,
        final_class=final_class,
    )
