"""Adapter module converting Agent 2 evidence into Agent 3 assessment schema."""

from typing import Any, Dict, List, Optional, Union

from dark_trace.agent2.agent3_contract import format_agent2_for_agent3
from dark_trace.common.schemas import Agent2Evidence
from cybersentinel.agent3.contract import AgentStatus
from cybersentinel.agent3.schemas import Agent2AnomalyAssessment


def adapt_agent2_evidence_to_assessment(
    evidence_or_dict: Union[Agent2Evidence, Dict[str, Any]],
    latency_ms: Optional[float] = None,
) -> Agent2AnomalyAssessment:
    """Transform Agent2Evidence payload into Agent2AnomalyAssessment consumed by Agent 3.

    Args:
        evidence_or_dict: Agent2Evidence object or standardized formatted dictionary.
        latency_ms: Optional execution latency in milliseconds.

    Returns:
        Agent2AnomalyAssessment instance ready for Agent 3 evidence fusion.
    """
    if isinstance(evidence_or_dict, Agent2Evidence) or hasattr(evidence_or_dict, "anomaly_detection"):
        try:
            formatted = format_agent2_for_agent3(evidence_or_dict)
        except Exception:
            formatted = evidence_or_dict.to_dict() if hasattr(evidence_or_dict, "to_dict") else {}
    elif isinstance(evidence_or_dict, dict):
        formatted = evidence_or_dict
    else:
        return Agent2AnomalyAssessment(
            agent_id="agent_2",
            status=AgentStatus.ERROR,
            error_message=f"Unsupported Agent 2 output type: {type(evidence_or_dict).__name__}"
        )

    anomaly_data = formatted.get("anomaly_evidence", {})
    if not anomaly_data and "is_anomaly" in formatted:
        # Direct flattened dictionary
        anomaly_data = formatted

    is_anomaly = bool(anomaly_data.get("is_anomaly", False))
    anomaly_score = float(anomaly_data.get("anomaly_score", 0.0))
    anomaly_label = anomaly_data.get("anomaly_label", "ANOMALOUS" if is_anomaly else "NORMAL")

    # Extract human-readable supporting feature descriptions
    evidence_list: List[str] = []
    for feat in anomaly_data.get("supporting_features", []):
        if isinstance(feat, dict):
            name = feat.get("feature_name", "feature")
            z = feat.get("z_score", "")
            evidence_list.append(f"{name} (z={z})" if z != "" else str(name))
        elif isinstance(feat, str):
            evidence_list.append(feat)

    # Attach threat intelligence indicators if present
    threat_intel = formatted.get("threat_intelligence", {})
    if isinstance(threat_intel, dict) and threat_intel.get("matched_indicators"):
        for indicator in threat_intel["matched_indicators"]:
            evidence_list.append(f"ThreatIntel: {indicator}")

    status_val = AgentStatus.SUCCESS if formatted.get("status") != "ERROR" else AgentStatus.ERROR

    return Agent2AnomalyAssessment(
        agent_id="agent_2",
        status=status_val,
        anomaly_detected=is_anomaly,
        anomaly_score=round(anomaly_score, 4),
        anomaly_type=anomaly_label,
        confidence=round(min(1.0, max(0.1, anomaly_score if is_anomaly else (1.0 - anomaly_score))), 4),
        evidence=evidence_list,
        model_version=anomaly_data.get("model_version", "isolation_forest_v1"),
        features=formatted.get("routing_metadata", {}),
        latency_ms=latency_ms or anomaly_data.get("inference_latency_ms"),
    )

