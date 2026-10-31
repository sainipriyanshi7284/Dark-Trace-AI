"""Agent 3 Evidence Fusion Integration Contract and Payload Formatter.

This module establishes the formal integration interface between Agent 2
(Network Anomaly Detection) and Agent 3 (Evidence Fusion).

ARCHITECTURE CONTRACT:
- Agent 1: Supervised threat classification (e.g. predicted_class, classifier_confidence).
- Agent 2: Unsupervised statistical anomaly detection (Isolation Forest anomaly score,
  calibrated threshold, categorical label, and disabled threat intelligence).
- Agent 3: Evidence fusion engine that combines Agent 1 and Agent 2 evidence to formulate
  the final composite risk assessment and mitigation recommendation.

MANDATORY INDEPENDENCE RULE:
- Agent 2 operates independently of Agent 1.
- Agent 2 NEVER ingests or requires Agent 1's outputs.
- If Agent 1 is offline or delayed, Agent 2 evidence remains 100% valid and consumable by Agent 3.
- If Agent 2 is offline, Agent 1 evidence remains 100% valid and consumable by Agent 3.
"""

from typing import Any, Dict, Optional


def format_agent2_for_agent3(evidence: Any) -> Dict[str, Any]:
    """Format Agent2 evidence into the standardized payload for Agent 3 fusion.

    Handles instances of Agent2Evidence, dictionaries, or legacy evidence records.

    Args:
        evidence: Agent2Evidence instance, dictionary, or evidence object.

    Returns:
        Dict[str, Any]: Standardized evidence package containing:
            - agent_id: 'A2'
            - flow_id: Flow identifier for cross-agent correlation
            - timestamp: Evidence generation timestamp
            - anomaly_evidence: ML outlier classification, scores, and threshold
            - threat_intelligence: Standardized disabled threat intelligence block
            - routing_metadata: Source/destination IPs, ports, and protocol
    """
    if hasattr(evidence, "to_dict"):
        data = evidence.to_dict()
    elif isinstance(evidence, dict):
        data = dict(evidence)
    else:
        raise ValueError(f"Expected Agent2Evidence or dict, got {type(evidence).__name__}")

    # Standardized new Agent2 schema
    if "anomaly_evidence" in data:
        anom = data.get("anomaly_evidence", {})
        threat = data.get("threat_intelligence", {
            "status": "DISABLED",
            "investigation_status": "NOT_APPLICABLE",
            "is_enriched": False,
        })
        routing = data.get("routing_metadata", {})
        return {
            "agent_id": data.get("agent_id", "A2"),
            "flow_id": str(data.get("flow_id", "unknown")),
            "timestamp": data.get("timestamp", ""),
            "anomaly_evidence": anom,
            "threat_intelligence": threat,
            "routing_metadata": routing,
        }

    # Legacy payload mapping (e.g., from old common schemas)
    ad = data.get("anomaly_detection", {})
    return {
        "agent_id": data.get("agent_id", "A2"),
        "flow_id": str(data.get("flow_id", "unknown")),
        "timestamp": data.get("timestamp", ""),
        "anomaly_evidence": {
            "status": "EVALUATED" if ad.get("is_anomaly") is not None else "MODEL_NOT_READY",
            "is_anomaly": ad.get("is_anomaly"),
            "anomaly_label": ad.get("anomaly_label", "UNKNOWN"),
            "raw_score": ad.get("raw_anomaly_score"),
            "normalized_score": ad.get("normalized_anomaly_score"),
            "anomaly_score": ad.get("normalized_anomaly_score") or ad.get("raw_anomaly_score", 0.0),
            "threshold": ad.get("threshold"),
            "decision_threshold": ad.get("threshold"),
            "model_version": ad.get("model_version", "isolation_forest_v1"),
            "supporting_features": ad.get("supporting_features", []),
            "inference_latency_ms": ad.get("inference_latency_ms"),
        },
        "threat_intelligence": data.get("threat_intelligence", {
            "status": "DISABLED",
            "investigation_status": "NOT_APPLICABLE",
            "is_enriched": False,
        }),
        "routing_metadata": data.get("metadata", {}),
    }


def create_agent3_composite_handover(
    flow_id: str,
    agent2_evidence: Optional[Any] = None,
    agent1_evidence: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Demonstrate composite multi-agent evidence handover to Agent 3.

    Proves architectural independence: Agent 3 can receive either agent's evidence
    alone or both simultaneously.

    Args:
        flow_id: Unique flow identifier.
        agent2_evidence: Optional Agent 2 evidence.
        agent1_evidence: Optional Agent 1 evidence.

    Returns:
        Dict[str, Any]: Handover bundle ready for Agent 3 fusion logic.
    """
    a2_payload = format_agent2_for_agent3(agent2_evidence) if agent2_evidence is not None else None

    return {
        "flow_id": flow_id,
        "agent1_available": agent1_evidence is not None,
        "agent2_available": a2_payload is not None,
        "agent1_evidence": agent1_evidence,
        "agent2_evidence": a2_payload,
    }
