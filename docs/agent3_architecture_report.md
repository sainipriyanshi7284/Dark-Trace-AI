# CyberSentinel Architecture Report: Agent 3 (Contextual Fusion & Triage)

**Status:** Block 1 (Provisional Architecture & Interface Contract)  
**Date:** October 30, 2026  
**Scope:** Integration Contract between Agent 1, Agent 2, Agent 3, and Policy Engine  

---

## 1. Executive Summary

In the **CyberSentinel** multi-agent intrusion detection ecosystem, **Agent 3** serves as the **Contextual Fusion, Alert Correlation, and Decision Coordinator**. 

- **Agent 1 (A1)** performs high-throughput line-rate signature matching and rapid rule-based triage.
- **Agent 2 (A2)** conducts deep behavioral and statistical anomaly analysis (e.g., autoencoders, sequence/graph models) to detect unknown or evolving threat patterns.
- **Agent 3 (A3)** ingests the outputs from A1 and A2, correlates them against network flow context, resolves conflicting or partial indicators, computes a calibrated composite risk score, and produces an actionable structured decision payload for the downstream **Policy Engine**.

---

## 2. Architectural Topology & Information Flow

```
   [ Network Flow / Packet Stream ]
           |              |
           v              v
     +-----------+  +-----------+
     |  Agent 1  |  |  Agent 2  |
     | Signature |  |  Anomaly  |
     |   Triage  |  |  Analysis |
     +-----+-----+  +-----+-----+
           |              |
    A1Detection    A2Detection
           \              /
            v            v
    +------------------------------+
    |           AGENT 3            |
    |  Contextual Fusion & Triage  |
    |   - Flow Key Correlation     |
    |   - Missing-Agent Resilience |
    |   - Evidence Aggregation     |
    +--------------+---------------+
                   |
             Agent3Output
                   |
                   v
       +-----------------------+
       |     Policy Engine     |
       | (Enforcement Actions) |
       +-----------------------+
```

### 2.1 Correlation Mechanism
Incoming detections from A1 and A2 are correlated using a compound key:
- **Primary Correlation Key:** `flow_id` (or standard 5-tuple: `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`).
- **Temporal Alignment Window:** A sliding time window (defaulting to 500ms–2000ms SLA) aligning asynchronous evaluations from A1 (fast path, <5ms) and A2 (deep path, 10–50ms).

### 2.2 Integration Channels
Agent 3 supports two architectural deployment modes:
1. **Direct In-Memory / Pipeline Mode:** Used for synchronous or localized agent pipelines where A1 and A2 pass structured dataclasses (`A1DetectionResult`, `A2DetectionResult`) directly to `Agent3Skeleton.process()`.
2. **Event-Driven Broker Mode:** Detections are ingested via an event bus (e.g., Redis Streams, Kafka, or RabbitMQ) and deserialized via `Agent3Skeleton.process_raw(dict)` for asynchronous distributed triage.

---

## 3. Resilience & Degradation Policy (Missing-Agent Handling)

A critical requirement for Agent 3 is operational resilience when an upstream agent is unavailable, delayed, or experiences an error.

| Scenario | State / FusionStatus | Handling Strategy |
| :--- | :--- | :--- |
| **Dual Agent (Nominal)** | `DUAL_AGENT` | Both A1 and A2 results present. Full contextual fusion and calibrated scoring executed. |
| **A1 Present, A2 Missing** | `SINGLE_AGENT_A1_ONLY` | Evaluates threat purely on A1 signature evidence. Applies an uncertainty penalty to the composite confidence score. Logs telemetry warning. |
| **A2 Present, A1 Missing** | `SINGLE_AGENT_A2_ONLY` | Evaluates threat based on A2 anomaly score. Flags lack of known-signature match. Confidence penalized to account for behavioral false-positive risk. |
| **Both Missing** | `NO_AGENT_DATA` | Returns `INCONCLUSIVE` verdict with baseline zero-risk score and recommended action `LOG_ALLOW`. Triggers system health alert. |

---

## 4. Upstream Owner Confirmation Checklist

Because Agent 1 and Agent 2 implementations are not yet present in the repository, the contract is **PROVISIONAL**. The following parameters must be formally confirmed with the A1 and A2 owners:

1. **Score Normalization:** Confirm whether A1 `confidence` and A2 `anomaly_score` are strictly normalized between `0.0` and `1.0`.
2. **Taxonomy & Class Labels:** Confirm enumeration of threat categories (e.g., `DOS`, `PORT_SCAN`, `EXFILTRATION`, `BEACONING`).
3. **Execution Latency SLA:** Confirm maximum allowed timeout before A3 commits to single-agent degraded evaluation.
4. **Transport Schema:** Confirm whether inputs will arrive via direct in-process calls or serialized JSON over an event queue.

