# Dark-Trace-AI — Agent 2: Phase 2 (A2-B4) Documentation
## Explainability Engine, Batch Processing & Agent 3 Integration Guide

---

### Overview

This guide documents the statistical explainability engine, resilient batch processing orchestrator, and Agent 3 evidence integration contract implemented in **Agent 2 Phase 2 (A2-B4)**:
1. **Explainability Engine (`AnomalyExplainer`)**: Derives statistical feature deviation evidence without claiming unsupported causality.
2. **Batch Processing Engine (`BatchAnomalyProcessor`)**: High-throughput multi-flow inference pipeline with partial failure isolation.
3. **Agent 3 Evidence Contract (`dark_trace.agent2.agent3_contract`)**: Integration payload format and verification of strict independence from Agent 1.

---

### 1. Explainability Engine (`AnomalyExplainer`)

Location: [`src/dark_trace/agent2/explainability.py`](file:///Users/parth/Documents/agenticai/Dark-Trace-AI/src/dark_trace/agent2/explainability.py)

#### Statistical Methodology
Isolation Forest identifies anomalies by isolating outliers in sparse regions of the feature space, but it does not natively provide per-sample causal attributions. The `AnomalyExplainer` provides defensible statistical evidence by computing:
- **Baseline Reference Median**: $\mu_{1/2, j}$ learned during training.
- **Robust Dispersion Scale**: Standard deviation $\sigma_j$ (with epsilon guard $\ge 1e-6$ preventing zero division).
- **Normalized Deviation**:
  $$z_j = \frac{|x_j - \mu_{1/2, j}|}{\sigma_j + \epsilon}$$
- **Directional Tagging**:
  - `HIGH`: $x_j > \mu_{1/2, j}$
  - `LOW`: $x_j < \mu_{1/2, j}$
  - `NORMAL`: within baseline tolerance.

#### Critical Non-Causality Rules
- Feature deviations are strictly **supporting statistical evidence**, not proven root causes.
- The normalized anomaly score is an **outlier severity index**, NOT a calibrated probability.
- If feature statistics are unavailable, the engine gracefully reports cluster divergence without fabricating artificial feature attributions.

---

### 2. Batch Processing Pipeline (`BatchAnomalyProcessor`)

Location: [`src/dark_trace/agent2/batch.py`](file:///Users/parth/Documents/agenticai/Dark-Trace-AI/src/dark_trace/agent2/batch.py)

#### Resilient Ingestion & Failure Isolation
When a batch of network flows arrives:
1. **Validation**: Each record is validated against `NetworkFlow`.
2. **Fault Isolation**: If a record has an invalid IP address or out-of-range port, it is logged into `errors` with its record index and error message. **Valid flows continue processing without interruption.**
3. **Batch Scoring**: Valid flows are scored through `TrainedAnomalyModel.score_batch()` in a single vector operation.
4. **Evidence Generation**: Every valid flow produces a fully structured `Agent2Evidence` payload preserving its unique `flow_id`.

#### Return Structure (`BatchProcessingResult`)
- `total_records`: Count of records submitted.
- `valid_count`: Successfully validated and scored records.
- `invalid_count`: Count of malformed records isolated.
- `anomalous_count`: Flows flagged as anomalous.
- `normal_count`: Flows flagged as normal baseline.
- `evidence`: List of `Agent2Evidence` objects.
- `errors`: List of error records containing index, error string, and raw identifier.
- `processing_time_ms`: Total execution latency in milliseconds.

---

### 3. Agent 3 Integration Contract & Multi-Agent Independence

Location: [`src/dark_trace/agent2/agent3_contract.py`](file:///Users/parth/Documents/agenticai/Dark-Trace-AI/src/dark_trace/agent2/agent3_contract.py)

#### Multi-Agent Workflow
```
NETWORK FLOW
    │
    ├───► AGENT 1 (Supervised: predicted_class, classifier_confidence)
    │
    └───► AGENT 2 (Isolation Forest: normalized_severity, supporting_features)
              │
              ▼
         AGENT 2 EVIDENCE
              │
    ┌─────────┴─────────┐
    ▼                   ▼
AGENT 3             AGENT 4
Evidence Fusion     Simulated Policy
```

#### Independence Rules
1. **Zero Input Dependency**: Agent 2 ingests raw network flows directly and does **not** consume Agent 1's outputs.
2. **Partial Evidence Resilience**:
   - If Agent 1 is unavailable, Agent 2 evidence is delivered to Agent 3 with `agent1_available: false`.
   - If Agent 2 is unavailable, Agent 1 evidence is delivered to Agent 3 with `agent2_available: false`.
   - When both are available, Agent 3 combines supervised attack classification with unsupervised anomaly severity.

---

### 4. Running the Tests

```bash
PYTHONPATH=src ./.venv/bin/python -m unittest discover -s tests/agent2 -p "test_*.py" -v
```
All 60 tests execute in $< 0.3$s.
