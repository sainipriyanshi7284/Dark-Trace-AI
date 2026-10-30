# Dark-Trace-AI — Agent 2: Comprehensive Architecture & Final Acceptance Report
## Intelligent Anomaly Detection & Threat Intelligence

---

### Executive Summary

**Agent 2** in the **Dark-Trace-AI** multi-agent cybersecurity intrusion detection and adaptive defense simulation system is fully implemented, verified, and documented across all planned phases:
- **Block 1 (A2-B1)**: Repository Intelligence, System Analysis & Architecture Design (`dfd9af9`).
- **Block 2 (A2-B2)**: Data Schemas, Feature Preprocessing & Validation Pipeline (`69ae4a0`).
- **Phase 1 (A2-B3)**: Isolation Forest Anomaly Detection & Training Pipeline (`e25aaa5`).
- **Phase 2 (A2-B4)**: Explainability Engine, Batch Processing & Agent 3 Contract (`a648353`).
- **Phase 3 (A2-B5)**: TinyFish Threat Intelligence Integration (Strict Free-Tier) & End-to-End System Verification.

---

### 1. End-to-End System Architecture

```
                       [ Live Network Flow Stream ]
                                    │
           ┌────────────────────────┴────────────────────────┐
           ▼                                                 ▼
  ┌──────────────────┐                             ┌──────────────────┐
  │     AGENT 1      │                             │     AGENT 2      │
  │ Supervised Model │                             │  Anomaly & Intel │
  │  (XGBoost / RF)  │                             │ (Isolation Forest│
  │                  │                             │   + TinyFish)    │
  └────────┬─────────┘                             └────────┬─────────┘
           │ [predicted_class + confidence]                 │ [anomaly_score + features + intel]
           └────────────────────────┬───────────────────────┘
                                    ▼
                           ┌──────────────────┐
                           │     AGENT 3      │
                           │  Evidence Fusion │
                           └────────┬─────────┘
                                    │ [composite_threat_assessment]
                                    ▼
                           ┌──────────────────┐
                           │     AGENT 4      │
                           │ Simulated Policy │
                           └────────┬─────────┘
                                    ▼
                         [ ALLOW / BLOCK / REVIEW ]
```

#### Mandatory Independence Verification:
- **Zero Input Dependency**: Agent 2 operates independently of Agent 1. It receives raw network flows directly and does **not** consume Agent 1's predictions or classifier confidence.
- **Partial Evidence Resilience**: If Agent 1 is unavailable, Agent 2 supplies complete evidence to Agent 3. If Agent 2 is unavailable, Agent 1 supplies evidence to Agent 3.

---

### 2. Complete Agent 2 Internal Pipeline

```
[ Ingested NetworkFlow ]
          │
          ▼
[ 1. Ingestion Validation ] ──► Rejects out-of-range ports, malformed IPs (ValidationError)
          │
          ▼
[ 2. AnomalyPreprocessor ]  ──► Strips labels (no target leakage), imputes NaNs, clips infs
          │
          ▼
[ 3. Isolation Forest ]     ──► Tree ensemble outlier detection (scikit-learn 1.9.1)
          │
          ▼
[ 4. Score Calibration ]    ──► Calibrates raw decision score into [0.0, 1.0] severity index
          │
          ▼
[ 5. Explainability ]       ──► Extracts top statistical supporting features (AnomalyExplainer)
          │
          ▼
[ 6. TinyFish Intel ]       ──► Selective Search & Fetch on public indicators (Free-Tier Only)
          │
          ▼
[ 7. Agent2Evidence ]       ──► Formats structured evidence bundle for Agent 3
```

---

### 3. Module Inventory & Responsibilities

| File Path | Component | Responsibility |
| :--- | :--- | :--- |
| `src/dark_trace/common/schemas.py` | `NetworkFlow`, `Agent2Evidence` | Ingestion & evidence data contracts with full validation and JSON serialization. |
| `src/dark_trace/common/ip_utils.py` | `ip_utils` | IPv4/IPv6 classification, RFC 1918 / RFC 4193 identification, public indicator filter. |
| `src/dark_trace/agent2/config.py` | `Agent2Config` | Hyperparameters, feature lists, and threat intelligence thresholds. |
| `src/dark_trace/agent2/preprocessor.py`| `AnomalyPreprocessor` | Target leakage stripping, median imputation, infinity clipping, column ordering. |
| `src/dark_trace/agent2/model.py` | `IsolationForestModel` | Scikit-learn wrapper with matrix validation and fitted state checks. |
| `src/dark_trace/agent2/trainer.py` | `ModelTrainer`, `TrainedAnomalyModel` | Unlabelled training pipeline and baseline score distribution calibration. |
| `src/dark_trace/agent2/scoring.py` | `scoring` | Monotonic mapping from raw scores to bounded $[0.0, 1.0]$ severity indices. |
| `src/dark_trace/agent2/persistence.py`| `persistence` | Serializes and restores `model.joblib` and `metadata.json` with integrity checks. |
| `src/dark_trace/agent2/explainability.py`| `AnomalyExplainer` | Statistical feature deviation evidence and human-readable analyst narratives. |
| `src/dark_trace/agent2/batch.py` | `BatchAnomalyProcessor` | Resilient batch execution with partial failure isolation. |
| `src/dark_trace/agent2/agent3_contract.py`| `agent3_contract` | Evidence formatting and composite multi-agent handover bundle creation. |
| `src/dark_trace/agent2/threat_intel/client.py` | `TinyFishClient` | Free-Tier Search & Fetch client with local 30 req/min rate limiter. |
| `src/dark_trace/agent2/threat_intel/triggers.py` | `ThreatIntelTriggerPolicy` | Public indicator gate, severity thresholding, and 1-hour LRU cache. |
| `src/dark_trace/agent2/threat_intel/investigator.py`| `ThreatIntelInvestigator` | Formulates search queries and extracts structured findings with source attribution. |
| `src/dark_trace/agent2/agent.py` | `AnomalyAgent2` | Unified coordinator linking all subsystems into a single entry point. |

---

### 4. Test Suite Verification (77 Tests, 100% Pass)

```bash
$ PYTHONPATH=src ./.venv/bin/python -m unittest discover -s tests/agent2 -p "test_*.py" -v
Ran 77 tests in 0.712s — OK (0 failures, 0 errors, 0 skipped)
```

#### Test Suite Breakdown:
1. `test_ip_utils.py` (7 tests): IPv4/IPv6 validation, RFC 1918 private IPv4, RFC 4193 unique-local IPv6, loopback, link-local, multicast, CGNAT, public routing indicators.
2. `test_schemas.py` (7 tests): Data contracts, port validation, IP validation, feature dictionary validation, JSON roundtrip serialization.
3. `test_preprocessor.py` (11 tests): Target label exclusion, median imputation of missing/NaN, infinite value clipping, column ordering, serialization.
4. `test_scoring.py` (5 tests): Score monotonicity, $[0, 1]$ bounds, decision threshold boundary semantics, baseline training stats calibration.
5. `test_model.py` (9 tests): Parameter sanity checks, matrix validation, NaN/inf guards, fitted state enforcement, scikit-learn wrapper behavior.
6. `test_trainer.py` (3 tests): ModelTrainer execution, baseline score capture, single and batch record scoring.
7. `test_persistence.py` (5 tests): Joblib save/load roundtrip, missing file errors, corrupted JSON metadata detection.
8. `test_explainability.py` (4 tests): Statistical feature deviations, zero dispersion guard, normal vs anomalous narrative generation.
9. `test_batch.py` (5 tests): Empty batches, valid batches, mixed batches with partial failures isolated, flow ID preservation.
10. `test_agent3_contract.py` (4 tests): Agent 3 payload structuring, multi-agent independence, partial evidence handovers.
11. `test_tinyfish.py` (8 tests): Search API parsing, Fetch API parsing, 401 auth handling, 429 rate limit handling, private IP rejection, quota threshold gate, caching layer, missing API key degradation.
12. `test_agent_e2e.py` (9 tests): All 9 operational scenarios verified.

---

### 5. Verification of the 9 Operational Scenarios

| # | Scenario | Tested Behavior | Verified Outcome |
| :--- | :--- | :--- | :--- |
| **1** | Normal network traffic | Flows within baseline distribution scored | Classified as `NORMAL` ($S < 0.50$, raw score $> 0.0$). |
| **2** | Known attack traffic | Volumetric flood (75k packets, 85 MB/s) | Classified as `ANOMALOUS` ($S = 1.00$, top supporting features identified). |
| **3** | Unusual traffic (Zero-day) | Abnormal micro-burst packet density | Flagged as `ANOMALOUS` ($S > 0.70$) without requiring attack signature. |
| **4** | Suspicious public IP | Severe anomaly with public IP destination | TinyFish Search API triggered, findings and source URLs populated. |
| **5** | TinyFish unavailable | Unconfigured API key or network down | Status marked `UNAVAILABLE`; ML anomaly detection continues 100% unaffected. |
| **6** | Agent 1 & Agent 2 disagreeing | Agent 1 predicts Benign; Agent 2 flags Anomaly | Agent 3 receives divergent evidence, allowing SOC review of novel threat. |
| **7** | Mixed batch execution | Batch containing valid flows and bad IPs/ports | Invalid records isolated into `errors`; valid flows scored without interruption. |
| **8** | Agent 1 unavailable | Agent 1 offline | Handover bundle delivers complete Agent 2 evidence with `agent1_available: false`. |
| **9** | Agent 2 unavailable | Agent 2 offline | Handover bundle delivers Agent 1 evidence with `agent2_available: false`. |

---

### 6. Free-Tier Compliance & Security Safeguards

1. **TinyFish Free-Tier Restriction**:
   - Uses **Search API** and **Fetch API** exclusively.
   - Strictly prohibits Agent API, Browser API, and paid metered endpoints.
   - Local sliding-window rate limiter prevents exceeding the 30 req/min ceiling.
2. **Private IP Data Exfiltration Protection**:
   - RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and RFC 4193 IPs are **never** queried to external web services.
3. **Credential Security**:
   - `.env` is ignored by `.gitignore`. Template provided in `.env.example`.
   - API keys are loaded dynamically via `os.environ.get("TINYFISH_API_KEY")`.
   - Zero hardcoded credentials in source code or tests.
4. **Non-Causality & Probability Guardrails**:
   - Isolation Forest scores are explicitly documented and structured as outlier severity metrics, NOT attack probabilities.
   - Supporting features are documented as statistical deviations, not causal attack mechanisms.
