# Dark-Trace-AI — Agent 2: Intelligent Anomaly Detection & Threat Intelligence
## Block 1: Repository Intelligence, System Analysis & Architectural Blueprint

---

### Executive Summary

**Agent 2** in the **Dark-Trace-AI** multi-agent intrusion detection and adaptive defense system operates as an autonomous, dual-capability intelligence provider:
1. **Unsupervised ML Anomaly Detection**: Statistical anomaly identification across live network flows using Isolation Forest to detect zero-day intrusions, stealthy lateral movements, and novel attack vectors without relying on labeled training data.
2. **TinyFish External Threat Intelligence**: Automated enrichment and investigation of external indicators (public IP addresses, external domains, hashes, and associated CVEs/MITRE ATT&CK techniques) powered by TinyFish's Search, Fetch, and Agent capabilities.

This document establishes the verified repository baseline, architectural design, component boundaries, input/output schemas, and multi-block implementation roadmap for Agent 2.

---

### 1. Repository Intelligence & Baseline Audit

#### 1.1 Git Status & History
- **Current Branch**: `anomaly_agent` (tracking `origin/anomaly_agent`).
- **Working Tree**: Clean. No uncommitted, staged, or untracked teammate changes.
- **Commit History**:
  - `99bfb25`: Initial commit by Priyanshi Saini (added `.gitignore` and `README.md`).
  - `58c0d70`: Commit by Parth jiit (added empty `test.py`).
- **Remote Branches**: `origin/main`, `origin/anomaly_agent`.

#### 1.2 Existing Codebase Inspection
- **Agent Implementations**: 
  - Agent 1 (Supervised Threat Detection): **Not yet present in repository**.
  - Agent 2 (Intelligent Anomaly Detection): **Assigned to this track; not yet implemented**.
  - Agent 3 (Evidence Fusion & Threat Assessment): **Not yet present in repository**.
  - Agent 4 (Adaptive Policy Enforcement): **Not yet present in repository**.
- **Source Code**: Only `test.py` (0 bytes) and `README.md` (header only).
- **Environment**: Python `3.14.7` initialized in `.venv`. Standard pip `26.2.1` present; no third-party packages installed yet.
- **Dependency Files**: No `requirements.txt`, `pyproject.toml`, or `setup.py` exists currently.
- **Configuration & Secrets**: No `.env` file present. Standard `.gitignore` is comprehensive and already ignores `.env`, `.venv`, `__pycache__`, and build artifacts.

#### 1.3 Dataset Audit
- **Status**: **No datasets are currently present in the repository**.
- **Impact**: All dataset-dependent assumptions (exact column names, statistics, flow duration formats) are strictly provisional until a concrete dataset (e.g., CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, or custom PCAP flow logs) is introduced by the team.

---

### 2. Agent 1 Compatibility & Boundary Analysis

Because Agent 1 is not yet implemented in the codebase, Agent 2 must adhere to the following decoupling principles:

```
               [ Network Flow Stream / Packet Parser ]
                                  │
         ┌────────────────────────┴────────────────────────┐
         ▼                                                 ▼
┌──────────────────┐                             ┌──────────────────┐
│     Agent 1      │                             │     Agent 2      │
│ Supervised Model │                             │  Anomaly + Intel │
│ (Random Forest / │                             │ (Isolation Forest│
│  XGBoost / DNN)  │                             │   + TinyFish)    │
└────────┬─────────┘                             └────────┬─────────┘
         │ [Predicted Class + Confidence]                 │ [Anomaly Score + Findings]
         └────────────────────────┬───────────────────────┘
                                  ▼
                         ┌──────────────────┐
                         │     Agent 3      │
                         │  Evidence Fusion │
                         └──────────────────┘
```

1. **Shared Flow Ingestion**: Both agents must ingest identical network flow metadata: `flow_id`, `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, and extracted flow statistics.
2. **Independent Preprocessing Pipelines**: 
   - Supervised models require label encoding, class balance considerations, and sometimes specific categorical one-hot vectors.
   - Isolation Forest requires purely numerical, non-infinite, non-null features, and does not require distance-based scaling. Preprocessing must remain modular and private to Agent 2 to prevent cascading failures.
3. **No Inter-Agent Dependency**: Agent 2 must never depend on Agent 1's execution state or predictions.
4. **Independent Evidence Emission**: Agent 1 and Agent 2 will emit independent evidence payloads keyed by `flow_id` to Agent 3.

---

### 3. Agent 2 Machine Learning Architecture: Isolation Forest

#### 3.1 Algorithm Suitability Evaluation
**Isolation Forest (`sklearn.ensemble.IsolationForest`)** is selected as the primary unsupervised anomaly detection engine based on the following characteristics:

| Criterion | Evaluation for Network Flows |
| :--- | :--- |
| **Supervision Requirement** | **Unsupervised**: Trains on unlabelled baseline or normal traffic; does not require attack annotations. |
| **Computational Complexity** | **Linear / Sub-linear**: $O(t \cdot \psi \log \psi)$ training and $O(t \cdot \log \psi)$ inference per sample, making it suitable for near-real-time flow rates. |
| **High Dimensionality** | Operates effectively on subsets of statistical network flow features (IAT, packet counts, byte rates, TCP flags). |
| **Outlier Isolation Principle** | Anomalies have short average path lengths in isolation trees because their feature values fall outside dense normal clusters. |
| **Sensitivity to Monotonic Transforms** | Tree-based splits are invariant to monotonic scaling; standard z-score normalization is not strictly required, reducing numerical overhead. |

#### 3.2 Preprocessing & Feature Hygiene
1. **Target Leakage Prevention**: Ground-truth label columns (`label`, `attack_cat`, `is_attack`) must be strictly stripped before model ingestion.
2. **Infinite and Missing Value Handling**:
   - Network flow metrics often exhibit division-by-zero artifacts (e.g., `flow_bytes_per_sec` when duration is 0).
   - Rules: Impute NaNs with median/zero; clip `+inf` / `-inf` to feature-specific upper/lower bounds.
3. **Feature Ordering Enforcement**: Maintain an explicit, immutable feature list in the model metadata. Training and inference must enforce identical column ordering.
4. **Categorical Features**: High-cardinality IP addresses and ports must be treated as routing metadata, not raw categorical splits for tree isolation. Statistical flow behaviors (e.g., connection counts per source IP in a time window) are used for ML splits.

#### 3.3 Score Semantics & Calibration
- **Raw Decision Function**: `decision_function(X)` in scikit-learn outputs negative scores for anomalies and positive scores for normal instances (threshold at `0.0`).
- **Normalized Anomaly Score**: A normalized score $S \in [0.0, 1.0]$ is computed via min-max or logistic scaling representing **anomaly severity**:
  $$\text{severity} = \text{clip}\left(\frac{-s_{\text{raw}} - \text{threshold}_{\min}}{\text{threshold}_{\max} - \text{threshold}_{\min}}, 0.0, 1.0\right)$$
- **Strict Semantic Rule**: Anomaly score is an **unsupervised outlier severity metric**, NOT a calibrated posterior probability of attack. It must never be labeled as "confidence percentage" or "attack probability".

---

### 4. TinyFish External Threat Intelligence Architecture

#### 4.1 Integration Methodology & Verified Capabilities
Based on the official TinyFish ecosystem (`tinyfish` Python SDK for Python 3.11+):
- **Authentication**: `TINYFISH_API_KEY` loaded exclusively from the process environment (`os.getenv`).
- **Core APIs Utilized**:
  1. `client.search.query(query=...)`: Real-time structured web search to locate threat intelligence reports, CVE advisories, and malicious IP/domain reputation entries.
  2. `client.fetch.get_contents(urls=[...])`: Headless Chromium retrieval layer to extract clean markdown/JSON from threat advisories without cookie walls or noisy DOM boilerplate.
  3. `client.agent.run(url=..., goal=...)`: Targeted autonomous goal-driven web investigation on specific security portals when deep multi-step extraction is required.

#### 4.2 Investigation Trigger Policy (Smart Filter)
To maintain low latency and prevent quota exhaustion, TinyFish will **not** inspect every flow. It executes conditionally:

```
[ Flow Ingestion ] ──► [ Isolation Forest Scoring ]
                                │
                                ▼
                   Is Normalized Score >= 0.75?
                                │
                   ┌────────────┴────────────┐
                   ▼ NO                      ▼ YES
            [ Skip Intel ]           Is Indicator Public?
            Status: SKIPPED          (Exclude RFC 1918/4193)
                                             │
                                ┌────────────┴────────────┐
                                ▼ NO                      ▼ YES
                         [ Skip Intel ]             Is Indicator in
                         Status: PRIVATE_IP         Cache (TTL 1h)?
                                                          │
                                             ┌────────────┴────────────┐
                                             ▼ YES                     ▼ NO
                                      [ Cache Hit ]            [ TinyFish Query ]
                                      Return Cached            Search & Fetch Intel
```

1. **Private IP Exclusion**: Strictly filter RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), RFC 4193 (IPv6 ULA), and loopback (`127.0.0.0/8`). Internal IP addresses are never transmitted to external web services.
2. **Severity Thresholding**: Trigger investigations only when the flow anomaly score exceeds a configurable threshold (e.g., $S \ge 0.75$) or upon explicit analyst request.
3. **Caching Layer**: In-memory LRU cache with a 1-hour Time-To-Live (TTL) prevents redundant external calls for the same public IP or domain.

#### 4.3 Separation of Responsibilities & Safety Guardrails
- **Complementary, Not Overriding**: TinyFish findings enrich the evidence package. They do not alter or overwrite the Isolation Forest numerical anomaly score.
- **No Policy Enforcement**: TinyFish findings are passed as structured evidence to Agent 3. Agent 2 does not execute firewall drops, iptables updates, or routing changes.
- **Fail-Open ML Operation**: If TinyFish is unreachable, times out, or encounters rate limits, Agent 2 marks `investigation_status: "UNAVAILABLE"` or `"FAILED"` and successfully returns the ML anomaly detection results.
- **Safe Content Consumption**: Retrieved external text is treated as passive data. Content is never passed into shell executors, dynamic evaluators, or SQL queries.
- **Attribution**: Every finding must retain its source URL, publisher title, and retrieval timestamp.

---

### 5. Unified Input/Output Interface Contracts

#### 5.1 Ingestion Schema (`NetworkFlow`)
```json
{
  "flow_id": "flow_20261030_001928_884",
  "timestamp": "2026-10-30T16:35:00.124Z",
  "src_ip": "10.0.4.15",
  "src_port": 49210,
  "dst_ip": "198.51.100.42",
  "dst_port": 445,
  "protocol": "TCP",
  "features": {
    "flow_duration_ms": 1240.5,
    "total_fwd_packets": 28,
    "total_bwd_packets": 14,
    "fwd_packet_length_mean": 452.1,
    "bwd_packet_length_mean": 128.0,
    "flow_bytes_per_sec": 12840.2,
    "flow_packets_per_sec": 33.8,
    "flow_iat_mean_ms": 30.2,
    "syn_flag_count": 1,
    "rst_flag_count": 0,
    "ack_flag_count": 41
  },
  "force_threat_intel": false
}
```

#### 5.2 Agent 2 Output Schema (`Agent2Evidence`)
```json
{
  "agent_id": "A2",
  "flow_id": "flow_20261030_001928_884",
  "timestamp": "2026-10-30T16:35:00.124Z",
  "anomaly_detection": {
    "is_anomaly": true,
    "anomaly_label": "ANOMALOUS",
    "raw_anomaly_score": -0.1842,
    "normalized_anomaly_score": 0.88,
    "threshold": 0.0,
    "supporting_features": [
      {
        "feature_name": "flow_bytes_per_sec",
        "observed_value": 12840.2,
        "baseline_median": 450.0,
        "deviation_direction": "HIGH"
      },
      {
        "feature_name": "total_fwd_packets",
        "observed_value": 28.0,
        "baseline_median": 4.0,
        "deviation_direction": "HIGH"
      }
    ],
    "model_version": "iforest_v1.0.0",
    "inference_latency_ms": 1.2
  },
  "threat_intelligence": {
    "provider": "tinyfish",
    "investigation_status": "COMPLETED",
    "indicator": "198.51.100.42",
    "indicator_type": "PUBLIC_IP",
    "findings": [
      "Reported in recent campaigns conducting SMB scanning (port 445)",
      "Flagged in public blocklists for automated reconnaissance activity"
    ],
    "threat_context": [
      {
        "cve_id": "CVE-2017-0144",
        "title": "EternalBlue SMB Remote Code Execution",
        "severity": "CRITICAL"
      }
    ],
    "attack_techniques": [
      {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery"
      }
    ],
    "sources": [
      {
        "title": "Threat Advisory: Active SMB Scanning Targets",
        "url": "https://threat-intel-example.org/advisories/2026-smb"
      }
    ],
    "investigated_at": "2026-10-30T16:35:01.050Z",
    "error": null
  },
  "metadata": {
    "src_ip": "10.0.4.15",
    "dst_ip": "198.51.100.42",
    "dst_port": 445,
    "protocol": "TCP"
  }
}
```

---

### 6. Integration Contract with Agent 3 (Evidence Fusion)

Agent 3 consumes outputs from Agent 1 and Agent 2 to compute composite risk scores and formulate actionable defense recommendations.

| Scenario | Agent 1 (Supervised) | Agent 2 (Anomaly Detection) | Agent 2 (TinyFish Intel) | Agent 3 Synthesis |
| :--- | :--- | :--- | :--- | :--- |
| **Known Exploit** | Attack: `EternalBlue` (0.95 conf) | `ANOMALOUS` (Score 0.91) | Hostile SMB scanner IP | **Critical Threat**: Immediate firewall block |
| **Zero-Day / Novel** | Class: `BENIGN` (0.48 conf) | `ANOMALOUS` (Score 0.94) | Unfamiliar external IP | **High Suspicion**: Flag for sandbox inspection / Review |
| **Benign Spike** | Class: `BENIGN` (0.96 conf) | `ANOMALOUS` (Score 0.62) | Trusted CDN IP | **Benign Novelty**: Suppress alert; log baseline shift |
| **False Alarm** | Class: `PortScan` (0.51 conf) | `NORMAL` (Score 0.12) | Internal / benign IP | **Downgrade Alert**: Low confidence benign behavior |

---

### 7. Target File Structure for Agent 2

The planned modular codebase will follow standard Python packaging conventions:

```
Dark-Trace-AI/
├── docs/
│   └── agent2/
│       └── architecture.md               # [Block 1] System Architecture Blueprint
├── src/
│   └── dark_trace/
│       ├── __init__.py
│       ├── common/
│       │   ├── __init__.py
│       │   ├── schemas.py                # [Block 2] Shared Pydantic schemas (Flow, Evidence)
│       │   └── ip_utils.py               # [Block 2] RFC 1918 / IP parsing utilities
│       └── agent2/
│           ├── __init__.py
│           ├── config.py                 # [Block 2] Model & TinyFish configuration
│           ├── preprocessor.py           # [Block 2] Missing/inf imputation, column ordering
│           ├── model.py                  # [Block 3] Isolation Forest wrapper & serialization
│           ├── trainer.py                # [Block 3] Offline training & validation pipeline
│           ├── detector.py               # [Block 4] Online inference & score calibration
│           ├── explainability.py         # [Block 4] Feature deviation & evidence extraction
│           ├── threat_intel/
│           │   ├── __init__.py
│           │   ├── client.py             # [Block 5] TinyFish client wrapper (timeout, backoff)
│           │   ├── triggers.py           # [Block 5] Public IP & anomaly trigger rules
│           │   └── investigator.py       # [Block 5] Intelligence parsing & source attribution
│           └── agent.py                  # [Block 6] Unified Agent 2 coordinator
├── models/
│   └── agent2/
│       └── .gitkeep                      # [Block 3] Serialized model artifacts (.joblib, metadata)
└── tests/
    └── agent2/
        ├── __init__.py
        ├── test_schemas.py               # [Block 2]
        ├── test_preprocessor.py          # [Block 2]
        ├── test_model.py                 # [Block 3]
        ├── test_detector.py              # [Block 4]
        ├── test_threat_intel_triggers.py # [Block 5]
        └── test_agent_integration.py     # [Block 6]
```

---

### 8. Dependency & Environment Analysis

#### 8.1 Requirements to be staged in later blocks:
- **Data & Machine Learning**:
  - `numpy>=1.26.0`
  - `pandas>=2.1.0`
  - `scikit-learn>=1.4.0`
  - `joblib>=1.3.0`
- **Validation & Serialization**:
  - `pydantic>=2.6.0`
- **External Threat Intelligence**:
  - `tinyfish>=0.1.0`
  - `httpx>=0.27.0` (direct REST fallback)
- **Testing & Quality Assurance**:
  - `pytest>=8.0.0`

#### 8.2 Technical Consideration on Python 3.14:
The current environment is running Python `3.14.7`. Because Python 3.14 is a future pre-release development branch, compiled C-extensions for packages such as `scikit-learn` or `numpy` may require source compilation if pre-built binary wheels are unavailable. If wheel compilation delays occur during Block 2/3 dependency installation, recommending Python 3.11 or 3.12 virtual environment provisioning will be proposed as a fallback.

---

### 9. Implementation Roadmap (Blocks 2–7)

- **Block 2: Data Schemas, Feature Preprocessing & Validation Pipeline**
  - Implement Pydantic data contracts for network flows and Agent 2 evidence.
  - Implement `AnomalyPreprocessor`: column selection, type casting, missing value imputation, infinite value clipping, deterministic feature ordering.
  - Implement `ip_utils` for RFC 1918/4193 private IP validation.
  - Unit tests for validation and preprocessing.

- **Block 3: Isolation Forest Model Implementation & Training Pipeline**
  - Implement `IsolationForest` model wrapper with hyperparameters (`n_estimators`, `contamination`, `random_state`).
  - Implement offline training script and model artifact exporter (`.joblib` + `metadata.json`).
  - Unit tests for model training, saving, loading, and deterministic predictions.

- **Block 4: Online Inference Engine, Score Calibration & Explainability**
  - Implement real-time inference pipeline (`AnomalyDetector`).
  - Implement score calibration (raw decision function to normalized anomaly score).
  - Implement feature attribution / explainability (identifying top anomalous features per flow).
  - Unit tests for inference latency, score correctness, and feature attribution.

- **Block 5: TinyFish Threat Intelligence Client & Smart Trigger Engine**
  - Implement TinyFish client wrapper with timeout, exponential backoff, rate limiting, and graceful offline fallback.
  - Implement trigger policy (severity thresholds, caching layer).
  - Implement indicator search & structured extraction with source attribution.
  - Unit and mock tests for threat intel enrichment.

- **Block 6: Unified Agent 2 Coordinator & End-to-End Testing**
  - Implement `Agent2Coordinator` tying together ML detector and Threat Intelligence investigator.
  - End-to-end integration tests with diverse synthetic network flows.
  - Offline mode resilience verification.

- **Block 7: Documentation, Performance Benchmarks & Agent 3 Hand-off**
  - Benchmark inference latency and memory footprint.
  - Final integration guide and API documentation for Agent 3.
  - Final review and verification.

---

### 10. Open Decisions & Questions for Team Alignment

1. **Benchmark Dataset Selection**: Has the team agreed upon a specific intrusion detection dataset (e.g. CIC-IDS2017, CSE-CIC-IDS2018, or UNSW-NB15) to calibrate baseline normal traffic, or will synthetic normal traffic profiles be generated for the hackathon simulation?
2. **Agent 1 Input Schema Alignment**: As soon as Agent 1 begins development, we should confirm the exact feature naming convention to ensure shared flow parser compatibility.
3. **TinyFish API Key Provisioning**: Confirm whether the `TINYFISH_API_KEY` credential will be provisioned in the local environment or secret manager for automated test execution.

