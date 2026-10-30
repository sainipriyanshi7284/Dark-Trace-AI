# Dark-Trace-AI — Agent 2: Block 2 Documentation
## Data Schemas, Feature Preprocessing & Validation Pipeline Guide

---

### Overview

This guide provides technical documentation for the data structures, network utilities, and feature preprocessing pipeline implemented in **Agent 2 Block 2**:
1. **Network Flow Schema (`NetworkFlow`)**: Standardized data ingestion contract for network traffic flows.
2. **Agent 2 Evidence Schema (`Agent2Evidence`)**: Structured evidence output schema for downstream consumption by Agent 3.
3. **IP Address Utilities (`dark_trace.common.ip_utils`)**: RFC 1918 / RFC 4193 private network identification and external threat intelligence indicator safety filtering.
4. **Anomaly Preprocessor (`AnomalyPreprocessor`)**: Leakage-free, stateful feature extraction, median imputation, and infinite value clipping pipeline.

---

### 1. Schema Specifications

#### 1.1 Ingestion Contract: `NetworkFlow`
Location: [`src/dark_trace/common/schemas.py`](file:///Users/parth/Documents/agenticai/Dark-Trace-AI/src/dark_trace/common/schemas.py)

| Field | Type | Required | Description | Validation Rule |
| :--- | :--- | :--- | :--- | :--- |
| `flow_id` | `str` | Yes | Unique network flow identifier | Non-empty string |
| `timestamp` | `str` | Yes | Flow capture timestamp | ISO-8601 string or epoch string (defaults to UTC now) |
| `src_ip` | `str` | Yes | Source IP address | Valid IPv4 or IPv6 string |
| `dst_ip` | `str` | Yes | Destination IP address | Valid IPv4 or IPv6 string |
| `src_port` | `int` | Yes | Source port | Integer in range `[0, 65535]` |
| `dst_port` | `int` | Yes | Destination port | Integer in range `[0, 65535]` |
| `protocol` | `str` \| `int` | Yes | Protocol identifier | String ('TCP', 'UDP', 'ICMP') or integer `[0, 255]` |
| `features` | `dict[str, float]` | No | Numerical flow characteristics | Non-empty keys, numeric values or `None` (imputed) |
| `force_threat_intel`| `bool` | No | Threat intel trigger flag | Boolean (`False` by default) |
| `metadata` | `dict[str, Any]` | No | Auxiliary sensor metadata | Dictionary |

#### 1.2 Output Contract: `Agent2Evidence`
Location: [`src/dark_trace/common/schemas.py`](file:///Users/parth/Documents/agenticai/Dark-Trace-AI/src/dark_trace/common/schemas.py)

- `agent_id`: Constant `"A2"`.
- `flow_id`: Originating flow identifier matching ingestion.
- `timestamp`: Evidence generation timestamp.
- `anomaly_detection`:
  - `is_anomaly`: Boolean (`True` if anomaly, `False` if normal).
  - `anomaly_label`: `"ANOMALOUS"` or `"NORMAL"`.
  - `raw_anomaly_score`: Raw decision score from Isolation Forest (negative for anomalies).
  - `normalized_anomaly_score`: Bounded outlier severity index in `[0.0, 1.0]`.
  - `threshold`: Decision boundary threshold (typically `0.0`).
  - `supporting_features`: List of top deviating features with observed values, baselines, and deviation directions.
  - `model_version`: Serialized model version string.
  - `inference_latency_ms`: Measured inference duration in milliseconds.
- `threat_intelligence`:
  - `provider`: `"tinyfish"`.
  - `investigation_status`: `"NOT_REQUESTED"` \| `"SKIPPED_PRIVATE_IP"` \| `"SKIPPED_BELOW_THRESHOLD"` \| `"COMPLETED"` \| `"FAILED"` \| `"UNAVAILABLE"`.
  - `indicator`: Public IP address or domain investigated.
  - `indicator_type`: `"NONE"` \| `"PUBLIC_IP"` \| `"DOMAIN"` \| `"HASH"`.
  - `findings`: List of external threat intelligence findings.
  - `sources`: Source URLs and titles preserving attribution.
- `metadata`: Echo of routing metadata (`src_ip`, `dst_ip`, `dst_port`, `protocol`).

---

### 2. IP Address Utilities

Location: [`src/dark_trace/common/ip_utils.py`](file:///Users/parth/Documents/agenticai/Dark-Trace-AI/src/dark_trace/common/ip_utils.py)

#### 2.1 Categorization Rules
- **RFC 1918 Private IPv4**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.
- **RFC 4193 Unique Local IPv6**: `fc00::/7` (includes `fd00::/8`).
- **Loopback**: `127.0.0.0/8`, `::1`.
- **Link-Local**: `169.254.0.0/16`, `fe80::/10`.
- **Multicast**: `224.0.0.0/4`, `ff00::/8`.
- **Carrier-Grade NAT (RFC 6598)**: `100.64.0.0/10`.
- **Public IPs**: Genuine globally routable unicast addresses (verified via `obj.is_global`).

#### 2.2 Cybersecurity Indicator Safety
- Function `is_routable_public_indicator(address) -> bool`:
  Ensures internal private IP addresses, loopback, and documentation subnets are never queried to external threat intelligence engines like TinyFish. Internal network traffic remains valid for ML anomaly detection.

---

### 3. Anomaly Preprocessor (`AnomalyPreprocessor`)

Location: [`src/dark_trace/agent2/preprocessor.py`](file:///Users/parth/Documents/agenticai/Dark-Trace-AI/src/dark_trace/agent2/preprocessor.py)

#### 3.1 Preprocessing Workflow
1. **Target Leakage Protection**: Automatically excludes attack labels (`label`, `attack_cat`, `is_attack`, `target`, `class`) and metadata (`flow_id`, `src_ip`, `dst_ip`, `timestamp`) from the numerical feature space.
2. **Missing Value Imputation**: Missing keys, `None`, or `NaN` values are imputed with the median of finite values learned during `fit()`.
3. **Infinite Value Clipping**: `+inf` and `-inf` (common in flow rates with 0 duration) are clipped to finite boundaries learned from the training set.
4. **Deterministic Feature Ordering**: Enforces consistent column ordering (`self.feature_names_`) across training and real-time inference.
5. **Robust Inference Handling**: Unexpected extra columns are safely ignored; missing columns are automatically imputed with learned medians.

#### 3.2 Usage Example
```python
from dark_trace.agent2.preprocessor import AnomalyPreprocessor
from dark_trace.common.schemas import NetworkFlow

# 1. Initialize preprocessor
preprocessor = AnomalyPreprocessor()

# 2. Fit on baseline network flow records
train_flows = [
    NetworkFlow(
        flow_id="f1",
        timestamp="2026-10-30T16:00:00Z",
        src_ip="10.0.0.1",
        dst_ip="198.51.100.1",
        src_port=50000,
        dst_port=80,
        protocol="TCP",
        features={"duration_ms": 120.0, "byte_rate": 5000.0, "packet_count": 15},
    )
]
preprocessor.fit(train_flows)

# 3. Transform inference flows into 2D numerical matrix
X = preprocessor.transform(train_flows)

# 4. Serialize preprocessor state for deployment
preprocessor.save("models/agent2/preprocessor_state.json")

# 5. Restore in production inference worker
restored = AnomalyPreprocessor.load("models/agent2/preprocessor_state.json")
```

---

### 4. Running Unit Tests

To run the unit test suite:
```bash
PYTHONPATH=src ./.venv/bin/python -m unittest discover -s tests/agent2 -p "test_*.py" -v
```

All 25 test cases execute in ~3ms without external network calls.

---

### 5. Known Limitations & Unresolved Dependencies

1. **Proxy SSL Interception**: The local test environment connects via an institutional proxy (`Cyberoam SSL CA / forward.http.proxy:3128`) which blocks direct outbound HTTP/HTTPS access to `pypi.org` (`403 Forbidden`). 
   - *Design Impact*: The Block 2 schemas and preprocessor were engineered with **zero external dependencies** using standard Python 3 (`dataclasses`, `ipaddress`, `math`, `statistics`, `unittest`), ensuring 100% operational reliability offline.
   - *Requirements Documented*: A standard [`requirements.txt`](file:///Users/parth/Documents/agenticai/Dark-Trace-AI/requirements.txt) has been staged for when proxy authentication or external wheel mirrors are configured.
2. **Dataset Availability**: No real benchmark dataset (e.g. CIC-IDS2017) is currently checked into the repository. The preprocessor dynamically learns schema features or accepts explicit column lists once the team provides the dataset.

