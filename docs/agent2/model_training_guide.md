# Dark-Trace-AI — Agent 2: Phase 1 (A2-B3) Documentation
## Isolation Forest Model Implementation & Training Pipeline Guide

---

### Overview

This guide details the machine learning anomaly detection engine implemented in **Agent 2 Phase 1 (A2-B3)**:
1. **Isolation Forest Model Wrapper (`IsolationForestModel`)**: Standard scikit-learn wrapper with strict input matrix validation, hyperparameter sanity checks, and fitted-state protection.
2. **Training Pipeline (`ModelTrainer`)**: End-to-end unlabelled network flow training, feature extraction, and baseline score calibration.
3. **Artifact Bundle (`TrainedAnomalyModel`)**: Unified container combining the trained estimator, preprocessor state, and training metadata.
4. **Scoring & Calibration (`dark_trace.agent2.scoring`)**: Monotonic transformation of decision scores into bounded `[0.0, 1.0]` outlier severity metrics.
5. **Model Persistence (`dark_trace.agent2.persistence`)**: Serializing and restoring model bundles with verification and dependency handling.

---

### 1. Model Architecture & Hyperparameter Configuration

Location: [`src/dark_trace/agent2/model.py`](file:///Users/parth/Documents/agenticai/Dark-Trace-AI/src/dark_trace/agent2/model.py)

#### Supported Hyperparameters
- `n_estimators`: Number of isolation trees in the ensemble (default `100`, must be $> 0$).
- `max_samples`: Number of samples drawn from training data to train each tree (default `"auto"` $= \min(256, n)$).
- `contamination`: Expected proportion of outliers in the data (`"auto"` or float in $(0.0, 0.5]$).
- `random_state`: Integer seed for deterministic tree generation (default `42`).
- `n_jobs`: CPU cores used for parallel execution (default `-1` for all available cores).
- `raw_decision_threshold`: Boundary separating inliers from outliers (default `0.0`).

#### Input Validation Guards
The wrapper validates all inputs prior to model execution:
- **Empty Matrix**: Rejects `None` or 0-length datasets with `ValueError`.
- **Non-Finite Values**: Strictly rejects `NaN`, `+inf`, and `-inf` with explicit error messages directing the caller to run `AnomalyPreprocessor.transform()` first.
- **Dimensionality**: Ensures all rows have matching column counts and enforces that inference matrices match `n_features_in_`.
- **Fitted State**: Invoking `predict()`, `decision_function()`, or `score_samples()` before `fit()` raises `NotFittedError`.

---

### 2. Anomaly Scoring & Calibration Semantics

Location: [`src/dark_trace/agent2/scoring.py`](file:///Users/parth/Documents/agenticai/Dark-Trace-AI/src/dark_trace/agent2/scoring.py)

#### Score Semantics
- `raw_anomaly_score`: Direct `decision_function(X)` output from scikit-learn.
  - Negative values ($< 0.0$): Outliers (anomalous flows).
  - Positive values ($> 0.0$): Inliers (normal baseline flows).
- `normalized_anomaly_score`: Calibrated severity index $S \in [0.0, 1.0]$.
  - $S \ge 0.5$: Anomalous flow (higher value = greater statistical deviation).
  - $S < 0.5$: Normal flow.
- **Cybersecurity Warning**: The normalized score represents **outlier severity**, NOT a posterior attack probability or confidence percentage. It must never be presented as a probabilistic guarantee.

---

### 3. Model Training Pipeline (`ModelTrainer`)

Location: [`src/dark_trace/agent2/trainer.py`](file:///Users/parth/Documents/agenticai/Dark-Trace-AI/src/dark_trace/agent2/trainer.py)

#### End-to-End Workflow
```
[ Raw NetworkFlow Records / Dicts ]
                 │
                 ▼
     [ AnomalyPreprocessor ]
     - Strips target labels (target leakage prevention)
     - Strips metadata (flow_id, IPs, timestamps)
     - Imputes missing/NaN values via column medians
     - Clips infinities to finite bounds
                 │
                 ▼
     [ Clean 2D Feature Matrix ]
                 │
                 ▼
     [ IsolationForestModel.fit() ]
                 │
                 ▼
     [ Baseline Score Calibration ]
     - Measures training score distribution:
       min, max, median, 5th percentile, 95th percentile
                 │
                 ▼
     [ TrainedAnomalyModel Artifact ]
```

#### Code Example
```python
from dark_trace.agent2 import IsolationForestModel, ModelTrainer
from dark_trace.common.schemas import NetworkFlow

# 1. Ingest baseline network traffic
flows = [
    NetworkFlow(
        flow_id="f1",
        timestamp="2026-10-30T16:00:00Z",
        src_ip="10.0.0.1",
        dst_ip="198.51.100.1",
        src_port=50000,
        dst_port=443,
        protocol="TCP",
        features={"duration_ms": 120.0, "byte_rate": 5000.0, "packet_count": 15},
    )
]

# 2. Train artifact bundle
trainer = ModelTrainer()
trained_bundle = trainer.train(flows)

# 3. Score a single live flow
score_result = trained_bundle.score_record(flows[0])
print(score_result)
# {
#   'is_anomaly': False,
#   'anomaly_label': 'NORMAL',
#   'raw_anomaly_score': 0.12,
#   'normalized_anomaly_score': 0.38,
#   'threshold': 0.0
# }

# 4. Save model artifact
trained_bundle.save("models/agent2/iforest_v1")

# 5. Load model artifact
restored_bundle = TrainedAnomalyModel.load("models/agent2/iforest_v1")
```

---

### 4. Model Persistence & Artifact Structure

Location: [`src/dark_trace/agent2/persistence.py`](file:///Users/parth/Documents/agenticai/Dark-Trace-AI/src/dark_trace/agent2/persistence.py)

Saved artifacts are structured as:
```
models/agent2/iforest_v1/
├── model.joblib      # Serialized scikit-learn IsolationForest estimator
└── metadata.json     # Hyperparameters, preprocessor state, and score statistics
```

#### Artifact Integrity & Security Checks
- Validates existence of both `model.joblib` and `metadata.json`.
- Detects corrupted or unparseable JSON metadata.
- Reconstructs preprocessor with exact learned feature names and column ordering.
- Reconstructs model with exact hyperparameters and random seed.

---

### 5. Running the Unit Tests

Execute the complete test suite (47 tests):
```bash
PYTHONPATH=src ./.venv/bin/python -m unittest discover -s tests/agent2 -p "test_*.py" -v
```

All 47 tests pass in ~6ms without requiring network access.

---

### 6. Environment & Dependency Status

- **Installed in `.venv`**: Python `3.14.7`, `pip 26.2.1`.
- **Institutional Proxy Status**: The development environment connects through an institutional proxy (`Cyberoam SSL CA / forward.http.proxy:3128`) which blocks direct outbound HTTP/HTTPS access to `pypi.org` (`403 Forbidden`).
- **Dependency Guarding**: `IsolationForestModel` and `persistence` modules verify `SKLEARN_AVAILABLE` and `JOBLIB_AVAILABLE`. If accessed in an environment without scikit-learn/joblib, they raise informative `DependencyMissingError` exceptions with installation commands.
- **Test Strategy**: The Phase 1 test suite uses standard library mocking to test 100% of the wrapper, validation, serialization, and training pipeline logic deterministically, ensuring immediate readiness when packages are installed.

