# Dark-Trace-AI

CyberSentinel: Multi-Agent Network Intrusion Detection System.

---

## Agent 3: Contextual Fusion & Decision Coordinator

### Responsibility
**Agent 3** acts as the synthesis and triage layer within CyberSentinel. Its core responsibilities are:
- Ingesting flow context and detection findings from **Agent 1** (Signature / Line-Rate Triage) and **Agent 2** (Anomaly / Behavioral Analysis).
- Correlating heterogeneous indicators across network flow identifiers and temporal windows.
- Resolving conflicting agent verdicts (e.g., signature detected vs. behavioral anomaly absent).
- Providing graceful degradation when upstream agents are delayed, unavailable, or in an error state.
- Emitting a standardized, structured JSON output consumed by the downstream **Policy Engine**.

### Interface Contract (Provisional)
- **Required Input:** `flow_context` (`flow_id`, `timestamp`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`).
- **Optional Inputs:** `a1_result` (`A1DetectionResult`), `a2_result` (`A2DetectionResult`), `network_metadata` (`dict`).
- **Standard Output:** `Agent3Output` (`incident_id`, `flow_id`, `verdict`, `fused_risk_score`, `confidence`, `contributing_agents`, `fusion_status`, `recommended_policy_action`).

### Repository Structure
```
agents/
└── agent3/
    └── __init__.py           # Package export for Agent 3 skeleton and schemas
schemas/
├── __init__.py               # Package export for data contracts
└── agent3_output.schema.json # JSON Schema definition for Agent 3 output
src/cybersentinel/
├── __init__.py
└── agent3/
    ├── __init__.py
    ├── contract.py           # Provisional interface data classes and validation
    ├── exceptions.py         # Custom exceptions
    └── skeleton.py           # Minimal Agent 3 module skeleton
docs/
└── agent3_architecture_report.md
tests/
├── __init__.py
├── test_agent3_skeleton.py
└── test_agents_and_schemas.py
```

### Running Tests & Verification
```powershell
$env:PYTHONPATH="src;."
python -m pytest -v
```
