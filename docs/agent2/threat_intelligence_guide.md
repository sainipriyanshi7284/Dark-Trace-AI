# Dark-Trace-AI — Agent 2: Phase 3 (A2-B5) Documentation
## TinyFish Threat Intelligence Integration Guide (Strict Free-Tier)

---

### Overview

This guide details the external threat intelligence integration in **Agent 2 Phase 3 (A2-B5)** powered by TinyFish:
1. **Free-Tier API Client (`TinyFishClient`)**: Interfaces exclusively with TinyFish's Search and Fetch APIs.
2. **Trigger Policy & Cache (`ThreatIntelTriggerPolicy`)**: Evaluates flow severity, enforces private IP exclusion, and maintains an in-memory LRU cache.
3. **Investigator Service (`ThreatIntelInvestigator`)**: Coordinates indicator searches, formats source-attributed findings, and ensures graceful degradation when external services are unavailable.

---

### 1. Mandatory Free-Tier Governance

To maintain strict cost control and zero-spend hackathon compliance:

| Capability | Tier Status | Free Limits | Implementation Details |
| :--- | :--- | :--- | :--- |
| **Search API** | **Permitted (Free)** | 30 req/min, 500 req/hr | Queries public indicators for CVEs, scanner activity, and abuse reports. |
| **Fetch API** | **Permitted (Free)** | 150 URLs/min, 1,000 URLs/day | Fetches clean markdown from threat advisories and blocklists. |
| **Agent API** | **FORBIDDEN (Paid)** | N/A | Strictly excluded; never invoked in Dark-Trace-AI. |
| **Browser API** | **FORBIDDEN (Paid)** | N/A | Strictly excluded; never invoked in Dark-Trace-AI. |

#### Zero-Spend Guardrails:
- No wallet auto-reload or payment method configuration.
- Client maintains a local sliding-window rate limiter ensuring requests do not exceed 30 req/min.
- If rate limits are reached, `investigation_status` reports `"RATE_LIMITED"` without blocking the ML pipeline.

---

### 2. Cybersecurity Indicator Safety: Private IP Exclusion

Location: [`src/dark_trace/agent2/threat_intel/triggers.py`](file:///Users/parth/Documents/agenticai/Dark-Trace-AI/src/dark_trace/agent2/threat_intel/triggers.py)

#### Indicator Filtering Rules:
- **Private Networks Excluded**: Internal RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), RFC 4193 (IPv6 ULA), loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`), and multicast are strictly excluded from external investigation.
- If an internal IP displays anomalous behavior, it is processed by the ML Anomaly Detector and flagged for internal review, but **never queried to external web services**.
- The `ThreatIntelligenceResult` reports `investigation_status: "SKIPPED_PRIVATE_IP"`.

---

### 3. Investigation Workflow & Caching

```
[ Ingested Network Flow ]
           │
           ▼
[ Isolation Forest Scoring ]
           │
           ▼
Is Normalized Score >= 0.75 OR force_threat_intel == True?
           │
      ┌────┴────┐
      ▼ NO      ▼ YES
[ Skip Intel ] Is Destination/Source IP a Globally Routable Public Indicator?
Status:          │
SKIPPED_BELOW    ├───► NO (RFC 1918 / Loopback) ──► Status: SKIPPED_PRIVATE_IP
THRESHOLD        │
                 ▼ YES
           Is Indicator in LRU Cache (TTL 1 Hour)?
                 │
            ┌────┴────┐
            ▼ YES     ▼ NO
      [ Cache Hit ]  [ TinyFish Search API ]
      Return Cached  Query: "<IP> malicious scanner attack CVE"
      Result         Extract source titles, URLs, and findings
```

---

### 4. Non-Overriding Evidence & Graceful Degradation

#### Independence from ML Anomaly Detection:
1. **Supplementary Evidence Only**: TinyFish findings enrich the evidence package for Agent 3. They do **not** alter or overwrite the Isolation Forest numerical anomaly score.
2. **No Policy Enforcement**: TinyFish findings are passed as passive text context to Agent 3. Agent 2 does not execute firewall drops or network blocks.
3. **Graceful Degradation**:
   - If `TINYFISH_API_KEY` is not set: `investigation_status = "UNAVAILABLE"`.
   - If network fails or times out: `investigation_status = "FAILED"`.
   - If rate limit is hit: `investigation_status = "RATE_LIMITED"`.
   - **In all failure modes, Isolation Forest inference, raw scores, normalized scores, and explainability remain 100% functional.**

---

### 5. Environment Setup

Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Edit `.env`:
```bash
TINYFISH_API_KEY=your_free_tier_api_key_here
```
The `.gitignore` strictly excludes `.env` to prevent credential leakage.
