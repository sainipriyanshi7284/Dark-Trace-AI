from datetime import datetime, timezone
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": [
    "http://localhost:1420",
    "http://127.0.0.1:1420",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:8443",
    "http://localhost:8443",
    "tauri://localhost",
    "http://tauri.localhost",
]}})

@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "CyberSentinel Multi-Agent Detection & Defense System API",
        "track": "Track 1 | CyberSentinel — Day 2",
        "level": "Level 2: Complete Multi-Agent Detection & Defense System",
        "agents_count": 5,
        "agents": [
            {"id": "a1", "name": "Threat Classification Agent", "phase": "DETECT"},
            {"id": "a2", "name": "Traffic & Anomaly Agent", "phase": "DETECT"},
            {"id": "a3", "name": "Evidence Fusion Agent", "phase": "CORRELATE"},
            {"id": "a4", "name": "Temporal Correlation Agent", "phase": "CORRELATE"},
            {"id": "a5", "name": "Adaptive Defense Agent", "phase": "RESPOND"},
        ],
        "mode": "chronological-replay-scaffold",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

@app.get("/api/status")
def status():
    return jsonify({
        "api": "online",
        "detection_engine": "5_agent_pipeline_ready",
        "phases": {
            "detect": "A1 (DoS signature classifier) + A2 (High traffic anomaly detector)",
            "correlate": "A3 (Evidence fusion) + A4 (Temporal correlation over sliding windows)",
            "respond": "A5 (Adaptive defense SOURCE_IP policies)"
        },
        "evaluation_rule": "Apply active defense policies BEFORE analyzing newly allowed flows."
    })

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8765, debug=False)
