from datetime import datetime, timezone
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": [
    "http://localhost:1420",
    "http://127.0.0.1:1420",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "tauri://localhost",
    "http://tauri.localhost",
]}})

@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "Dark Trace AI local API",
        "mode": "development-scaffold",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

@app.get("/api/status")
def status():
    # This endpoint confirms the local API is reachable.
    # It does NOT indicate that a trained detection model is loaded.
    return jsonify({
        "api": "online",
        "detection_engine": "not_configured",
        "message": "Connect your trained model and packet/flow ingestion pipeline here."
    })

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8765, debug=False)
