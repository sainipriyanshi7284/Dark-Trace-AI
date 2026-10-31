# Dark Trace AI local backend

This is an integration scaffold, not the actual NIDS detection engine yet.

## Windows setup
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Health check: http://127.0.0.1:8765/api/health

The React desktop UI polls this endpoint and displays whether the local API is connected.
The dashboard's current charts, incidents, and metrics are still demo/mock data until the
real flow ingestion and trained inference pipeline is connected.
