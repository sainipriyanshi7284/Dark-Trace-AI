# Dark Trace AI — Tauri + Python backend

## Prerequisites (Windows 10/11)
1. Install Node.js LTS.
2. Install Rust using https://rustup.rs (choose the MSVC toolchain).
3. Install Microsoft C++ Build Tools with **Desktop development with C++**.
4. Install Microsoft Edge WebView2 Runtime (usually already present on Windows 10/11).

## Install dependencies
Open PowerShell in `Cybersecurity SOC Dashboard`:
```powershell
npm install
```

## Run the Python API
In a second terminal:
```powershell
cd "Cybersecurity SOC Dashboard"
py -m venv backend/.venv
backend/.venv/Scripts/Activate.ps1
python -m pip install -r backend/requirements.txt
python backend/app.py
```
Or double-click `start-backend.bat` in the project root.

## Run the desktop app in development
In another terminal, from `Cybersecurity SOC Dashboard`:
```powershell
npm run tauri:dev
```

## Build the Windows installer
```powershell
npm run tauri:build
```
Installer output is under:
`src-tauri/target/release/bundle/`

Tauri is configured to generate NSIS (`.exe`) and MSI installers.

## Important current limitation
The UI's existing dashboard values and charts are hard-coded demonstration data. The Flask service currently provides health/status endpoints only. The backend connection indicator proves that the local API is reachable; it does not mean threat detection is running. Next implementation step is to connect the real flow ingestion, trained model inference, alert storage, and enforcement components to API endpoints and replace the demo dashboard data.

## Troubleshooting
- If PowerShell blocks venv activation, run `Set-ExecutionPolicy -Scope Process Bypass`.
- If Rust build reports missing linker/build tools, install Visual Studio Build Tools (C++ workload), then reopen the terminal.
- If WebView2 is missing, install the Evergreen WebView2 Runtime.
