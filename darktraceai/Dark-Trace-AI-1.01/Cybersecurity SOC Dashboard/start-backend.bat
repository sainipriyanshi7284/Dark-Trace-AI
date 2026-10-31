@echo off
cd /d "%~dp0"
if not exist backend\.venv\Scripts\python.exe (
  where py >nul 2>nul
  if %errorlevel% equ 0 (
    py -m venv backend\.venv
  ) else (
    python -m venv backend\.venv
  )
  backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
)
start "Dark Trace AI Backend" cmd /k "backend\.venv\Scripts\python.exe backend\app.py"
