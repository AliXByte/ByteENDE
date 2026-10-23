@echo off
REM ByteENDE launcher for Windows.
REM Creates a local virtual environment on first run, installs dependencies,
REM then starts the web panel + API. Safe to re-run any time.

cd /d "%~dp0"

if not exist venv (
    echo [ByteENDE] Creating virtual environment...
    python -m venv venv
)

call venv\Scripts\activate.bat

echo [ByteENDE] Installing dependencies...
python -m pip install --upgrade pip --quiet
python -m pip install -r requirements.txt --quiet

echo [ByteENDE] Starting on http://127.0.0.1:8800
python run.py
