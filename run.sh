#!/usr/bin/env bash
# ByteENDE launcher for Linux / macOS.
# Creates a local virtual environment on first run, installs dependencies,
# then starts the web panel + API. Safe to re-run any time.
set -e
cd "$(dirname "$0")"

PYTHON_BIN="${PYTHON_BIN:-python3}"

if [ ! -d "venv" ]; then
  echo "[ByteENDE] Creating virtual environment..."
  "$PYTHON_BIN" -m venv venv
fi

# shellcheck disable=SC1091
source venv/bin/activate

echo "[ByteENDE] Installing dependencies..."
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet

echo "[ByteENDE] Starting on http://${BYTEENDE_HOST:-127.0.0.1}:${BYTEENDE_PORT:-8800}"
python run.py
