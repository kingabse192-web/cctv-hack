#!/usr/bin/env bash
# AB Search 😊 — safe demo launcher (Linux / WSL / macOS)
# Double-click is not needed: open a terminal and run:
#   bash /home/ab/cctv/TRY_ME.sh
set -e
cd "$(dirname "$0")"
if [ -f .venv/bin/activate ]; then
  echo "Activating local virtual environment..."
  source .venv/bin/activate
fi
if ! python3 -c 'import absearch' 2>/dev/null; then
  echo "Installing AB Search locally (first run only)..."
  python3 -m pip install -e . --quiet
fi
echo
echo "Starting SAFE demo dashboard..."
echo "Open this address in your browser: http://127.0.0.1:8765/"
echo "Press Ctrl+C in this window to stop."
echo
python3 -m absearch --demo --web
