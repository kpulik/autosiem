#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

DB_PATH="${AUTOSIEM_DB:-data/autosiem.db}"
HOST="${AUTOSIEM_HOST:-127.0.0.1}"
PORT="${AUTOSIEM_PORT:-8000}"
URL="http://${HOST}:${PORT}/"

mkdir -p data

python - <<'PY'
import importlib.util
import subprocess
import sys

missing = [pkg for pkg in ("fastapi", "uvicorn") if importlib.util.find_spec(pkg) is None]
if missing:
    print(f"Installing missing API dependencies: {', '.join(missing)}")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-e", ".[api]"])
PY

echo "Checking for existing demo data in ${DB_PATH}..."
if python - "${DB_PATH}" <<'PY'
import sqlite3
import sys
from pathlib import Path

db_path = Path(sys.argv[1])
if not db_path.exists():
    raise SystemExit(0)
try:
    conn = sqlite3.connect(db_path)
    count = conn.execute("select count(*) from incidents").fetchone()[0]
    conn.close()
except sqlite3.Error:
    raise SystemExit(0)
raise SystemExit(0 if count == 0 else 1)
PY
then
  echo "Seeding AutoSIEM demo data into ${DB_PATH}..."
  PYTHONPATH=src python -m autosiem.cli demo --db "${DB_PATH}" >/tmp/autosiem-demo-output.json || {
    echo "Failed to seed demo data. Try: PYTHONPATH=src python -m autosiem.cli demo --db ${DB_PATH}"
    exit 1
  }
else
  echo "Demo data already present in ${DB_PATH}; skipping seed."
fi

echo "Starting AutoSIEM dashboard at ${URL}"
echo "Press Ctrl+C in this terminal to stop the server."

if command -v open >/dev/null 2>&1; then
  (sleep 1.5 && open "${URL}") &
fi

AUTOSIEM_DB="${DB_PATH}" PYTHONPATH=src python -m uvicorn autosiem.web.api:app --host "${HOST}" --port "${PORT}" --reload
