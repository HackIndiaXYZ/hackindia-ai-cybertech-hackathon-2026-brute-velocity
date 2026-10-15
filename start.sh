#!/bin/bash
# ============================================================
# Velbrix - One-command starter for Replit / local dev
# Usage: bash start.sh
# ============================================================
set -e

echo "================================================"
echo "  Velbrix - Build fast. Verify before you ship."
echo "  Authorized testing only | Synthetic demo data"
echo "================================================"

cd "$(dirname "$0")"

# --- Install Python dependencies if missing ---
if ! python3 -c "import fastapi" 2>/dev/null; then
  echo "[setup] Installing Python dependencies..."
  pip install -r requirements.txt --quiet 2>&1 | tail -5 || {
    echo "[setup] Full pip install failed, installing core deps..."
    pip install fastapi "uvicorn[standard]" python-multipart pydantic pydantic-settings httpx python-dotenv PyYAML Jinja2 --quiet
  }
fi

# --- Load .env if present ---
if [ -f .env ]; then
  echo "[setup] Loading .env"
  set -a
  source .env
  set +a
fi

# --- Determine port (Replit uses 8000 -> 80) ---
PORT="${VELBRIX_PORT:-8000}"
HOST="${VELBRIX_HOST:-0.0.0.0}"

echo "[run] Starting Velbrix on http://${HOST}:${PORT}"
echo "[run] Demo ready at: /demo/vibebank"
echo "------------------------------------------------"

exec python3 -m uvicorn main:app --host "$HOST" --port "$PORT" --reload
