#!/usr/bin/env bash
set -euo pipefail

# Simple bare-metal run (no Docker) — for WSL / local dev
# Usage: ./scripts/run.sh
# Requires: .venv, Ollama (optional), .env

if [ ! -f ".env" ]; then echo ".env not found — run ./scripts/setup.sh first"; exit 1; fi
if [ ! -d ".venv" ]; then echo ".venv not found — run ./scripts/setup.sh first"; exit 1; fi

# Load env
set -a; source .env; set +a
API_PORT="${API_PORT:-8000}"
DASH_PORT="${DASH_PORT:-5173}"

# Check Ollama
if [ "${LLM_PROVIDER:-openai}" = "openai" ] && [[ "${OPENAI_API_BASE:-}" == *"11434"* ]]; then
  if ! curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
    echo "WARN: Ollama not reachable at ${OPENAI_API_BASE:-http://localhost:11434/v1} — API will use rule-based fallback."
    echo "Start Ollama: ollama serve  OR  docker compose up -d ollama"
  else
    echo "Ollama reachable — model: ${OPENAI_MODEL:-llama3.1:8b}"
  fi
fi

echo "==> Starting API on http://localhost:${API_PORT} ..."
# shellcheck disable=SC1091
source .venv/bin/activate
uvicorn api.main:app --host 0.0.0.0 --port "$API_PORT" --reload &
API_PID=$!

echo "==> Starting dashboard on http://localhost:${DASH_PORT} ..."
if command -v npm >/dev/null 2>&1 && [ -f "dashboard/package.json" ]; then
  (cd dashboard && npm run dev -- --port "$DASH_PORT" --host 0.0.0.0) &
  DASH_PID=$!
  echo "API PID $API_PID, dashboard PID $DASH_PID"
  echo "Press Ctrl+C to stop both"
  wait
else
  echo "Dashboard not started (no npm). API only at http://localhost:${API_PORT}/docs"
  wait "$API_PID"
fi
