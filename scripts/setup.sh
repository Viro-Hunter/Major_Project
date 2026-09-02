#!/usr/bin/env bash
set -euo pipefail

# CyberGraphRAG — download-and-run setup for any PC (WSL / macOS / Linux / Windows)
# Usage: chmod +x scripts/setup.sh && ./scripts/setup.sh [--model llama3.1:8b]

MODEL="${1:-llama3.1:8b}"
if [[ "$1" == --model ]]; then MODEL="$2"; fi

echo "==> [1/5] Checking prerequisites..."
command -v python3 >/dev/null || { echo "python3 not found"; exit 1; }
command -v node >/dev/null || echo "WARN: node not found — dashboard will not build"
command -v git >/dev/null || { echo "git not found"; exit 1; }

# WSL detection
if grep -qi microsoft /proc/version 2>/dev/null; then
  echo "WSL detected — using localhost for Ollama (host 11434). Ensure Ollama is installed on Windows host or run 'docker compose up ollama'."
fi

echo "==> [2/5] Python venv & deps..."
if [ ! -d ".venv" ]; then python3 -m venv .venv; fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo "  Python deps OK"

echo "==> [3/5] Env file..."
if [ ! -f ".env" ]; then
  cp .env.example .env
  echo "  Created .env from .env.example (Ollama default: $MODEL). Edit if you want Anthropic."
else
  echo "  .env exists — keeping"
fi

echo "==> [4/5] Ollama model ($MODEL)..."
if command -v ollama >/dev/null 2>&1; then
  echo "  Ollama found: $(ollama --version)"
  if ! ollama list 2>/dev/null | grep -q "${MODEL%%:*}"; then
    echo "  Pulling $MODEL (first run ~5GB, may take a few minutes)..."
    ollama pull "$MODEL" || echo "WARN: ollama pull failed — you can retry: ollama pull $MODEL"
  else
    echo "  Model $MODEL already present"
  fi
  # Optional: create custom cybergraphrag alias
  if [ -f "Modelfile" ]; then
    echo "  Creating cybergraphrag alias..."
    ollama create cybergraphrag -f Modelfile 2>/dev/null || true
  fi
else
  echo "  Ollama not installed — skipping pull."
  echo "  Install: https://ollama.com/download"
  echo "  Windows (WSL): winget install Ollama.Ollama  (on Windows host)"
  echo "  macOS: brew install ollama"
  echo "  Linux: curl -fsSL https://ollama.com/install.sh | sh"
  echo "  Or use Docker: docker compose up -d ollama && docker exec cybergraphrag-ollama ollama pull $MODEL"
  echo "  The API will run with rule-based fallback until Ollama is available."
fi

echo "==> [5/5] Dashboard deps..."
if [ -d "dashboard" ] && command -v npm >/dev/null 2>&1; then
  (cd dashboard && npm install --silent && npm run build --silent) && echo "  Dashboard built"
else
  echo "  Skipping dashboard build (no npm/dashboard)"
fi

echo ""
echo "✅ Setup complete."
echo "Next: ./scripts/run.sh  OR  docker compose up --build"
echo "  API: http://localhost:8000/docs  |  Dashboard: http://localhost:5173"
echo "  Test: .venv/bin/pytest -q"
echo "  Ingest demo: .venv/bin/python scripts/ingest_sample_data.py"
