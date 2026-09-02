#!/usr/bin/env bash
set -euo pipefail
# Pull / switch Ollama model — e.g. ./scripts/pull_model.sh qwen2.5:3b
MODEL="${1:-llama3.1:8b}"
echo "Pulling $MODEL..."
if command -v ollama >/dev/null 2>&1; then
  ollama pull "$MODEL"
  echo "Updating .env OPENAI_MODEL..."
  if grep -q "^OPENAI_MODEL=" .env 2>/dev/null; then
    sed -i "s|^OPENAI_MODEL=.*|OPENAI_MODEL=$MODEL|" .env
  else
    echo "OPENAI_MODEL=$MODEL" >> .env
  fi
  echo "Done. Restart API to pick up new model."
else
  echo "Ollama not installed. Use Docker: docker exec cybergraphrag-ollama ollama pull $MODEL"
  exit 1
fi
