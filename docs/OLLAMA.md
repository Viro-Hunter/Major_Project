# Ollama — Local LLM for CyberGraphRAG (Week 6+)

**Default (free, low-RAM Qwen):** `qwen2.5:3b` (1.9GB) via Ollama — fits 4GB RAM, CPU-only. No paid key. First run pulls ~1.9GB (0.5b is 396MB for 2GB VMs); subsequent runs offline.

## Quickstart (any PC, WSL included)

```bash
git clone https://github.com/Viro-Hunter/Major_Project.git && cd Major_Project
cp .env.example .env   # already set to Ollama
# Option A — bare metal (recommended for WSL):
./scripts/setup.sh          # pulls qwen2.5:3b, creates .venv, builds dashboard
./scripts/run.sh            # API :8000, dashboard :5173

# Option B — Docker (one command for all 3 services):
docker compose up --build -d
docker exec cybergraphrag-ollama ollama pull qwen2.5:3b
# API http://localhost:8000/docs  Dashboard http://localhost:5173
```

## Model choice (RAM table)

| Model | RAM | Quality | Install |
|-------|-----|---------|---------|
| `qwen2.5:0.5b` | ~2GB | tiny, fastest | `ollama pull qwen2.5:0.5b` |
| `qwen2.5:3b` (default) | ~4GB | balanced, low-RAM | `ollama pull qwen2.5:3b` |
| `qwen2.5:7b` | ~8GB | higher quality | `ollama pull qwen2.5:7b` |
| `phi3:mini` | ~4GB | CPU-optimized | `ollama pull phi3:mini` |

Switch: `make pull-model MODEL=qwen2.5:3b` or `./scripts/pull_model.sh gemma2:9b`

## How it works (no code change needed)

`llm/client.py` is provider-agnostic. For Ollama we use the OpenAI SDK with:

```
LLM_PROVIDER=openai
OPENAI_API_BASE=http://localhost:11434/v1
OPENAI_API_KEY=ollama      # dummy
OPENAI_MODEL=qwen2.5:3b
```

Inside Docker, `OPENAI_API_BASE=http://ollama:11434/v1` (compose sets it).

If Ollama is down, `extraction/entity_extractor.py` and `reasoning/verdict_generator.py` fall back to rule-based/templates + groundedness check — so `pytest` stays green offline.

## WSL notes

- Install Ollama on **Windows host**: `winget install Ollama.Ollama`, then `ollama serve` stays reachable at `http://localhost:11434` from WSL.
- Or run Ollama in Docker: `docker compose up -d ollama` — no Windows install needed.

## Fine-tune for Sem 8

1. Build dataset: `python scripts/build_finetune_dataset.py --out data/finetune.jsonl` (uses `data/demo/*.csv` + `graph/schema.py`)
2. Train adapter (QLoRA) with `axolotl`/`unsloth` — see `Modelfile.finetuned`
3. `ollama create cybergraphrag:ft -f Modelfile.finetuned`
4. Set `.env`: `OPENAI_MODEL=cybergraphrag:ft`

Evaluate on `evaluation/metrics.py` before promoting.

## Troubleshooting

- `ollama: command not found` → https://ollama.com/download or use Docker.
- `Failed to connect to localhost:11434` → `ollama serve` or `docker compose up -d ollama`
- Slow on CPU → try `qwen2.5:3b` or `OLLAMA_NUM_THREADS=4`
