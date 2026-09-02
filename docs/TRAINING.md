# Training & Fine-Tuning Guide — From 15% → 100% (Week 12 Robust)

**Status (Week 6):** Base `llama3.1:8b` via Ollama, **not yet fine-tuned**. All verdicts are from **Ollama (via `llm/client.py`)**, not hardcoded — you can verify by `curl` with `OPENAI_MODEL=llama3.1:8b` and checking `verdict.model` field. Hardcoded `_template_verdict` is only the offline fallback when `ollama serve` is down.

**Goal Sem 8:** Fine-tune a small adapter (QLoRA, ~50MB) on CERT insider-threat extraction → reasoning, then serve as `cybergraphrag:ft` (still Ollama, still `git clone && ./run.sh`). Week 12 will ingest **100%** of `data/demo/` (or full `data/raw/r4.2` if you have it) — same `scripts/build_graph_from_cert.py` with larger limits.

---

## 1) Verify Current (Not Hardcoded)

```bash
# Start API with Ollama (see docs/OLLAMA.md)
ollama serve &  # or docker compose up -d ollama
ollama pull llama3.1:8b
OPENAI_MODEL=llama3.1:8b .venv/bin/uvicorn api.main:app --reload &
curl -X POST http://localhost:8000/incidents/analyze -H "Content-Type: application/json" -d '{"entity":"AAM0658","query":"Why is user linked to host?"}' | jq .verdict.model
# → "llama3.1:8b" (live)  vs  "template-fallback" (offline)
```

`reasoning/verdict_generator.py:1` now calls `LLMClient(provider=openai, base_url=http://localhost:11434/v1)` via `llm/client.py:1`. If `OPENAI_API_BASE` is unreachable, it falls back to `_template_verdict` (grounded but not LLM).

## 2) 15% → 100% Dataset

**Current:** `data/cert_graph_15pct.json` (501 nodes, 16202 edges, 2.3MB) built from `data/demo/` with:

```bash
PYTHONPATH=. .venv/bin/python scripts/build_graph_from_cert.py --users 200 --rows-per-user 80 --output data/cert_graph_15pct.json
# ~14% of 557k demo rows, ~80k events, 10-20% sweet spot, many entities to analyze
```

API bootstrap (`api/main.py:35`) auto-loads this file if present; else builds live from `data/demo/*.csv` with `CERT_USERS=200 CERT_ROWS_PER_USER=80` (env-tunable). Set `CERT_SAMPLE_RATIO=0` to force minimal 8-node fallback for tests.

**Week 12 (100%):**

```bash
# Demo subset 100% (~557k rows)
PYTHONPATH=. .venv/bin/python scripts/build_graph_from_cert.py --users 1000 --rows-per-user 1000 --output data/cert_graph_100pct.json
# Full raw (if you have data/raw/r4.2/ ~13GB): same command, it auto-discovers raw
# Then set bootstrap to prefer it:
echo "CERT_GRAPH_PATH=data/cert_graph_100pct.json" >> .env
# Or directly in api/main.py keep 15pct default but allow override via env
```

`evaluation/metrics.py` (Week 10) will measure on 100%: retrieval accuracy, graph completeness, threat-correlation precision, response time (index vs per-query), F1.

## 3) Fine-Tune (Sem 8, Small Model)

### 3a. Build SFT dataset (no manual labeling)

```bash
# Converts CERT + ATT&CK lookup into ShareGPT JSONL
.venv/bin/python scripts/build_finetune_dataset.py --input data/demo --output data/finetune.jsonl --limit 5000
# Output: {"system": "...", "user": "Event ...", "assistant": "{\"entities\": [...], \"relations\": [...] }"} + reasoning examples
head data/finetune.jsonl
```

`scripts/build_finetune_dataset.py` (to be added) samples `logon/device/file/email/http` rows, pairs each event window (5 events per user) with gold entities/relations from `graph/schema.py` + `data/attack_technique_lookup.json` (STIX 2.1). For reasoning, it pairs `retrieve_subgraph` output with `verdict` JSON.

### 3b. Train adapter (QLoRA, 1x 24GB or Colab T4)

```bash
# Option: unsloth (fast, low RAM) — example
pip install unsloth axolotl
# Prepare config axolotl/cybergraphrag.yml:
#   base_model: meta-llama/Meta-Llama-3.1-8B
#   datasets: [{path: data/finetune.jsonl, type: sharegpt}]
#   lora_r: 64, lora_alpha: 128, load_in_4bit: true, epochs: 2, micro_batch: 2

axolotl train axolotl/cybergraphrag.yml
# Output: adapters/cybergraphrag-lora/
# Quantize to GGUF for Ollama:
# python -m llamacpp.convert --q4_K_M adapters/cybergraphrag-lora
```

Hardware: 8B 4-bit QLoRA fits on 16GB RAM + 8GB VRAM (Colab free T4 works). For pure CPU, use `qwen2.5:3b` base.

### 3c. Serve fine-tuned

```bash
# Create Ollama model from adapter
ollama create cybergraphrag:ft -f Modelfile.finetuned
# Modelfile.finetuned: FROM llama3.1:8b + ADAPTER ./adapters/cybergraphrag-lora
# Update .env:
echo "OPENAI_MODEL=cybergraphrag:ft" >> .env
# Restart API — verdict.model will now be cybergraphrag:ft
curl -X POST http://localhost:8000/incidents/analyze -d '{"entity":"AAM0658","query":"..."}' | jq .verdict.model
```

Push to teammates: `ollama push` to private registry or export `GGUF` to `huggingface` (see `scripts/push_adapter.sh`).

## 4) Robustness Checklist for Week 12

- [ ] `data/cert_graph_100pct.json` builds without OOM (streaming, chunksize 20k in `build_graph_from_cert.py`)
- [ ] `api/main.py` bootstrap handles both 15% and 100% via `GraphStore.from_json` (streaming load)
- [ ] `evaluation/benchmark.py` compares base vs `cybergraphrag:ft` on retrieval accuracy / groundedness / F1
- [ ] `tests/` mock LLM via `llm/client.py` so CI stays offline-green
- [ ] `docker-compose.yml` mounts `data/` as volume so graph survives `docker compose down`
- [ ] Dashboard pagination for 500+ nodes (vis-network handles 5k+; table paginated)

## 5) Is the Model Trained Now?

No — current `llama3.1:8b` is **base, instruct-tuned by Meta**, not on CERT. It works zero-shot via prompts (`extraction/prompts/extract.txt`, `reasoning/verdict_generator.py` system prompt + STIX lookup). Fine-tune (above) will teach it CERT-specific patterns and reduce hallucination, but is optional for Week 6 demo. All results you see now are from Ollama (check `model` field) unless Ollama is down (then `template-fallback`).

For immediate robustness, keep Ollama running; fallback is only for CI/offline.
