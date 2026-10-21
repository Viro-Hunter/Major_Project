# CyberGraphRAG: Insider Threat Detection via Graph-Augmented Retrieval

> Enterprise-grade threat detection system leveraging graph-based reasoning, LLM-augmented analysis, and behavioral correlation for real-time insider threat detection and incident response.

---

## 📋 Overview

**CyberGraphRAG** is a production-ready system for detecting and investigating insider threats through:

- **Graph-Based Correlation:** Builds a normalized entity relationship graph from security logs, enabling fast pattern discovery and threat propagation scoring
- **LLM-Augmented Reasoning:** Uses Claude/GPT to synthesize behavioral narratives, derive risk scores, and generate explainable verdicts grounded in evidence
- **Adaptive Retrieval:** Routes queries between structural graph queries (subgraph traversal) and semantic vector search (behavioral anomalies)
- **Confidence Scoring:** Multiplies edge trust and decays confidence over time, avoiding spurious high-confidence correlations
- **Real-Time Ingestion:** Processes streaming security events with incremental graph updates and alert thresholding
- **Audit & Compliance:** Complete action trail, analyst queue, and automated vs. manual decision logging

**Use Cases:**
- Detect data exfiltration chains (user → host → network → external contact)
- Correlate failed authentications, privilege escalation, and unusual access patterns
- Prioritize incidents by risk score and groundedness
- Auto-execute low-risk actions (IP block, force reauth); escalate ambiguous cases to analysts

---

## 🏗️ Architecture & Tech Stack

### Core Technologies

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| **Backend API** | Python 3.11, FastAPI | Type-safe, async-ready, fast to iterate |
| **Graph Store** | NetworkX (prototype) / Neo4j (production) | In-memory for semester prototype; Neo4j for scale |
| **Vector Store** | Chroma / FAISS | Lightweight, file-based, no server overhead |
| **LLM Integration** | **Ollama `llama3.1:8b` (default, local, free)** · Anthropic Claude / OpenAI GPT (optional) | Local-first via OpenAI-compatible `http://localhost:11434/v1`; see `docs/OLLAMA.md`. Fine-tune template `Modelfile.finetuned` for Sem 8. |
| **Dataset** | CERT r4.2/r5.2 + synthetic scenarios | Realistic insider-threat logs; hand-crafted demos |
| **Frontend** | React + Cytoscape.js / vis-network | Real-time graph visualization, incident queue UI |
| **Monitoring & Logs** | PostgreSQL + audit tables | Compliance trail; optional distributed tracing |
| **Containerization** | Docker + Docker Compose | Reproducible local + CI/CD environments |

### System Architecture Diagram

```mermaid
flowchart TD
    A["Security Event Stream<br/>(CERT Logs, Syslog, EDR Feeds)"] --> B
 
    subgraph B["Ingestion"]
        B1["log_parser.py"]
        B2["stream_simulator"]
    end
 
    B --> C
 
    subgraph C["Extraction"]
        C1["entity_extractor.py<br/>(LLM: Event → Entities + Relations)"]
        C2["schema.py"]
    end
 
    C --> D["Graph Store<br/>(NetworkX / Neo4j)<br/>graph_store_updater.py"]
    C --> E["Vector Store<br/>(Chroma / FAISS fallback)"]
    D <-->|confidence scoring + decay| E
 
    D --> F
    E --> F
 
    subgraph F["Retrieval Router"]
        F1["Classify Query Type:<br/>• Structural (graph)<br/>• Lookup (vector)<br/>• Hybrid (both)"]
    end
 
    F --> G["Graph Retriever<br/>(traverse subgraphs)"]
    F --> H["Vector Retriever<br/>(semantic search)"]
 
    G --> I
    H --> I
 
    subgraph I["Reasoning Engine"]
        I1["verdict_generator<br/>(LLM: Subgraph → Narrative)"]
        I2["groundedness_chk"]
    end
 
    I --> J
 
    subgraph J["Action Gating - gate.py"]
        J1["Threshold"]
        J2["Auto-execute"]
        J3["Analyst queue"]
    end
 
    J --> K["Simulated Actions<br/>(block, reauth)"]
    J --> L["Audit Log & Compliance Trail<br/>(PostgreSQL)"]
 
    K --> M["React Dashboard<br/>• Graph View<br/>• Incident Queue<br/>• Metrics Panel"]
    L --> M
```

---

## 📂 Repository Structure

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the module-by-module map of the pipeline.

---

## 🚀 Quick Start — For Your Friend (Copy-Paste, 3 Commands)

> **No paid keys. No daily training. Just works.**

```bash
# 1) Clone
git clone https://github.com/Viro-Hunter/Major_Project.git
cd Major_Project
cp .env.example .env   # already set to free local Ollama

# 2) One-command setup (WSL / macOS / Linux — pulls llama3.1:8b ~5GB first time only)
./scripts/setup.sh
#    ↳ creates .venv, pip install, ollama pull llama3.1:8b, npm build
#    If Ollama not installed: https://ollama.com/download  OR use Docker:
#    docker compose up --build -d && docker exec cybergraphrag-ollama ollama pull llama3.1:8b

# 3) Run
./scripts/run.sh
# API → http://localhost:8000/docs
# Dashboard → http://localhost:5173  (shows 501 nodes, multi-entity graph)
```
That's it. **Fine-tune is NOT daily** — it's *one time* in Sem 8 only if you want a custom model (see below). Your friend never needs to train.

<details>
<summary>Manual steps (if you prefer)</summary>

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn api.main:app --reload --port 8000  # backend
cd dashboard && npm install && npm run dev  # frontend
```
</details>

### Choosing the reasoning model (OpenRouter, Claude, OpenAI, Groq, Gemini or local)

Open the dashboard and use the **Reasoning model** panel at the top:

1. Paste an API key. The provider is detected as you type (`sk-or-` OpenRouter, `sk-ant-` Anthropic, `sk-proj-`/`sk-` OpenAI, `gsk_` Groq, `AIza` Gemini, `xai-` xAI); you can override it.
2. Click **Check key**. The API verifies the key with the provider.
   - **OpenRouter with credit** → paid models are unlocked and the recommended one (newest Claude Sonnet if listed) is selected; each option shows an estimated cost per verdict and your remaining credit.
   - **OpenRouter free tier, or credit exhausted** → only free models are listed and the strongest free model for JSON reasoning is selected automatically (large instruct models preferred; tiny, vision-only and slow "thinking" models ranked down).
3. Change the model from the dropdown any time, and press **Send test prompt** to confirm it answers.

The key stays in the API server's memory only (never written to disk, logged or sent back to the browser) and is forgotten on restart. To make it permanent put it in `.env`:

```bash
LLM_PROVIDER=openrouter
OPENROUTER_API_KEY=sk-or-v1-...
OPENROUTER_MODEL=auto        # pick the best model for this key at startup, or name one
```

Without any key the system uses local Ollama, and if no model answers it falls back to a deterministic, grounded evidence template.

### First Query (Works Immediately)

```bash
# No ingest needed — 15% CERT graph (501 nodes) auto-loads on startup.
# Or rebuild it:
.venv/bin/python scripts/build_graph_from_cert.py --users 200 --rows-per-user 80 --output data/cert_graph_15pct.json

# Query
curl http://localhost:8000/health
curl http://localhost:8000/graph/subgraph/AAM0658?hops=2 | jq .nodes[0]

curl -X POST http://localhost:8000/incidents/analyze \
  -H "Content-Type: application/json" \
  -d '{"entity":"AAM0658","query":"Why is user linked to host?"}' | jq .verdict
# → {"narrative":..., "risk_score":0.9, "model":"llama3.1:8b"} when Ollama live, else "template-fallback"
```

### Fine-Tune? One Time Only (Optional, Sem 8)

```bash
# You do this ONCE, not daily. Friend just pulls the result.
.venv/bin/python scripts/build_finetune_dataset.py --limit 5000 --output data/finetune.jsonl
ollama create cybergraphrag:ft -f Modelfile.finetuned  # needs adapters/ from training
echo "OPENAI_MODEL=cybergraphrag:ft" >> .env
# Friend: ollama pull <your-registry>/cybergraphrag:ft  (no GPU needed)
```
See `docs/TRAINING.md:1` for full QLoRA guide.

---

## 🔧 Configuration

### Environment Variables

```bash
# LLM Configuration — default is local Ollama (free, no key)
LLM_PROVIDER=openai
OPENAI_API_BASE=http://localhost:11434/v1
OPENAI_API_KEY=ollama
OPENAI_MODEL=llama3.1:8b
# Paid fallback (optional):
# LLM_PROVIDER=anthropic
# ANTHROPIC_API_KEY=sk-ant-...
# LLM_MODEL=claude-3-5-sonnet

# Graph Store
GRAPH_STORE_TYPE=networkx  # or neo4j
NEO4J_URI=bolt://localhost:7687  # if using Neo4j
NEO4J_USER=neo4j
NEO4J_PASSWORD=...

# Vector Store
VECTOR_STORE_TYPE=chroma  # or faiss
CHROMA_PERSIST_DIR=./data/chroma

# Database (PostgreSQL, optional but recommended for production)
DATABASE_URL=postgresql://user:password@localhost:5432/cyber_graphrag
SQLALCHEMY_ECHO=false

# Action & Gating
ACTION_AUTO_THRESHOLD=0.85
ACTION_ANALYST_THRESHOLD=0.50
MAX_AUTO_ACTIONS_PER_DAY=50

# Logging & Monitoring
LOG_LEVEL=INFO
OPENTELEMETRY_ENABLED=false  # Set true for distributed tracing
PROMETHEUS_ENABLED=true

# Security
SECRET_KEY=your-secret-key-here
CORS_ORIGINS=["http://localhost:3000"]
```

See `.env.example` for all options.

---

## 🔁 Recent changes (high level)

These notes summarize notable work merged since the last README update:

- (2026-08-13) feat: Added a provider-agnostic LLM client and completed the entity/relation extraction pipeline — extraction is now modular and can target Anthropic or OpenAI via a common interface.
- (2026-08-13) feat: Introduced explicit graph schema models and ATT&CK technique lookup support to enrich relation types and map behaviors to techniques.
- (2026-08-13) data: Added a trimmed (~159MB) demo subset of the CERT r4.2 dataset for offline demos and CI-friendly testing.
- (2026-08-12) tests: Added data-loading tests and expanded unit/integration coverage for ingestion and parsing logic.

If you rely on the demo subset in CI, point ingestion to the `data/` demo files included in the repository (see commit history for exact filenames).

---

## 📊 Core Modules

(Documentation in this section reflects the current codebase — see files under each package for exact APIs.)

### 1. Ingestion (`ingestion/`)

**Responsibility:** Parse raw security logs into normalized event objects.

**Key Functions:**
- `log_parser.py::parse_cert_log()` — Convert CERT CSV rows to Event Pydantic models
- `stream_simulator.py::replay_stream()` — Emit events with real timestamps for demos

---

### 2. Extraction (`extraction/`)

**Responsibility:** Use an LLM to extract entities and relations from events. The extraction layer now uses a provider-agnostic LLM client so you can swap Anthropic/OpenAI without changing extraction logic.

**Key Functions:**
- `entity_extractor.py::extract_from_event()` — Call LLM with prompt; validate schema
- `schema.py::EntityType, RelationType` — Define allowed types (User, IP, Host, ThreatActor, Exfiltration, PrivEsc, etc.)

---

### 3. Graph (`graph/`)

**Responsibility:** Store entities/relations, compute edge confidence, and provide query interfaces. Graph schema models were added to make relation typing explicit and to support ATT&CK technique mapping.

**Key Functions:**
- `graph_store.py::GraphStore` — Wrapper around NetworkX; `add_node()`, `add_edge()`, `get_subgraph()`
- `confidence.py::compute_edge_confidence()` — Trust score × decay × path multiplication
- `updater.py::incremental_insert()` — Apply new events without full recompute

---

(Other module descriptions unchanged; see the full README in the repository for per-module examples and API endpoints.)

---

## 🎬 Story mode (for presentations and non-technical audiences)

Open the dashboard and click **▶ Story mode** (or go to `http://localhost:5173/#story`). Twelve presenter-paced scenes
(→ / Space / ← or the buttons) follow one employee from ordinary days to two late nights of data theft, then show each
step: connecting the dots, comparing with colleagues, the AI's plain-English answer, the fact-check that rejects an
invented claim, confidence, the STIX 2.1 export and the measured results. It needs no API server, so it is safe to present offline.

Every number in it comes from a real run: `python scripts/build_story.py` regenerates `dashboard/public/story_data.json`
(re-run it after the benchmark). `python scripts/demo.py --pause` tells the same case in the terminal.

## 🛰️ STIX 2.1 output

`GET /incidents/{entity}/stix` (or **Download this case as STIX 2.1** in Story mode) returns the checked verdict as a STIX 2.1
bundle: report, suspected threat actor, MITRE's **official** ATT&CK attack-pattern objects (original ids, from
`data/attack_patterns.stix21.json`, rebuilt by `scripts/extract_attack_stix.py`), sightings, observed data and a note with
the groundedness result. Only verified evidence is exported. Bundles are checked with the OASIS `stix2-validator` in the tests.

## 🧪 Testing & Evaluation

```bash
pytest -q                                   # 123 unit/integration tests, no API key or model needed

python scripts/run_pipeline_e2e.py          # Week 9: all 7 stages on 20 users, per-stage timing, exit 1 on any error
python evaluation/run_benchmark.py          # Week 10: five metrics -> evaluation/results/benchmark_report.md
python scripts/generate_report_assets.py    # Week 11: figures -> docs/report_assets/, tables -> docs/report_tables.md
python scripts/demo.py --pause              # Week 12: live walkthrough for the presentation
```

Add `--llm` to the e2e, benchmark or demo scripts to use the configured model instead of the offline template.

**Real-LLM comparison.** With an OpenRouter key in `.env` (`LLM_PROVIDER=openrouter`, `OPENROUTER_MODEL=auto`):

```bash
python evaluation/compare_models.py --sleep 4            # template vs your LLM on the same 30 users
python evaluation/compare_models.py --sleep 4 --hybrid   # + LLM extraction of implicit relations
```

`evaluation/results/model_comparison.md` shows detection quality and, for the real model, how many verdicts cited
evidence that does not exist and how many the self-check repaired or flagged. `--sleep 4` keeps free models under their rate limit.

**Extraction.** Structured CERT fields are extracted by rules (exact, free). `--extractor hybrid` (benchmark) or
`--llm-extract` (e2e) adds LLM-inferred relations from windows of each user's events, capped at 0.6 confidence; any
entity the model names that does not appear in the events it was shown is rejected (`extraction/llm_enrichment.py`).

**Ground truth.** The benchmark uses the official CERT r4.2 answer key when `data/raw/answers/` exists
(`python scripts/fetch_cert_data.py answers`). Otherwise it injects seeded insider scenarios, modelled on
the three published r4.2 scenarios, into real users' activity and says so in every report. Use the
answer-key run for numbers you publish.

Current results (injected ground truth, 60 users / 12 insiders, offline template; see the report for all tables):

| Metric | Value |
|---|---|
| Detection | precision 0.636, recall 0.583, F1 0.609, false-positive rate 8.3% |
| Same without peer-prevalence discount | F1 0.462, false-positive rate 58.3% |
| Graph completeness | 100% |
| Threat-correlation precision | 0.440 |
| Evidence retrieval F1 | 0.319 |
| Response time | ~3 s indexing, ~16 ms per query |
| Groundedness under simulated hallucination | 15/15 fabricated citations caught, 0 false alarms |

---

## 📈 Performance & Scalability

(Prototype and roadmap information unchanged.)

---

## 🤝 Contributing

We follow standard open-source practices:

1. **Fork & branch:** Create a feature branch from `develop`
2. **Code style:** Black, isort, ruff; run `make format && make lint`
3. **Tests:** Add unit tests for new code; aim for >80% coverage
4. **Commit messages:** Follow [Conventional Commits](https://www.conventionalcommits.org/)
5. **Pull requests:** Link to issues; describe the change and testing approach

See `CONTRIBUTING.md` for detailed guidelines.

---

## 📖 Documentation

- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** — Deep dive into module interactions and design decisions
- **[API.md](docs/API.md)** — Full OpenAPI specification and examples
- **[DEPLOYMENT.md](docs/DEPLOYMENT.md)** — Production setup, scaling, monitoring
- **[CONTRIBUTING.md](docs/CONTRIBUTING.md)** — Development workflow and style guide
- **[examples/](docs/examples/)** — End-to-end walkthroughs and cURL snippets

---

## 📦 Deployment

### Docker Compose (Development)
```bash
docker-compose up -d
```

### Kubernetes (Production, Optional)
See `docs/DEPLOYMENT.md` for Helm charts and manifests.

### Cloud Platforms
- **AWS:** ECS + Aurora PostgreSQL + Secrets Manager
- **Azure:** Container Instances + Cosmos DB + Key Vault
- **GCP:** Cloud Run + Cloud SQL + Secret Manager

---

## 📜 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## 🙋 Support & Contact

- **Issues:** Use [GitHub Issues](https://github.com/Viro-Hunter/Major_Project/issues) for bugs and feature requests
- **Discussions:** [GitHub Discussions](https://github.com/Viro-Hunter/Major_Project/discussions) for questions and ideas
- **Email:** [tabrez@realitykernel.dev](mailto:tabrez@realitykernel.dev)

---

## 🏆 Acknowledgments

- **CERT Insider Threat Dataset (r4.2/r5.2)** for realistic behavioral data
- **FastAPI community** for the excellent web framework
- **NetworkX team** for the graph library
- **Anthropic & OpenAI** for powerful LLM capabilities
- **Qwen & Ollama** for their open-source models
---

## Roadmap

### Phase 1 (Semester): MVP ✅
- [x] Log ingestion & parsing
- [x] Entity extraction (LLM-based)
- [x] Graph construction & confidence scoring
- [x] Graph-based retrieval
- [x] LLM-powered verdict generation
- [x] Action gating & execution
- [x] REST API
- [x] React dashboard

### Phase 2 (Post-semester): Production Hardening
- [ ] Neo4j backend integration
- [ ] PostgreSQL + advanced audit logging
- [ ] Distributed tracing (OpenTelemetry)
- [ ] Kubernetes deployment
- [ ] Advanced analytics & dashboards (Grafana)
- [ ] RBAC & SSO integration
- [ ] Formal security audit

### Phase 3: Advanced Features
- [ ] Real-time Kafka ingestion
- [ ] Multi-tenant support
- [ ] Custom ML models for risk scoring
- [ ] Integration with commercial SIEM platforms
- [ ] Automated playbooks & response automation

---

**Last Updated:** 2026-08-13  
**Maintained By:** Viro-Hunter Team
