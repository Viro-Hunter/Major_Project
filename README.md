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

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                        Security Event Stream                                 │
│                    (CERT Logs, Syslog, EDR Feeds)                            │
└────────────────────────────┬────────────────────────────────────────────────────┘
                             │
                    ┌────────▼────────┐
                    │   Ingestion     │
                    │  log_parser.py  │  ◄─── Replay with timestamps
                    │stream_simulator │
                    └────────┬────────┘
                             │
                    ┌────────▼──────────┐
                    │   Extraction      │
                    │entity_extractor.py│  ◄─── LLM: Event → Entities
                    │    schema.py      │       + Relations (w/ types)
                    └────────┬──────────┘
                             │
          ┌──────────────────▼──────────────────┐
          │                                      │
    ┌─────▼──────┐                    ┌─────────▼──────┐
    │ Graph Store │                    │ Vector Store   │
    │ (NetworkX/  │◄─── confidence ───►│  (Chroma/FAISS)│
    │  Neo4j)     │      scoring       │ (fallback)     │
    │ graph_store │      + decay       │                │
    │ updater.py  │                    └────────────────┘
    └──────┬──────┘
           │
      ┌────▼───────────────────────┐
      │      Retrieval Router       │
      │  Classify Query Type:       │
      │  • Structural (graph)       │
      │  • Lookup (vector)          │
      │  • Hybrid (both)            │
      └────┬──────────────────┬─────┘
           │                  │
   ┌───────▼─────┐   ┌────────▼────────┐
   │   Graph      │   │  Vector         │
   │  Retriever   │   │  Retriever      │
   │  (traverse   │   │  (semantic      │
   │   subgraphs) │   │   search)       │
   └───────┬──────┘   └────────┬────────┘
           │                   │
           └─────────┬─────────┘
                     │
           ┌─────────▼──────────┐
           │ Reasoning Engine   │
           │ verdict_generator  │  ◄─── LLM: Subgraph → Narrative
           │groundedness_chk    │       + Risk Score + Evidence Links
           └─────────┬──────────┘
                     │
           ┌─────────▼──────────┐
           │  Action Gating     │
           │  gate.py           │
           │  ├─ Threshold      │
           │  ├─ Auto-execute   │
           │  └─ Analyst queue  │
           └─────────┬──────────┘
                     │
    ┌────────────────┴─────────────────┐
    │                                   │
┌───▼──────────────┐      ┌─────────────▼─────┐
│  Simulated       │      │  Audit Log &      │
│  Actions         │      │  Compliance Trail │
│ (block, reauth)  │      │  (PostgreSQL)     │
└──────────────────┘      └───────────────────┘
           │                    │
           └────────┬───────────┘
                    │
           ┌────────▼─────────┐
           │  React Dashboard │
           │  • Graph View    │
           │  • Incident Q    │
           │  • Metrics Panel │
           └──────────────────┘
```

---

## 📂 Repository Structure

```
<snipped for brevity — full structure remains in repo>
```

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

### First Query (Works Immediately, 501 nodes ready)

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

## 🧪 Testing & Evaluation

### Unit & Integration Tests

```bash
# Run all tests
pytest tests/ -v

# Run only unit tests
pytest tests/unit/ -v

# Run integration tests (requires API running)
pytest tests/integration/ -v --tb=short

# Coverage report
pytest tests/ --cov=. --cov-report=html
```

### Benchmark & Metrics

```bash
# Run full evaluation suite against CERT r4.2
python evaluation/benchmark.py --dataset cert_r4.2 --output results/latest_run.json

# View results
cat results/latest_run.json | jq '.metrics'
```

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
- **Email:** [maintainer-email@example.com](mailto:maintainer-email@example.com)

---

## 🏆 Acknowledgments

- **CERT Insider Threat Dataset (r4.2/r5.2)** for realistic behavioral data
- **FastAPI community** for the excellent web framework
- **NetworkX team** for the graph library
- **Anthropic & OpenAI** for powerful LLM capabilities

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
