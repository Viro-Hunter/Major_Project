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
| **LLM Integration** | Anthropic Claude / OpenAI GPT | High reasoning quality; templated prompts for consistency |
| **Dataset** | CERT r4.2/r5.2 + synthetic scenarios | Realistic insider-threat logs; hand-crafted demos |
| **Frontend** | React + Cytoscape.js / vis-network | Real-time graph visualization, incident queue UI |
| **Monitoring & Logs** | PostgreSQL + audit tables | Compliance trail; optional distributed tracing |
| **Containerization** | Docker + Docker Compose | Reproducible local + CI/CD environments |

### System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Security Event Stream                             │
│                    (CERT Logs, Syslog, EDR Feeds)                       │
└────────────────────────────┬────────────────────────────────────────────┘
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
┌───▼──────────────┐      ┌────────────▼─────┐
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
cyber-graphrag/
├── README.md                          # This file
├── pyproject.toml                     # Poetry/pip dependencies + metadata
├── Dockerfile                         # Container build
├── docker-compose.yml                 # Local dev stack
├── .env.example                       # Template for secrets
├── .github/workflows/                 # CI/CD pipelines
│   ├── test.yml                       # Unit + integration tests
│   ├── lint.yml                       # Code quality (ruff, mypy)
│   └── release.yml                    # Build & push images
│
├── ingestion/
│   ├── __init__.py
│   ├── log_parser.py                  # Parse CERT/raw logs → Event objects
│   ├── stream_simulator.py            # Replay events with timestamps
│   └── schemas.py                     # Pydantic Event, LogRecord definitions
│
├── extraction/
│   ├── __init__.py
│   ├── entity_extractor.py            # LLM call: Event → Entities + Relations
│   ├── schema.py                      # Allowed types (User, IP, Host, ThreatActor)
│   ├── prompts/
│   │   ├── extract.txt                # Few-shot extraction prompt
│   │   └── validate.txt               # Schema validation prompt
│   └── cache.py                       # Optional: cache LLM calls
│
├── graph/
│   ├── __init__.py
│   ├── graph_store.py                 # NetworkX wrapper interface
│   ├── confidence.py                  # Edge trust, decay, path multiplication
│   ├── updater.py                     # Incremental graph insert
│   └── neo4j_adapter.py               # [Optional] Swap NetworkX for Neo4j
│
├── retrieval/
│   ├── __init__.py
│   ├── router.py                      # Classify query → structural/lookup/hybrid
│   ├── graph_retriever.py             # Subgraph traversal given entity + question
│   ├── vector_retriever.py            # Semantic fallback (Chroma/FAISS)
│   └── query_parser.py                # Parse natural language queries
│
├── reasoning/
│   ├── __init__.py
│   ├── verdict_generator.py           # LLM: Subgraph + question → explanation + risk
│   ├── groundedness_checker.py        # Verify claims ↔ edges; regenerate if needed
│   ├── prompts/
│   │   ├── reason.txt                 # Reasoning prompt template
│   │   └── ground.txt                 # Groundedness validation prompt
│   └── risk_model.py                  # Risk scoring function (parametric)
│
├── action/
│   ├── __init__.py
│   ├── gate.py                        # Threshold logic: auto vs. analyst queue
│   ├── simulated_actions.py           # Mock block, force-reauth, etc.
│   ├── audit_log.py                   # Insert into PostgreSQL audit trail
│   └── action_executor.py             # Dispatch logic + retry
│
├── api/
│   ├── __init__.py
│   ├── main.py                        # FastAPI app initialization
│   ├── dependencies.py                # Shared middleware, auth, logging
│   └── routes/
│       ├── incidents.py               # GET/POST /incidents
│       ├── graph.py                   # GET /graph/subgraph, /graph/neighbors
│       ├── actions.py                 # GET/POST /actions, approval workflow
│       ├── health.py                  # GET /health, /ready
│       └── metrics.py                 # GET /metrics (Prometheus format)
│
├── dashboard/
│   ├── public/
│   │   └── index.html
│   ├── src/
│   │   ├── index.tsx
│   │   ├── App.tsx
│   │   ├── components/
│   │   │   ├── GraphView.tsx          # Cytoscape.js visualization
│   │   │   ├── IncidentQueue.tsx      # Pending actions table
│   │   │   ├── MetricsPanel.tsx       # KPIs + trends
│   │   │   └── ActionApproval.tsx     # Analyst review UI
│   │   └── services/
│   │       └── api.ts                 # Axios client to backend
│   ├── package.json
│   └── tsconfig.json
│
├── evaluation/
│   ├── __init__.py
│   ├── metrics.py                     # Retrieval accuracy, graph completeness, precision
│   ├── benchmark.py                   # Run evaluation suite
│   ├── datasets/
│   │   ├── cert_r4.2.csv              # Insider-threat ground truth
│   │   └── synthetic_scenarios.json   # Hand-built test cases
│   └── results/
│       └── latest_run.json            # Benchmark output
│
├── tests/
│   ├── conftest.py                    # Pytest fixtures
│   ├── unit/
│   │   ├── test_log_parser.py
│   │   ├── test_entity_extractor.py
│   │   ├── test_graph_store.py
│   │   ├── test_confidence.py
│   │   ├── test_router.py
│   │   └── test_verdict_generator.py
│   ├── integration/
│   │   ├── test_end_to_end.py         # Full pipeline from log to action
│   │   ├── test_graph_retrieval.py    # Subgraph queries
│   │   ├── test_vector_fallback.py    # Semantic search
│   │   └── test_api.py                # HTTP endpoints
│   └── fixtures/
│       ├── sample_logs.py             # Test data
│       └── mock_llm.py                # LLM response mocks
│
├── config/
│   ├── __init__.py
│   ├── settings.py                    # Pydantic BaseSettings + env vars
│   ├── logging.py                     # Structured logging (JSON)
│   └── constants.py                   # Model names, thresholds, entity types
│
├── utils/
│   ├── __init__.py
│   ├── decorators.py                  # Retry, cache, time-limit decorators
│   ├── validators.py                  # Input validation helpers
│   └── formatters.py                  # JSON/CSV export utilities
│
├── migrations/                        # Alembic migrations (if using PostgreSQL)
│   └── versions/
│
├── docs/
│   ├── ARCHITECTURE.md                # Detailed module interactions
│   ├── API.md                         # OpenAPI schema + examples
│   ├── DEPLOYMENT.md                  # Production runbook
│   ├── CONTRIBUTING.md                # Development guidelines
│   └── examples/
│       ├── basic_query.sh             # cURL examples
│       └── end_to_end_scenario.py     # Full walkthrough
│
└── scripts/
    ├── setup_dev.sh                   # Local environment bootstrap
    ├── run_tests.sh                   # Test suite wrapper
    ├── generate_docs.sh               # API doc generation
    └── ingest_sample_data.py          # Load CERT dataset
```

---

## 🚀 Quick Start

### Prerequisites
- **Python 3.11+** (3.12 recommended)
- **Node.js 18+** (for React dashboard)
- **Docker & Docker Compose** (optional, for containerized dev)
- **API Keys:** Anthropic or OpenAI (set in `.env`)

### Local Development Setup

#### 1. Clone & Install

```bash
git clone https://github.com/Viro-Hunter/Major_Project.git
cd Major_Project

# Copy environment template
cp .env.example .env
# Edit .env with your API keys
```

#### 2. Backend (Python)

```bash
# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install poetry
poetry install

# Run migrations (if using PostgreSQL)
alembic upgrade head

# Start FastAPI server
uvicorn api.main:app --reload --port 8000
```

#### 3. Frontend (React)

```bash
cd dashboard
npm install
npm start  # Runs on http://localhost:3000
```

#### 4. Docker Compose (All-in-One)

```bash
docker-compose up -d
# Backend: http://localhost:8000
# Frontend: http://localhost:3000
# PostgreSQL: localhost:5432
```

### First Query

```bash
# Ingest sample CERT logs
python scripts/ingest_sample_data.py --dataset cert_r4.2

# Query the system
curl -X POST http://localhost:8000/incidents/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "entity": "d.kapoor",
    "query": "What actions did this user take outside business hours?",
    "threshold": 0.7
  }'
```

---

## 🔧 Configuration

### Environment Variables

```bash
# LLM Configuration
LLM_PROVIDER=anthropic  # or openai
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
LLM_MODEL=claude-3-5-sonnet  # or gpt-4-turbo

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

## 📊 Core Modules

### 1. Ingestion (`ingestion/`)

**Responsibility:** Parse raw security logs into normalized event objects.

**Key Functions:**
- `log_parser.py::parse_cert_log()` — Convert CERT CSV rows to Event Pydantic models
- `stream_simulator.py::replay_stream()` — Emit events with real timestamps for demos

**Example:**
```python
from ingestion import log_parser, stream_simulator

events = log_parser.parse_cert_log("data/cert_r4.2.csv")
for event in stream_simulator.replay_stream(events, speed=10):
    print(f"Event: {event.user_id} @ {event.timestamp}")
```

---

### 2. Extraction (`extraction/`)

**Responsibility:** Use an LLM to extract entities and relations from events.

**Key Functions:**
- `entity_extractor.py::extract_from_event()` — Call LLM with prompt; validate schema
- `schema.py::EntityType, RelationType` — Define allowed types (User, IP, Host, ThreatActor, Exfiltration, PrivEsc, etc.)

**Example:**
```python
from extraction import entity_extractor

event = Event(user_id="d.kapoor", action="copied_file", target="C:\\data\\secrets.zip", ...)
entities, relations = entity_extractor.extract_from_event(event)
# entities: [Entity(id="d.kapoor", type="User"), Entity(id="secrets.zip", type="File"), ...]
# relations: [Relation(source="d.kapoor", target="secrets.zip", type="Exfiltration", confidence=0.92), ...]
```

---

### 3. Graph (`graph/`)

**Responsibility:** Store entities/relations, compute edge confidence, and provide query interfaces.

**Key Functions:**
- `graph_store.py::GraphStore` — Wrapper around NetworkX; `add_node()`, `add_edge()`, `get_subgraph()`
- `confidence.py::compute_edge_confidence()` — Trust score × decay × path multiplication
- `updater.py::incremental_insert()` — Apply new events without full recompute

**Example:**
```python
from graph import graph_store, confidence

gs = graph_store.GraphStore()
gs.add_node("d.kapoor", type="User", risk_baseline=0.3)
gs.add_edge("d.kapoor", "secrets.zip", relation="Exfiltration", base_confidence=0.92)

# Decay confidence after 48 hours
decayed = confidence.apply_decay(edge_conf=0.92, hours_old=48)

# Multi-hop trust: d.kapoor → secrets.zip → cloud_server
path_conf = confidence.multiply_path_confidence([0.92, 0.85])
```

---

### 4. Retrieval (`retrieval/`)

**Responsibility:** Route queries to the right retrieval strategy and fetch relevant subgraphs or semantic matches.

**Key Functions:**
- `router.py::classify_query()` — Determine if query is structural (graph), lookup (vector), or hybrid
- `graph_retriever.py::get_entity_subgraph()` — BFS/DFS from entity, return k-hop neighbors + edges
- `vector_retriever.py::semantic_search()` — Embed query, find similar events in Chroma/FAISS

**Example:**
```python
from retrieval import router, graph_retriever

query = "What data did d.kapoor exfiltrate?"
query_type = router.classify_query(query)  # "structural"

if query_type == "structural":
    subgraph = graph_retriever.get_entity_subgraph("d.kapoor", hops=3)
    # Returns: {"nodes": [...], "edges": [...]}
```

---

### 5. Reasoning (`reasoning/`)

**Responsibility:** Generate explainable risk verdicts using LLM + groundedness verification.

**Key Functions:**
- `verdict_generator.py::generate_verdict()` — LLM: subgraph + question → narrative + risk score
- `groundedness_checker.py::verify_verdict()` — Check each claim against actual edges; regenerate if unsound

**Example:**
```python
from reasoning import verdict_generator, groundedness_checker

subgraph = {...}  # From retrieval layer
verdict = verdict_generator.generate_verdict(subgraph, query="data exfiltration risk?")
# verdict: {"narrative": "User d.kapoor copied ...", "risk_score": 0.88, "confidence": 0.79}

is_sound = groundedness_checker.verify_verdict(verdict, subgraph)
# Returns True if all evidence claims map to edges; False → regenerate
```

---

### 6. Action (`action/`)

**Responsibility:** Gate decisions (auto vs. analyst), execute simulated actions, audit log all outcomes.

**Key Functions:**
- `gate.py::should_auto_execute()` — Check risk score vs. thresholds
- `simulated_actions.py::block_ip()`, `force_reauth_user()` — Fake action calls (no real API)
- `audit_log.py::log_action()` — Insert into PostgreSQL with full context

**Example:**
```python
from action import gate, simulated_actions, audit_log

verdict = {"risk_score": 0.88}
if gate.should_auto_execute(verdict.risk_score):
    simulated_actions.block_ip("192.168.1.50")
    audit_log.log_action(
        action_type="block_ip",
        verdict=verdict,
        executed_by="system",
        status="success"
    )
else:
    audit_log.log_action(
        action_type="analyst_review_pending",
        verdict=verdict,
        status="queued"
    )
```

---

### 7. API (`api/`)

**Responsibility:** Expose REST endpoints for queries, status, and analyst workflows.

**Key Endpoints:**
- `POST /incidents/analyze` — Analyze an entity; return verdict
- `GET /graph/subgraph?entity=d.kapoor&hops=3` — Retrieve subgraph
- `POST /actions/{action_id}/approve` — Analyst approves queued action
- `GET /health` — Readiness & dependency checks
- `GET /metrics` — Prometheus-format performance metrics

See `docs/API.md` for full OpenAPI spec.

---

### 8. Dashboard (`dashboard/`)

**Responsibility:** Visualize the entity graph, monitor incidents, and review queued actions.

**Features:**
- **Real-time graph rendering** (Cytoscape.js)
- **Incident queue** with sorting/filtering
- **Metrics panel** (detection rate, avg response time, false positives)
- **Action approval workflow**

Start with `npm start` in the `dashboard/` directory.

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

**Key Metrics:**
- **Retrieval Accuracy:** What % of relevant edges are returned?
- **Graph Completeness:** Do we capture all entity relationships?
- **Correlation Precision:** Are correlations sound (low false-positive rate)?
- **Risk Score Calibration:** Does the risk score align with ground truth?

---

## 📈 Performance & Scalability

### Prototype Performance (NetworkX, in-memory)
- **Graph size:** ~10k nodes, ~50k edges (CERT r4.2 + synthetic)
- **Subgraph query (3-hop):** ~50ms
- **LLM extraction:** ~2–5s per event (API latency)
- **Full pipeline (event → action):** ~10–15s

### Production Roadmap (Neo4j, PostgreSQL)
- **Scale to:** 1M+ entities, distributed deployments
- **Real-time ingestion:** Kafka → extraction → graph updates
- **Caching:** Redis for vector embeddings + query results
- **Distributed tracing:** OpenTelemetry + Jaeger for observability

---

## 🔐 Security & Compliance

### Data Protection
- **API authentication:** Bearer tokens (JWT or API keys)
- **Audit logging:** All queries, actions, and decisions logged to PostgreSQL
- **Data retention:** Configurable TTL for events and verdicts
- **Encryption:** TLS for API + DB connections (production)

### Incident Response
- **Analyst approval workflow:** High-risk actions require human review
- **Rollback capability:** All auto actions are logged and reversible
- **Compliance reports:** Export incident trails for audit/legal review

See `docs/DEPLOYMENT.md` for production hardening.

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

## 🐛 Troubleshooting

### LLM calls failing
- Check `.env` for valid API keys and model names
- Review logs: `tail -f logs/app.log | grep -i llm`

### Graph queries slow
- If using NetworkX: Check graph size (`gs.num_nodes()`, `gs.num_edges()`)
- Consider switching to Neo4j for large graphs (>100k edges)

### Analyst queue growing
- Lower `ACTION_ANALYST_THRESHOLD` in `.env` to auto-execute more
- Review risk model in `reasoning/risk_model.py`

See `docs/TROUBLESHOOTING.md` for more.

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

**Last Updated:** 2026-07-31  
**Maintained By:** Viro-Hunter Team
