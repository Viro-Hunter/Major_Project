# Progress — Cyber Intelligence GraphRAGs for Behavioral Detection (Till Week 6)

**Domain:** Cybersecurity · AI/LLMs | **Category:** Research/Application-based Software
**Objectives Sem 7:** Data ingestion + KG construction (STIX 2.1/ATT&CK) → GraphRAG retrieval/reasoning → groundedness verification
**Objectives Sem 8:** Dashboard + adaptive routing/confidence propagation + evaluation

## Week-by-Week — What’s Actually Done (Visible in Repo)

### Week 1 — Scope + Scaffold ✅
- Finalized scope with guide, locked architecture: `CERT logs → ingestion → extraction → graph (NetworkX) → retrieval → LLM reasoning → groundedness → dashboard` with ATT&CK as intelligence layer.
- Created GitHub repo with folder structure `ingestion, extraction, graph, retrieval, reasoning, evaluation, dashboard, data, llm` (see `README.md:1`, `docs/ARCHITECTURE.md`).
- **Who:** Tabrez architecture + scaffold, Faizan React skeleton, Bilal CERT r4.2 download + docs.

### Week 2 — Lit Survey ✅
- Surveyed 7 papers (GraphRAG, CyKG-RAG, Actionable CTI, Audit-LLM, SHIELD, D3FEND, Beyond RAG), built comparison table; studied MITRE ATT&CK/STIX 2.1/TAXII, CERT schema.
- **Artifacts:** `docs/cert_dataset_notes.md`, `data/attack_technique_lookup.json` (5+ ATT&CK mappings).

### Week 3 — Schema + Gap ✅
- Locked problem statement/gap (static retrieval, binary paths, no groundedness).
- Designed KG schema `graph/schema.py`: entities `User, Host, Device, FileResource, EmailEvent, NetworkConnection, AttackTechnique` and relations `LOGGED_IN_FROM, ACCESSED, CONNECTED_DEVICE, SENT_EMAIL_TO, MATCHES_TECHNIQUE` + confidence/timestamp.
- **Tests:** `tests/test_log_parser.py` enforces schema contracts.

### Week 4 — Ingestion + Extraction (v1) ✅
- Pipeline: `ingestion/log_parser.py` normalizes CERT rows (`parse_logon_row`, `parse_device_row`, `parse_file_row`, `parse_email_row`, `parse_http_row`) → uniform `Event(user, timestamp, event_type, raw_fields, event_id)` plus advanced `parse_cert_log` for pandas CERT r4.2.
- `extraction/entity_extractor.py` (hybrid) + `extraction/prompts/extract.txt` + `llm/client.py` (provider-agnostic: `LLM_PROVIDER=openai` with `OPENAI_API_BASE=http://localhost:11434/v1` for Ollama `llama3.1:8b` default, fallback to Anthropic). Confidence contract 0.9 direct / 0.6 inferred.
- **Tests:** `tests/test_log_parser.py`, `tests/test_entity_extractor.py`, `tests/test_data_loading.py` (demo CSVs under `data/demo/`).

### Week 5 — Knowledge Graph (NetworkX) ✅
- `graph/graph_store.py` (MultiDiGraph, `add_entity/add_relation`, `get_subgraph`, `to_json` STIX-compatible) + advanced helpers `add_node/add_edge`, singleton `store`. `graph/updater.py`, `graph/confidence.py` (decay, path multiplication).
- Verified nodes/edges = real user-behavior relationships; behaviors → ATT&CK IDs via `data/attack_technique_lookup.json`.
- `dashboard/src/components/EntityGraph.jsx` (vis-network) renders the graph.
- **Tests:** `tests/test_graph_store.py`.

### Week 6 — GraphRAG Retrieval Layer (Current Milestone) ✅
- `retrieval/graph_retriever.py`: `retrieve_subgraph(entity_id, question, graph_store, max_hops, confidence_threshold)` — confidence-pruned BFS, path-ranked by keyword match, returns `subgraph + paths`.
- `retrieval/router.py`: `classify_query(question) -> structural | lookup | hybrid` (`RuleBasedQueryClassifier` with `STRUCTURAL_KEYWORDS=why/linked to/path/connected`). Wired as stub for adaptive routing (Sem 8 will add vector/hybrid + confidence propagation).
- `api/routes/graph.py`: `GET /graph/subgraph?entity=&hops=` (advanced) + `GET /graph/subgraph/{entity_id}` (vis-network) + `GET /graph/stats`; `api/routes/incidents.py`: `POST /incidents/query` (structural/lookup) + `POST /incidents/analyze` (advanced) + `POST /incidents/ingest`.
- `dashboard/src/components/DashboardPage.jsx` **connected**: `EntityGraph` live + health/analyze panels (`subgraph` tables, verdict, groundedness, risk). Retrieval visibly demoable: `curl http://localhost:8000/graph/stats`, `POST /incidents/query {"entity_id":"AAM0658","question":"Why is user linked to host?"}`.
- **Tests:** `tests/test_graph_retriever.py`, `tests/test_router.py`, `tests/test_health.py` (70 tests green).

## How to Demo Week 6 (clone-and-run, Ollama default)

```bash
git clone https://github.com/Viro-Hunter/Major_Project.git && cd Major_Project
cp .env.example .env   # already Ollama: LLM_PROVIDER=openai, OPENAI_MODEL=llama3.1:8b
./scripts/setup.sh     # pulls llama3.1:8b, .venv, npm build (WSL-safe)
./scripts/run.sh       # API :8000, dashboard :5173
# OR docker compose up --build -d && docker exec cybergraphrag-ollama ollama pull llama3.1:8b
pytest -q              # 70 passed
curl http://localhost:8000/graph/subgraph/AAM0658?hops=2
curl -X POST http://localhost:8000/incidents/query -H "Content-Type: application/json" -d '{"entity_id":"AAM0658","question":"Why is user linked to host?"}'
```

Dashboard at `http://localhost:5173` shows vis-network graph + retrieval paths + subgraphs — this is the visible Week 6 deliverable.

## Next (Week 7-12, Sem 8)

- Week 7: `reasoning/verdict_generator.py` + `groundedness_checker.py` (already scaffolded, to be wired end-to-end)
- Week 8: groundedness self-check novelty
- Week 9-10: confidence propagation + `evaluation/metrics.py` (retrieval accuracy, graph completeness, threat-correlation precision, response time, F1)
- Sem 8: interactive dashboard analytics + adaptive routing + `Modelfile.finetuned` (QLoRA) for `llama3.1:8b`
