# Architecture

This document describes the system as implemented in the repository (v1.0-sem7). Every file named here exists; `scripts/generate_report_assets.py` copies the summary below into the report.

<!-- SUMMARY:START -->
The proposed system is an explainable GraphRAG pipeline for insider-threat detection. Raw CERT r4.2 behavioural logs (logon, removable-device, file, email and web activity) are normalised into timestamped events and converted into a knowledge graph in which each event becomes a short story chain: a User is observed on a Host and touches a File, Device, Email or URL, and any behaviour matching a MITRE ATT&CK technique adds an edge to that technique together with an INDICATES edge from the specific event node, so every technique match is traceable to the event that caused it. For an analyst's question about an entity, a rule-based router chooses the retrieval depth and a bounded, confidence-pruned breadth-first retriever extracts the relevant subgraph. A large language model (local via Ollama, or any OpenRouter, Anthropic, OpenAI, Groq or Gemini model selected from the dashboard) reasons over that subgraph and must return a verdict that cites the exact edge identifiers supporting it. The core contribution is the groundedness self-check that follows: every cited edge is verified against the retrieved subgraph, ungrounded verdicts are regenerated up to twice with the permitted edge list, and verdicts that remain ungrounded have their risk reduced by 20% and are marked [unverified] rather than shown with false confidence. Finally, confidence is propagated along the verified evidence paths only, multiplying edge confidences and decaying older evidence by 0.95 per day, and behavioural risk combines the distinct techniques with a noisy-OR weighted by severity, path confidence and peer prevalence, so behaviour that most employees exhibit carries little weight. Results are presented in a React dashboard with an incident queue, interactive graph, timeline, evidence trail and evaluation metrics.
<!-- SUMMARY:END -->

## Pipeline

```mermaid
flowchart LR
  A[CERT r4.2 CSVs] --> B[Ingestion<br/>ingestion/log_parser.py<br/>ingestion/cert_loader.py]
  B --> C[Extraction<br/>scripts/build_graph_from_cert.py::ingest_row<br/>extraction/entity_extractor.py LLM]
  C --> D[Knowledge graph<br/>graph/graph_store.py<br/>+ ATT&CK lookup]
  D --> E[Router + retriever<br/>retrieval/router.py<br/>retrieval/graph_retriever.py]
  E --> F[Verdict<br/>reasoning/verdict_generator.py]
  F --> G[Groundedness check<br/>reasoning/groundedness_checker.py]
  G --> H[Confidence<br/>reasoning/confidence_scoring.py<br/>graph/confidence.py]
  H --> I[API + dashboard<br/>api/ · dashboard/]
```

| Stage | Module | What it does |
|---|---|---|
| Ingestion | `ingestion/log_parser.py`, `ingestion/cert_loader.py` | Normalises each CERT row into an `Event`; loads per-user rows from `data/raw` or the committed `data/demo` subset |
| Extraction | `scripts/build_graph_from_cert.py` (`ingest_row`, `build_graph_from_rows`) | Deterministic CERT extraction into story chains; `extraction/entity_extractor.py` is the LLM extractor for unstructured logs |
| Graph | `graph/graph_store.py`, `graph/schema.py`, `data/attack_technique_lookup.json` | NetworkX `MultiDiGraph`; 8 behaviour patterns mapped to ATT&CK technique ids with severity |
| Routing | `retrieval/router.py` | Rule-based `structural` / `lookup` / `hybrid` classifier behind a swappable `QueryClassifier` interface (Sem 8: learned classifier) |
| Retrieval | `retrieval/graph_retriever.py` | Bounded BFS over edges above a confidence threshold; ranks paths by keyword relevance, hops and propagated confidence |
| Reasoning | `reasoning/verdict_generator.py`, `reasoning/evidence.py` | LLM verdict with `cited_edges`; ATT&CK evidence edges are placed first in the prompt; deterministic evidence template when no model answers |
| Groundedness | `reasoning/groundedness_checker.py` | Verify citations → regenerate ≤ 2× → downgrade 20% + `[unverified]` (see `docs/groundedness_design.md`) |
| Confidence | `graph/confidence.py`, `reasoning/confidence_scoring.py` | Π cᵢ·0.95^ageᵢ over verified paths only; verdict label benign / suspicious (≥ 0.4) / high_risk (≥ 0.7) |
| Action gate | `action/gate.py`, `action/audit_log.py` | Auto / analyst / ignore decision and audit trail |
| LLM access | `llm/client.py`, `llm/providers.py`, `llm/runtime.py` | Provider-agnostic client; key auto-detection, credit check, paid-vs-free model recommendation |
| API | `api/routes/*.py` | `/incidents/analyze`, `/incidents/query`, `/incidents/queue`, `/graph/*`, `/llm/*`, `/metrics/benchmark` |
| Dashboard | `dashboard/src/components/*.jsx` | Model panel, incident queue, entity graph, timeline, verdict with evidence trail, metrics panel |
| Evaluation | `evaluation/metrics.py`, `evaluation/run_benchmark.py`, `evaluation/scenarios.py` | Five Objective-5 metrics, ablation, naive baseline, groundedness fault injection |

## Key design decisions

**Edge ids.** Edges in a retrieved subgraph get positional ids `e<index>` in the graph's insertion order (`reasoning.groundedness_checker.indexed_edge_ids`). Generator, checker, confidence stage and dashboard all use the same function, so a citation means the same edge everywhere.

**Decay reference time.** CERT timestamps are from 2010, so decay is measured from an `as_of` time (the focus entity's newest event) rather than the wall clock, which would multiply every edge by ≈ 0.

**Peer prevalence.** A technique's contribution is multiplied by (1 − fraction of users exhibiting it). In CERT nearly every user emails attachments externally (T1567) while few log in after hours (T1078); without this discount the false-positive rate rises from 8% to 58% (see `evaluation/results/benchmark_report.md`, Table 2).

**Confidence after groundedness.** Only paths whose every edge was verified contribute confidence, so an `[unverified]` verdict reports near-zero confidence even if its narrative sounds certain.

**Keys.** A key pasted in the dashboard is kept in API-process memory only (`llm/runtime.py`), never logged or returned in full, and overrides `.env` until the server restarts.
