# Changelog

All notable changes to this project are documented in this file.

## [1.2.0-sem7] - 2026-10-21

### Changed
- Dashboard redesigned for operators and non-specialists: plain language by default, "Technical details" switch for raw IDs/edges/ATT&CK codes/formal metrics.
- People-to-review list (search, sort, "only needs review"), case file with verdict, risk and certainty meters, plain summary and recommendation.
- "Why we think so" table: each behaviour with when, how often, share of colleagues who do the same, and ✓ found-in-logs after the AI check.
- Evaluation shown as outcomes (insiders caught, false alarms, invented claims caught, answer time).

### Fixed
- Graph showed strangers' highest-confidence edges instead of the investigated person; it now shows the person's evidence chain (person → what they used → behaviour), with "Everything they used" as an alternative view.
- Graph stretching and drifting (hierarchical layout + physics toggle): positions are now computed and fixed; edge labels moved to hover tooltips; overlapping labels removed.
- Edge counts in the graph header did not add up (counted before vs after grouping).
- Tables overflowed their cards and the page; all tables now scroll inside their card, verified at 1366×768, 1920×1080 and 390×844.
- Dashboard opened on a placeholder user with no activity; it now opens the highest-risk person.

## [1.1.0-sem7] - 2026-10-21

### Added
- Native STIX 2.1 export (`intel/stix_export.py`, `GET /incidents/{entity}/stix`) embedding MITRE's official ATT&CK attack-pattern objects; validated with the OASIS stix2-validator.
- Hybrid LLM extraction (`extraction/llm_enrichment.py`) with extraction-time grounding and a 0.6 confidence cap; `--extractor hybrid` / `--llm-extract`.
- `evaluation/compare_models.py`: template vs real LLM (vs LLM + LLM extraction) on the same labelled set, including live groundedness statistics.
- Story mode (`#story`): 12-scene presenter walkthrough for non-technical audiences, generated from a real run by `scripts/build_story.py`.

### Fixed
- The extraction prompt's relation vocabulary did not match the parser's schema, so most relations a real LLM returned would have been dropped.

## [1.0.0-sem7] - 2026-10-20

### Added
- Week 9: confidence propagation (`graph/confidence.py`) — product of edge confidences with 0.95/day decay measured from the entity's newest event; evidence paths and peer-baselined behavioural risk (`reasoning/evidence.py`); confidence stage after the groundedness check that counts verified paths only (`reasoning/confidence_scoring.py`); `/incidents/queue` triage endpoint; `scripts/run_pipeline_e2e.py`.
- Week 10: `evaluation/metrics.py` (retrieval accuracy, graph completeness, threat-correlation precision, response time, detection effectiveness), `evaluation/run_benchmark.py` with ablation, naive baseline, threshold sweep and groundedness fault injection; labelled sets from the official answer key or seeded scenarios (`evaluation/scenarios.py`).
- Week 11: `scripts/generate_report_assets.py` (figures, captioned tables, architecture paragraph).
- Week 12: `scripts/demo.py` live walkthrough.
- Model connection: OpenRouter, Anthropic, OpenAI, Groq, Gemini and xAI key auto-detection, credential and credit check, paid-vs-free model recommendation (`llm/providers.py`, `api/routes/llm.py`); dashboard Reasoning model panel, Incident queue, Metrics panel, verdict confidence and evidence trail.

### Fixed
- Edge attribute `source=<log name>` overwrote the real edge source in subgraph dicts, so freshly built graphs attributed every edge to "logon"/"email"/...
- Risk score was near-constant on CERT graphs (legacy weights only covered relation names absent from CERT).
- Retrieval copied the whole graph per query: per-query latency 852 ms → 16 ms with identical results.
- Email, web and logon technique matches had no INDICATES edge from the triggering event.

### Changed
- `docs/ARCHITECTURE.md` rewritten to describe the implemented system.
- `/incidents/query` now also returns the checked verdict (Week 7 spec).

## [Unreleased]

### Added
- Groundedness verification layer for LLM-generated verdicts to ensure every cited edge exists in the retrieved subgraph.
- Retry-based regeneration for ungrounded verdicts, with explicit allowed-edge constraints and downgrade-to-analyst-review behavior for remaining invalid findings.
- Timeline API for incident storytelling and a dashboard timeline view for step-by-step investigation.
- Richer story graph relationships for file, device, email, and network activity tied to attack techniques.
- Hierarchical graph layout and grouped parallel-edge visualization for more readable threat narratives.
- MIT License.

### Changed
- Verdict generation pipeline now emits explicit `cited_edges` and tracks groundedness metadata for auditability.
- Incident analysis flow now validates verdicts before action gating and logs groundedness outcomes.
- Graph-building workflow expanded from user/host/technique relationships to full story chains for analyst readability.

### Fixed
- Prevented hallucinated evidence edges from being treated as trusted output.
- Reduced false-confidence risk by downgrading unverified findings and labeling them as `[unverified]`.
- Improved readability of high-density graphs and temporal incident stories.

---

## [0.3.0] - 2026-09-30

### Added
- Groundedness checking and regeneration framework for verdict validity.
- `groundedness` metadata structure with `status`, `retries_used`, `missing_edges`, and `verified_edges`.
- Improved prompt/verification flow for edge-grounded reasoning under constrained generation.
- Tests covering groundedness checks, regeneration logic, retry behavior, and edge ID conventions.

### Changed
- Refactored verdict generation to support `extra_instruction` and explicit edge citations.
- Updated API incident analysis to route verdicts through the groundedness gate before action decisions.
- Added docs describing the groundedness design and evaluation rationale.

### Fixed
- Eliminated non-existent edge citations from being surfaced as confident findings.
- Preserved compatibility with legacy `grounded` flags while enforcing stricter validation.

---

## [0.2.0] - 2026-08-13

### Added
- Provider-agnostic LLM client supporting multiple model backends.
- Entity and relation extraction pipeline with ATT&CK enrichment.
- Graph schema modeling to support richer threat context and technique mapping.
- Trimmed CERT r4.2 demo dataset for offline testing and CI-friendly execution.
- Expanded ingestion and parsing tests for CERT data loading.

### Changed
- README updated to document the demo dataset and tooling flow.

---

## [0.1.0] - 2026-07-31

### Added
- Initial MVP of the insider threat detection platform.
- Data ingestion and log parsing for security event feeds.
- Graph construction and retrieval pipeline for user and host activity analysis.
- LLM-assisted reasoning and risk scoring.
- Action gating and audit logging for incident handling.
- REST API and React dashboard for investigation workflows.

---

## Notes
- This changelog intentionally excludes formatting-only edits, typo fixes, and superficial text corrections.
- Major architecture, product, and reasoning changes are included; minor polish changes are intentionally omitted.
