# Changelog

All notable changes to this project are documented in this file.

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
