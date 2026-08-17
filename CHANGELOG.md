# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]
- Docs: Add architecture notes for provider-agnostic LLM client and ATT&CK technique enrichment (2026-08-17)

## [0.2.0] - 2026-08-13
### Added
- Provider-agnostic LLM client and entity/relation extraction pipeline — extraction now supports both Anthropic and OpenAI via a common interface.
- Graph schema models and ATT&CK technique lookup support to enrich relations and improve analyst explanations.
- Trimmed (~159MB) demo subset of the CERT r4.2 dataset for offline demos and CI-friendly testing.
- Data-loading tests for CERT r4.2 CSV files and expanded unit/integration tests for ingestion and parsing.

### Changed
- README: Updated with recent changes and guidance on the demo dataset.

### Notes
- For CI using the demo dataset, ensure ingestion points to the files under `data/` added in the 2026-08-13 commit.

## [0.1.0] - 2026-07-31
### Added
- Initial MVP: ingestion, extraction (LLM), graph construction, retrieval, reasoning, action gating, REST API, and React dashboard.

---

*This changelog follows a lightweight Keep a Changelog style. For release tagging and discussion, consider creating GitHub Releases from the 0.2.0 commit.*
