# Architecture — Graph + LLM Integration

This document highlights the recent design decisions and implementation details for the provider-agnostic LLM client and the graph schema / ATT&CK technique mapping added in recent work.

## Provider-agnostic LLM client (llm/)

Goal: let extraction and reasoning logic invoke a single interface regardless of LLM provider (Anthropic, OpenAI, or a mock for tests).

Key points:

- Implementation lives under the `llm/` package. The code exposes a small interface used by `extraction/entity_extractor.py` and `reasoning/verdict_generator.py`:
  - `LLMClient` (interface / base class) — send(prompt, **options) -> LLMResponse
  - `AnthropicLLMClient` — concrete adapter for Anthropic API
  - `OpenAILLMClient` — concrete adapter for OpenAI API
  - `MockLLMClient` — deterministic/local responses used by tests and CI (`tests/fixtures/mock_llm.py`)

- Configuration is driven by the environment variables documented in `.env.example` and `README.md`: `LLM_PROVIDER`, `LLM_MODEL`, and provider API keys.

- Prompts are stored as templates under `extraction/prompts/` and `reasoning/prompts/`. The extraction layer performs a lightweight schema validation step after receiving an LLM response to avoid invalid entities/relations entering the graph.

- The client implements:
  - request/response logging (redacts secrets)
  - retry/backoff for transient HTTP errors
  - optional caching (configurable) to reduce API usage for repeated or deterministic prompts

## Extraction pipeline (extraction/)

- `extraction/entity_extractor.py` calls the LLM client through the common interface. The extractor:
  1. Formats the prompt (uses `extraction/prompts/extract.txt`) with the event payload
  2. Sends the prompt via the `LLMClient` implementation
  3. Validates and normalizes the returned entities/relations against `extraction/schema.py`
  4. Writes normalized entities/relations to the graph via `graph/updater.py`

- Tests use `tests/fixtures/mock_llm.py` so extraction logic can be validated offline and in CI without external API keys.

## Graph schema & ATT&CK technique lookup (graph/)

- A lightweight, explicit schema was added to make relation typing and technique mapping explicit. The system now supports mapping observed behaviors and relation types to ATT&CK techniques for richer context and analyst-facing explanations.

- Graph interactions are primarily performed through `graph/graph_store.py` and the incremental updater in `graph/updater.py`. Confidence, decay, and path-multiplication logic live in `graph/confidence.py`.

- ATT&CK support is implemented as a lookup/mapping step that enriches relations with:
  - technique_id (e.g., T1005)
  - technique_name (e.g., "Data from Local System")
  - mapping_confidence

  The mapping source is a local mapping table (included in the repo under `data/` or referenced via `docs/`; see the git history for the exact file added with the dataset commit).

## Groundedness & Verdict Generation (reasoning/)

- `reasoning/verdict_generator.py` now leverages the provider-agnostic LLM client to produce narratives from subgraphs. The groundedness checker (`reasoning/groundedness_checker.py`) cross-validates any claim in the narrative against graph edges before a verdict is returned or recorded.

- If groundedness fails, the generator will retry with stricter prompts asking the LLM to cite edges or to abstain.

## Testing & CI notes

- A trimmed demo subset of the CERT r4.2 dataset was added under `data/` to make CI and offline demos feasible (see recent commit history). Unit and integration tests were extended to use this dataset and a mock LLM client to avoid external API dependency during CI.

- To run the full pipeline locally (with real LLMs), ensure `LLM_PROVIDER` and API keys are set in your `.env` and follow the README quick-start section.

## Where to look in the code

- LLM client: `llm/` (interface + providers)
- Extraction: `extraction/entity_extractor.py`, `extraction/schema.py`, and `extraction/prompts/`
- Graph: `graph/graph_store.py`, `graph/updater.py`, `graph/confidence.py`
- Reasoning: `reasoning/verdict_generator.py`, `reasoning/groundedness_checker.py`
- Tests: `tests/fixtures/mock_llm.py`, `tests/unit/`, `tests/integration/`

---

If you'd like, I can expand this file to include sequence diagrams, example payloads, or code snippets showing the LLM client interface (LLMClient.send signature and expected LLMResponse shape).