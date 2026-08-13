"""Week 4 — extraction/entity_extractor.py

Given a normalized Event plus a short window of related events for the same
user, calls the LLM to extract entities/relations conforming to
``graph/schema.py``. Parses the JSON response, retries once on malformed JSON,
and returns ``(entities, relations)`` lists with the confidence contract:

    0.9  -- direct log evidence
    0.6  -- LLM-inferred implicit relations

The prompt template lives in extraction/prompts/extract.txt with three
placeholders: {technique_lookup}, {event_window}.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from graph.schema import (
    ENTITY_CLASSES,
    EntityType,
    Relation,
    RelationType,
)
from ingestion.log_parser import Event

PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "extract.txt"


class ExtractionError(RuntimeError):
    """Raised when the LLM response cannot be parsed after retry."""


def _load_prompt_template() -> str:
    return PROMPT_PATH.read_text(encoding="utf-8")


def _load_technique_lookup_summary(path: Path | None = None) -> str:
    """Condensed list of pattern -> technique id pairs for the prompt."""
    path = path or Path(__file__).resolve().parent.parent / "data" / "attack_technique_lookup.json"
    if not path.exists():
        return "(lookup unavailable)"
    with path.open() as fh:
        data = json.load(fh)
    lines = []
    for p in data.get("patterns", []):
        lines.append(f"- {p['pattern']} -> {p['technique_id']} ({p['technique']}, {p['tactic']})")
    return "\n".join(lines) or "(no patterns)"


def _format_event_window(events: list[Event]) -> str:
    out = []
    for i, e in enumerate(events, 1):
        out.append(f"Event {i}: type={e.event_type.value} user={e.user} "
                   f"timestamp={e.timestamp} host={e.host} "
                   f"raw_fields={repr(e.raw_fields)}")
    return "\n".join(out)


def _parse_response_json(text: str) -> dict[str, Any]:
    """Parse the LLM response, retrying once after stripping markdown fences."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # retry once: strip ``` fences and try again (common LLM output quirk)
        cleaned = text.strip()
        if cleaned.startswith("```"):
            lines = cleaned.splitlines()
            lines = [l for l in lines if not l.strip().startswith("```")]
            cleaned = "\n".join(lines)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as exc:
            raise ExtractionError(f"malformed LLM JSON after retry: {exc}") from exc


def _hydrate_entities(raw_entities: list[dict[str, Any]]) -> list:
    entities = []
    for raw in raw_entities:
        etype = raw.get("type")
        if etype not in ENTITY_CLASSES:
            continue  # skip unknown entity types rather than crash
        cls = ENTITY_CLASSES[etype]
        entities.append(cls(**raw))
    return entities


def _hydrate_relations(raw_relations: list[dict[str, Any]]) -> list[Relation]:
    relations = []
    for raw in raw_relations:
        rtype = raw.get("type")
        if rtype not in {rt.value for rt in RelationType}:
            continue
        relations.append(Relation(**raw))
    return relations


def extract(
    client: Any,
    events: list[Event],
    technique_lookup_path: Path | None = None,
    max_retries: int = 1,
) -> tuple[list, list[Relation]]:
    """Run extraction on an event window.

    Args:
        client: an LLMClient with a ``call(system_prompt, user_prompt)`` method
                (or any duck-typed mock in tests).
        events: one normalized Event plus related events for the same user.
        technique_lookup_path: optional override for the ATT&CK lookup file.
        max_retries: number of retry attempts after the first malformed response.

    Returns:
        (entities, relations) conforming to graph/schema.py.
    """
    if not events:
        return [], []

    template = _load_prompt_template()
    lookup_text = _load_technique_lookup_summary(technique_lookup_path)
    window_text = _format_event_window(events)

    user_prompt = template.format(technique_lookup=lookup_text, event_window=window_text)
    system_prompt = (
        "Extract graph entities and relations from security log evidence. "
        "Respond with JSON only."
    )

    attempts = 0
    last_error = None
    while attempts <= max_retries:
        response = client.call(system_prompt, user_prompt)
        try:
            data = _parse_response_json(response.content)
        except ExtractionError as exc:
            last_error = exc
            attempts += 1
            continue
        return (
            _hydrate_entities(data.get("entities", [])),
            _hydrate_relations(data.get("relations", [])),
        )
    raise ExtractionError(f"extraction failed after retries: {last_error}")
