"""Week 4 — extraction/entity_extractor.py (hybrid)

Keeps remote LLM extraction (extract) plus advanced simple extraction (extract_from_event).
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, List, Tuple

from graph.schema import (
    ENTITY_CLASSES,
    EntityType as RemoteEntityType,
    Relation,
    RelationType as RemoteRelationType,
)
from ingestion.log_parser import Event

# Advanced pipeline imports (fallback if not available)
try:
    from extraction.schema import Entity, EntityType as AdvancedEntityType, Relation as AdvancedRelation, RelationType as AdvancedRelationType
    from ingestion.schemas import Event as AdvancedEvent
except ImportError:
    Entity = None

PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "extract.txt"


class ExtractionError(RuntimeError):
    """Raised when the LLM response cannot be parsed after retry."""


def _load_prompt_template() -> str:
    return PROMPT_PATH.read_text(encoding="utf-8")


def _load_technique_lookup_summary(path: Path | None = None) -> str:
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
        out.append(f"Event {i}: type={e.event_type.value} user={e.user} timestamp={e.timestamp} host={e.host} raw_fields={repr(e.raw_fields)}")
    return "\n".join(out)


def _parse_response_json(text: str) -> dict[str, Any]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
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
            continue
        cls = ENTITY_CLASSES[etype]
        entities.append(cls(**raw))
    return entities


def _hydrate_relations(raw_relations: list[dict[str, Any]]) -> list[Relation]:
    relations = []
    for raw in raw_relations:
        rtype = raw.get("type")
        if rtype not in {rt.value for rt in RemoteRelationType}:
            continue
        relations.append(Relation(**raw))
    return relations


def extract(
    client: Any,
    events: list[Event],
    technique_lookup_path: Path | None = None,
    max_retries: int = 1,
) -> tuple[list, list[Relation]]:
    if not events:
        return [], []
    template = _load_prompt_template()
    lookup_text = _load_technique_lookup_summary(technique_lookup_path)
    window_text = _format_event_window(events)
    user_prompt = template.format(technique_lookup=lookup_text, event_window=window_text)
    system_prompt = "Extract graph entities and relations from security log evidence. Respond with JSON only."
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


# ---------------------------------------------------------------------------
# Advanced pipeline helper — simple rule-based extraction for dashboard
# ---------------------------------------------------------------------------

def _rule_extract(event: Any) -> Tuple[List[Any], List[Any]]:
    if Entity is None:
        return [], []
    entities: List[Any] = []
    relations: List[Any] = []
    # handle both AdvancedEvent and remote Event
    user = getattr(event, "user_id", None) or getattr(event, "user", "unknown")
    host = getattr(event, "host", None) or getattr(event, "raw_fields", {}).get("pc") if hasattr(event, "raw_fields") else None
    # if remote Event, host via property
    if hasattr(event, "host") and isinstance(getattr(event, "host"), str):
        host = event.host
    target = getattr(event, "target", None)
    src_ip = getattr(event, "src_ip", None)
    action = getattr(event, "action", None) or getattr(event, "activity", "") or str(getattr(event, "raw_fields", {}).get("activity", ""))

    entities.append(Entity(id=user, type=AdvancedEntityType.User, risk_baseline=0.1))
    if host:
        entities.append(Entity(id=host, type=AdvancedEntityType.Host))
        relations.append(AdvancedRelation(source=user, target=host, type=AdvancedRelationType.UsedHost, confidence=0.85, evidence=action))
    if src_ip:
        entities.append(Entity(id=src_ip, type=AdvancedEntityType.IP))
        relations.append(AdvancedRelation(source=user, target=src_ip, type=AdvancedRelationType.ConnectedTo, confidence=0.75))
    if target:
        t = target
        if re.search(r"\.(zip|pdf|docx|xlsx|csv|txt)$", t, re.I) or "\\" in t or "/" in t:
            entities.append(Entity(id=t, type=AdvancedEntityType.File))
            if any(k in action.lower() for k in ["copy", "download", "upload", "exfil", "send", "attach"]):
                relations.append(AdvancedRelation(source=user, target=t, type=AdvancedRelationType.Exfiltration, confidence=0.92, evidence=action))
            else:
                relations.append(AdvancedRelation(source=user, target=t, type=AdvancedRelationType.Accessed, confidence=0.8, evidence=action))
        elif re.match(r"^\d+\.\d+\.\d+\.\d+$", t):
            entities.append(Entity(id=t, type=AdvancedEntityType.IP))
            relations.append(AdvancedRelation(source=user, target=t, type=AdvancedRelationType.ConnectedTo, confidence=0.8))
        else:
            entities.append(Entity(id=t, type=AdvancedEntityType.Resource))
            relations.append(AdvancedRelation(source=user, target=t, type=AdvancedRelationType.Accessed, confidence=0.7))
    act = action.lower()
    if "logon" in act or "login" in act:
        relations.append(AdvancedRelation(source=user, target=host or "system", type=AdvancedRelationType.LoggedIn, confidence=0.9))
    if "fail" in act or "denied" in act:
        relations.append(AdvancedRelation(source=user, target=host or "system", type=AdvancedRelationType.FailedLogin, confidence=0.95))
    if "priv" in act or "escalat" in act or "admin" in act:
        relations.append(AdvancedRelation(source=user, target=host or "system", type=AdvancedRelationType.PrivEsc, confidence=0.88))
    return entities, relations


def extract_from_event(event: Any) -> Tuple[List[Any], List[Any]]:
    api_key = os.getenv("LLM_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
    if not api_key or api_key.startswith("dummy") or api_key == "your_anthropic_api_key_here":
        return _rule_extract(event)
    try:
        import anthropic

        client = anthropic.Anthropic(api_key=api_key)
        prompt = f"Extract entities and relations from security event: user={getattr(event,'user_id', getattr(event,'user','unknown'))} action={getattr(event,'action', '')} target={getattr(event,'target','')} host={getattr(event,'host','')} src_ip={getattr(event,'src_ip','')}. Return JSON with entities [id,type] and relations [source,target,type,confidence]."
        resp = client.messages.create(model=os.getenv("LLM_MODEL", "claude-3-5-sonnet-20240620"), max_tokens=500, messages=[{"role": "user", "content": prompt}])
        text = resp.content[0].text if resp.content else ""
        if "User" in text:
            return _rule_extract(event)
        return _rule_extract(event)
    except Exception:
        return _rule_extract(event)
