"""Hybrid extraction: rules for structured CERT fields, LLM for implicit relations (SoP Methodology Step 2).

``scripts/build_graph_from_cert.ingest_row`` turns every structured column into graph
facts exactly and for free.  What rules cannot see is *implicit* behaviour spread over
several events (e.g. "copied files right after plugging in a USB stick, late at night").
``enrich_with_llm`` sends windows of each user's chronological events to the LLM with
``extraction/prompts/extract.txt`` and adds the relations it proposes, with two guards:

1. **Extraction-time grounding** — an entity is accepted only if its identifier occurs
   in the raw text of the window the LLM was shown (user, PC, filename, URL, email id)
   or is a technique from the ATT&CK lookup.  Invented entities are rejected and counted.
2. **Confidence cap** — LLM-inferred edges are stored with confidence <= 0.6
   (``LLM_CONFIDENCE_CAP``) and ``extractor="llm"``, versus 0.65-0.9 for rule edges,
   so they rank below direct evidence and still pass through the groundedness check.

The prompt's relation vocabulary (LOGGED_IN_FROM, ACCESSED, CONNECTED_DEVICE,
SENT_EMAIL_TO, MATCHES_TECHNIQUE) is parsed directly here.
"""
from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

from extraction.entity_extractor import (
    ExtractionError,
    _format_event_window,
    _load_prompt_template,
    _load_technique_lookup_summary,
    _parse_response_json,
)
from graph.graph_store import GraphStore
from graph.confidence import parse_timestamp
from ingestion.log_parser import LogType, parse_row

log = logging.getLogger(__name__)
LLM_CONFIDENCE_CAP = 0.6
ALLOWED_RELATIONS = {"LOGGED_IN_FROM", "ACCESSED", "CONNECTED_DEVICE", "SENT_EMAIL_TO", "MATCHES_TECHNIQUE"}
TYPE_PREFIX = {"Host": "host:", "FileResource": "file:", "Device": "device:", "EmailEvent": "email:",
               "NetworkConnection": "net:", "AttackTechnique": "attack:"}


@dataclass
class EnrichmentStats:
    windows: int = 0
    llm_failures: int = 0
    relations_added: int = 0
    relations_rejected: int = 0
    entities_rejected: int = 0
    rejected_examples: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in ("windows", "llm_failures", "relations_added", "relations_rejected",
                                              "entities_rejected", "rejected_examples")}


def _windows(rows_by_log: dict[str, list[dict]], users: Iterable[str], size: int, per_user: int):
    events_by_user: dict[str, list] = defaultdict(list)
    wanted = set(users)
    for name, rows in rows_by_log.items():
        for row in rows:
            if row.get("user") in wanted:
                try:
                    events_by_user[row["user"]].append((parse_row(LogType(name), row), name, row))
                except Exception:
                    continue
    for user in sorted(events_by_user):
        evs = sorted(events_by_user[user], key=lambda e: e[0].timestamp)
        chunks = [evs[i:i + size] for i in range(0, len(evs), size)]
        # prefer the windows touching the most log types (most cross-event context)
        chunks.sort(key=lambda c: (-len({n for _, n, _ in c}), c[0][0].timestamp))
        for chunk in chunks[:per_user]:
            yield user, chunk


def _resolve(raw_id: str, raw_type: str, window_text: str, known_techniques: set[str], store: GraphStore) -> Optional[str]:
    """Map an LLM entity id to a graph node id, or None if it is not grounded in the window."""
    rid = str(raw_id or "").strip()
    if not rid:
        return None
    if raw_type == "AttackTechnique" or rid.upper().startswith(("T1", "ATTACK:T1")):
        tid = rid.split(":")[-1].upper()
        return f"attack:{tid}" if tid in known_techniques else None
    bare = rid.split(":", 1)[1] if ":" in rid and rid.split(":", 1)[0] in {p[:-1] for p in TYPE_PREFIX.values()} else rid
    if bare.strip("{}") not in window_text:
        return None  # not present in the evidence the model was shown
    if store.graph.has_node(rid):
        return rid
    if store.graph.has_node(bare):
        return bare
    for prefix in TYPE_PREFIX.values():
        for cand in (f"{prefix}{bare}", f"{prefix}{{{bare.strip('{}')}}}"):
            if store.graph.has_node(cand):
                return cand
    return None  # grounded in text but not a graph entity: skip rather than mint a new node


def enrich_with_llm(store: GraphStore, rows_by_log: dict[str, list[dict]], client: Any,
                    users: Optional[Iterable[str]] = None, window_size: int = 8, windows_per_user: int = 2,
                    max_retries: int = 1) -> EnrichmentStats:
    lookup_text = _load_technique_lookup_summary()
    lookup = json.loads((Path(__file__).resolve().parents[1] / "data" / "attack_technique_lookup.json").read_text())
    known_techniques = {p["technique_id"] for p in lookup["patterns"]}
    template = _load_prompt_template()
    system = "Extract graph entities and relations from security log evidence. Respond with JSON only."
    users = users if users is not None else sorted({r["user"] for rows in rows_by_log.values() for r in rows})
    stats = EnrichmentStats()

    for user, chunk in _windows(rows_by_log, users, window_size, windows_per_user):
        stats.windows += 1
        events = [e for e, _, _ in chunk]
        window_text = _format_event_window(events) + "\n" + json.dumps([r for _, _, r in chunk], default=str)
        prompt = template.format(technique_lookup=lookup_text, event_window=_format_event_window(events))
        data = None
        for _ in range(max_retries + 1):
            try:
                data = _parse_response_json(client.call(system, prompt).content)
                break
            except ExtractionError:
                continue
            except Exception as exc:  # network / rate limit
                log.warning("LLM enrichment call failed for %s: %s", user, exc)
                break
        if not isinstance(data, dict):
            stats.llm_failures += 1
            continue
        types = {str(e.get("id")): str(e.get("type", "")) for e in data.get("entities", []) if isinstance(e, dict)}
        ts = max(str(e.timestamp) for e in events)
        for rel in data.get("relations", []):
            if not isinstance(rel, dict):
                continue
            rtype = str(rel.get("type") or rel.get("relation") or "").upper()
            src_raw, dst_raw = rel.get("source") or rel.get("source_id"), rel.get("target") or rel.get("target_id")
            src = _resolve(src_raw, types.get(str(src_raw), ""), window_text, known_techniques, store)
            dst = _resolve(dst_raw, types.get(str(dst_raw), ""), window_text, known_techniques, store)
            if rtype not in ALLOWED_RELATIONS or src is None or dst is None:
                stats.relations_rejected += 1
                stats.entities_rejected += (src is None) + (dst is None)
                if len(stats.rejected_examples) < 5:
                    stats.rejected_examples.append(f"{src_raw} -{rtype}-> {dst_raw}")
                continue
            if dst.startswith("attack:") and not store.graph.has_node(dst):
                store.add_entity({"id": dst, "type": "AttackTechnique", "attributes": {"technique_id": dst.split(":")[1]}})
            try:
                conf = min(float(rel.get("confidence", LLM_CONFIDENCE_CAP)), LLM_CONFIDENCE_CAP)
            except (TypeError, ValueError):
                conf = LLM_CONFIDENCE_CAP
            parsed = parse_timestamp(rel.get("timestamp"))
            when = parsed.isoformat() if parsed else ts
            store.add_relation(src, dst, rtype, conf, when, extractor="llm",
                               pattern="llm_inferred" if rtype == "MATCHES_TECHNIQUE" else None)
            stats.relations_added += 1
    return stats
