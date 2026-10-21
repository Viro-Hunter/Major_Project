"""Answer an analyst's question about one person, grounded in their log records.

Flow:  scope guard -> LLM answer citing edge ids -> groundedness check (one constrained retry)
       -> otherwise a question-aware answer built directly from the logs (offline / model failure).

The case VERDICT is not touched here; this is a conversation about the evidence.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

from graph.confidence import parse_timestamp
from reasoning.groundedness_checker import indexed_edge_ids
from reasoning.scope_guard import check_scope

PLAIN = {
    "T1078": "logged in outside working hours", "T1052": "plugged in a USB storage device",
    "T1005": "opened files they had never touched before", "T1567": "emailed attachments outside the company",
    "T1048": "emailed many outside addresses at once", "T1030": "moved an unusually large amount of data",
    "T1071": "used an upload or file-sharing website", "T1213": "pulled documents from shared repositories",
}
QA_SYSTEM = (
    "You are an insider-threat analyst assistant. Answer the analyst's question about ONE employee using ONLY the "
    "log records provided (each has an id). Rules: (1) Answer only questions about work activity visible in the logs: "
    "logins, computers, USB devices, files, email, websites and the ATT&CK behaviours they match. (2) If the question "
    "asks about personal or protected characteristics (sexual orientation, religion, caste, race, health, pregnancy, "
    "politics, relationships, appearance, age) or anything the logs cannot show, do not speculate: return "
    '{"out_of_scope": true}. (3) Cite the ids of the records that support each statement; never cite ids that are not '
    "listed. (4) Plain English, 2-4 sentences, no jargon. Reply with JSON only: "
    '{"answer": "...", "cited_edges": ["e12", ...]} or {"out_of_scope": true}.'
)


def _when(ts: Any) -> str:
    t = parse_timestamp(ts)
    return t.strftime("%a %-d %b %Y, %-I:%M %p") if t else ""


def _is_night(ts: Any) -> bool:
    t = parse_timestamp(ts)
    return bool(t) and (t.hour >= 20 or t.hour < 6)


def _is_weekend(ts: Any) -> bool:
    t = parse_timestamp(ts)
    return bool(t) and t.weekday() >= 5


def _short(node_id: str) -> str:
    kind, _, rest = str(node_id).partition(":")
    rest = rest.strip("{}")
    if kind == "host":
        return f"computer {rest}"
    if kind == "file":
        return f"file {rest}"
    if kind == "device":
        return "a USB drive"
    if kind == "email":
        return "an email"
    if kind == "net":
        host = rest.split("/")[2] if "://" in rest else rest.split("/")[0]
        return host.replace("www.", "")
    if kind == "attack":
        return PLAIN.get(rest, rest)
    return str(node_id)


VERB = {"OBSERVED_ON": "used", "ACCESSED": "opened", "CONNECTED_DEVICE": "plugged in", "SENT_EMAIL_TO": "sent",
        "BROWSED": "visited", "MATCHES_TECHNIQUE": "matched the behaviour:", "LOGGED_IN_FROM": "logged in from"}


def _records(subgraph: dict, focus: str) -> list[dict]:
    ids = indexed_edge_ids(subgraph)
    out = []
    for i, e in enumerate(subgraph.get("edges", [])):
        if e.get("source") != focus:
            continue
        rel = e.get("type") or e.get("relation") or ""
        verb = VERB.get(rel, rel.lower())
        if rel == "CONNECTED_DEVICE" and str(e.get("activity", "")).lower() == "disconnect":
            verb = "removed"
        out.append({"id": ids[i], "rel": rel, "target": e.get("target"), "ts": e.get("timestamp"),
                    "text": f"{_when(e.get('timestamp'))}: {verb} {_short(e.get('target'))}"})
    out.sort(key=lambda r: str(r["ts"]))
    return out


INTENTS = [
    ("night", r"night|late|after.?hours|evening|weekend|midnight|odd hours|outside (work|office)"),
    ("usb", r"usb|device|drive|thumb|pen ?drive|removable|plug"),
    ("email", r"e-?mail|mail|sent|send|attach|outside the company|external"),
    ("web", r"web|site|url|browse|visit|upload|internet|download"),
    ("file", r"file|document|doc\b|copied|copy|opened|access"),
    ("why", r"why|flag|suspicious|risk|steal|stealing|taking|leak|exfil|insider|threat|data"),
    ("when", r"when|last|recent|timeline|first|latest"),
]
REL_FOR = {"usb": {"CONNECTED_DEVICE"}, "email": {"SENT_EMAIL_TO"}, "web": {"BROWSED"}, "file": {"ACCESSED"}}


def offline_answer(subgraph: dict, focus: str, question: str) -> dict:
    """Answer common question types straight from the records (no model needed)."""
    q = question.lower()
    intent = next((name for name, pat in INTENTS if re.search(pat, q)), None)
    recs = _records(subgraph, focus)
    chosen: list[dict] = []
    if intent == "night":
        acts = [r for r in recs if r["rel"] != "MATCHES_TECHNIQUE"]
        night = [r for r in acts if _is_night(r["ts"])]
        weekend = [r for r in acts if _is_weekend(r["ts"]) and not _is_night(r["ts"])]
        weekend_note = f" There are also {len(weekend)} daytime action(s) at the weekend." if weekend else ""
        if night:
            chosen = night
            head = f"{focus} has {len(night)} recorded action(s) at night (8 PM–6 AM).{weekend_note}"
        else:
            chosen = weekend
            head = (f"{focus} has no recorded activity at night (8 PM–6 AM)."
                    + (f" However, there are {len(weekend)} daytime action(s) at the weekend:" if weekend else ""))
    elif intent in REL_FOR:
        chosen = [r for r in recs if r["rel"] in REL_FOR[intent]]
        noun = {"usb": "USB device event", "email": "email sent", "web": "website visit", "file": "file opened"}[intent]
        head = f"{focus} has {len(chosen)} {noun}{'s' if len(chosen) != 1 else ''} in the logs." if chosen else f"No {noun}s by {focus} appear in the logs."
        if intent == "usb" and chosen:
            plugged = sum(1 for r in chosen if "removed" not in r["text"])
            head = f"{focus} plugged in a USB drive {plugged} time(s) and removed one {len(chosen) - plugged} time(s)."
    elif intent in ("why", "when"):
        tech = {}
        for r in recs:
            if r["rel"] == "MATCHES_TECHNIQUE":
                tech.setdefault(r["target"], []).append(r)
        if intent == "why":
            chosen = [v[-1] for v in tech.values()]
            head = (f"{focus} was flagged because they " + ", ".join(PLAIN.get(t.split(':')[-1], t) for t in tech) + "."
                    if tech else f"Nothing in {focus}'s logs matches a known attacker behaviour.")
        else:
            chosen = recs[-6:]
            head = f"{focus}'s most recent recorded activity:" if chosen else f"No dated activity for {focus}."
    else:
        return {"answer": ("Without an AI model I can answer questions about logins, night or weekend activity, USB devices, "
                           "files, email, websites and why someone was flagged. Connect an AI model under “AI model” for other questions."),
                "cited_edges": [], "evidence": [], "mode": "offline-unsupported"}
    shown = chosen[-8:]
    return {"answer": head, "cited_edges": [r["id"] for r in shown],
            "evidence": [r["text"] for r in shown], "more": max(0, len(chosen) - len(shown)), "mode": "offline"}


def llm_answer(subgraph: dict, focus: str, question: str, client: Any) -> dict:
    recs = _records(subgraph, focus)
    # techniques and their evidence first, then the most recent activity, within a compact budget
    recs = [r for r in recs if r["rel"] == "MATCHES_TECHNIQUE"] + [r for r in recs if r["rel"] != "MATCHES_TECHNIQUE"][-60:]
    lines = "\n".join(f'{r["id"]}: {r["text"]}' for r in recs[:90])
    user = f"Employee: {focus}\nLog records:\n{lines}\n\nQuestion: {question}\nReply with JSON only."
    from reasoning.verdict_generator import extract_json_object

    allowed = {r["id"] for r in recs}
    for attempt in range(2):
        resp = client.call(QA_SYSTEM, user if attempt == 0 else user + f"\nYou may ONLY cite these ids: {sorted(allowed)[:120]}")
        data = extract_json_object((resp.content or "").strip())
        if data is None:
            raise ValueError(f"{client.model} did not reply in the required JSON format")
        if data.get("out_of_scope"):
            return {"answer": None, "out_of_scope": True, "cited_edges": [], "evidence": []}
        cited = [str(c) for c in data.get("cited_edges") or []]
        missing = [c for c in cited if c not in allowed]
        if not missing or attempt == 1:
            by_id = {r["id"]: r["text"] for r in recs}
            return {"answer": str(data.get("answer") or "").strip(), "cited_edges": [c for c in cited if c in allowed],
                    "missing_edges": missing, "evidence": [by_id[c] for c in cited if c in by_id][:8]}
    return {}  # unreachable
