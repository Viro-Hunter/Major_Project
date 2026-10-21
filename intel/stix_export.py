"""Export a groundedness-checked verdict as a native STIX 2.1 bundle (SoP Objective 1).

ATT&CK techniques are NOT re-described here: the bundle embeds MITRE's own
``attack-pattern`` objects (original ids, kill-chain phases, references) from
``data/attack_patterns.stix21.json`` (built by ``scripts/extract_attack_stix.py``),
so any STIX-aware tool (OpenCTI, MISP, a TAXII server) links them to ATT&CK directly.

Object model for one verdict about a user:

    identity (our organisation) ─┐
    threat-actor "Suspected insider: <user>" ──uses──▶ attack-pattern (MITRE)   [confidence = path confidence]
    user-account / file / url / email-message (SCOs) ◀── observed-data ◀── sighting ──▶ attack-pattern
    note: groundedness result + verified edge ids
    report: verdict narrative, risk, label; object_refs = everything above

Custom properties are prefixed ``x_cybergraphrag_`` as STIX 2.1 requires.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping, Optional

import stix2

from graph.confidence import parse_timestamp

ROOT = Path(__file__).resolve().parents[1]
ATTACK_BUNDLE = ROOT / "data" / "attack_patterns.stix21.json"
NS = uuid.UUID("1b7e4f1a-6a43-4a4e-9c35-3c3a3d9b0f17")  # namespace for deterministic ids
PRODUCER = "Cyber Intelligence GraphRAG"


@lru_cache(maxsize=1)
def mitre_objects() -> dict[str, dict]:
    """``{"T1052": attack-pattern dict, ...}`` plus ``"_support"`` -> identity/marking objects."""
    data = json.loads(ATTACK_BUNDLE.read_text())["objects"]
    out: dict[str, Any] = {"_support": [o for o in data if o["type"] != "attack-pattern"]}
    for o in data:
        if o["type"] == "attack-pattern":
            ext = next(r["external_id"] for r in o["external_references"] if r.get("source_name") == "mitre-attack")
            out[ext] = o
    return out


def _sid(kind: str, *parts: Any) -> str:
    return f"{kind}--{uuid.uuid5(NS, '|'.join(map(str, (kind,) + parts)))}"


def _ts(value: Any) -> datetime:
    t = parse_timestamp(value) or datetime(1970, 1, 1)
    return t.replace(tzinfo=timezone.utc)


def _sco_for(node_id: str, node: Mapping[str, Any]) -> Optional[Any]:
    kind, _, rest = node_id.partition(":")
    attrs = node.get("attributes") or {}
    if kind == "file" and rest:
        return stix2.File(name=rest)
    if kind == "net" and rest:
        url = attrs.get("url") or rest
        return stix2.URL(value=url if "://" in url else f"http://{url}")
    if kind == "email":
        return stix2.EmailMessage(is_multipart=False, subject=f"CERT email event {rest.strip('{}')}",
                                  custom_properties={"x_cybergraphrag_recipients": str(attrs.get("to", ""))[:200]},
                                  allow_custom=True)
    return None


def build_stix_bundle(verdict: Mapping[str, Any], subgraph: Mapping[str, Any], entity: str,
                      organisation: str = "Example Enterprise SOC") -> dict:
    """STIX 2.1 bundle (as a dict) for one checked verdict. Only VERIFIED evidence paths are exported."""
    attack = mitre_objects()
    nodes = {n.get("id"): n for n in subgraph.get("nodes", [])}
    now = datetime.now(timezone.utc)
    org = stix2.Identity(id=_sid("identity", organisation), name=organisation, identity_class="organization",
                         description=f"Organisation whose logs were analysed by {PRODUCER}.")
    account = stix2.UserAccount(user_id=entity, account_login=entity)
    label = verdict.get("verdict_label", "benign")
    actor = stix2.ThreatActor(
        id=_sid("threat-actor", organisation, entity), name=f"Suspected insider: {entity}",
        threat_actor_types=["unknown"], roles=["agent"], created_by_ref=org.id,
        description=("Account whose behaviour matched ATT&CK techniques on evidence paths verified against "
                     "the knowledge graph. This is a lead for an analyst, not a finding of guilt."),
        confidence=int(round(100 * float(verdict.get("propagated_confidence", 0.0)))),
    )
    objs: list[Any] = [org, account, actor]
    objs.append(stix2.Relationship(id=_sid("relationship", entity, "impersonates"), source_ref=actor.id,
                                   relationship_type="impersonates", target_ref=org.id, created_by_ref=org.id,
                                   description=f"Acts from inside the organisation using account {entity}."))
    used_patterns: dict[str, dict] = {}
    by_tech: dict[str, list[Mapping]] = {}
    for p in verdict.get("evidence_paths") or []:
        by_tech.setdefault(p["technique_id"], []).append(p)

    for tid, paths in by_tech.items():
        ap = attack.get(tid)
        if ap is None:
            continue
        used_patterns[tid] = ap
        best = max(paths, key=lambda p: p["confidence"])
        conf = int(round(100 * best["confidence"]))
        objs.append(stix2.Relationship(
            id=_sid("relationship", entity, tid), source_ref=actor.id, relationship_type="uses", target_ref=ap["id"],
            confidence=conf, created_by_ref=org.id,
            description=f"{entity} matched {tid} ({ap['name']}) via {best.get('pattern') or 'technique match'} "
                        f"on {len(paths)} verified evidence path(s); strongest path confidence {best['confidence']:.2f}."))
        scos = [account]
        for p in paths:
            for nid in p["nodes"][1:-1]:
                sco = _sco_for(nid, nodes.get(nid, {}))
                if sco is not None and all(getattr(s, "id", None) != sco.id for s in scos):
                    scos.append(sco)
        times = sorted(_ts(p.get("timestamp")) for p in paths)
        objs += scos[1:]
        od = stix2.ObservedData(
            id=_sid("observed-data", entity, tid), first_observed=times[0], last_observed=times[-1],
            number_observed=len(paths), object_refs=[s.id for s in scos], created_by_ref=org.id,
            custom_properties={"x_cybergraphrag_edge_ids": sorted({e for p in paths for e in p["edge_ids"]})},
            allow_custom=True)
        objs.append(od)
        objs.append(stix2.Sighting(
            id=_sid("sighting", entity, tid), sighting_of_ref=ap["id"], observed_data_refs=[od.id],
            where_sighted_refs=[org.id], first_seen=times[0], last_seen=times[-1], count=len(paths),
            confidence=conf, created_by_ref=org.id))

    g = verdict.get("groundedness") or {}
    report_id = _sid("report", organisation, entity, verdict.get("narrative", ""))
    note = stix2.Note(
        id=_sid("note", report_id), created_by_ref=org.id, object_refs=[report_id],
        abstract=f"Groundedness check: {g.get('status', 'unknown')}",
        content=(f"Every claim in the verdict must cite an edge that exists in the retrieved knowledge graph. "
                 f"Status: {g.get('status', 'unknown')}; {len(g.get('verified_edges') or [])} cited edge(s) verified; "
                 f"missing: {g.get('missing_edges') or 'none'}; regeneration attempts: {g.get('retries_used', 0)}."),
        authors=[PRODUCER])
    attack_support = attack["_support"] if used_patterns else []
    report = stix2.Report(
        id=report_id, name=f"Insider-threat verdict for {entity}: {label.replace('_', ' ')}",
        report_types=["threat-actor", "attack-pattern"], published=now, created_by_ref=org.id,
        description=verdict.get("narrative", ""), labels=[label],
        confidence=int(round(100 * float(verdict.get("propagated_confidence", 0.0)))),
        object_refs=[o.id for o in objs] + [ap["id"] for ap in used_patterns.values()] + [note.id],
        custom_properties={
            "x_cybergraphrag_risk_score": round(float(verdict.get("risk_score", 0.0)), 4),
            "x_cybergraphrag_groundedness": g.get("status", "unknown"),
            "x_cybergraphrag_model": verdict.get("model", ""),
        }, allow_custom=True)
    bundle = stix2.Bundle(objects=objs + [note, report], allow_custom=True)
    data = json.loads(bundle.serialize())
    data["objects"] = attack_support + list(used_patterns.values()) + data["objects"]
    return data
