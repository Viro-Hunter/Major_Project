"""Week 9 — evidence paths, propagated confidence and behavioural risk.

Given the dict subgraph returned for an entity (``GraphStore.get_subgraph_dict``)
this module answers two questions the verdict needs:

1. *Which concrete paths connect the focus entity to an ATT&CK technique, and
   how much should we trust each one?*  (``find_evidence_paths``)
   A path is either a direct ``User -MATCHES_TECHNIQUE-> Technique`` edge or a
   story chain ``User -ACCESSED/CONNECTED_DEVICE-> X -INDICATES-> Technique``.
   Each path's confidence is propagated with ``graph.confidence.path_confidence``.

2. *How risky is the behaviour overall?*  (``behavioral_risk``)
   Each distinct technique contributes
        s_t = severity_weight(t) * best_path_confidence(t) * (1 - peer_prevalence(t))
   and techniques are combined with a noisy-OR, so several *different* stages
   (e.g. off-hours access + USB + upload) compound, while one behaviour seen a
   hundred times does not.  ``peer_prevalence`` is the fraction of users in the
   whole graph that also exhibit the technique — behaviour that nearly every
   employee shows (e.g. emailing an attachment outside) carries little weight.
   No labels are used anywhere in this computation.

Edge ids follow ``reasoning.groundedness_checker.indexed_edge_ids`` so the
evidence trail can be cited by the verdict and verified by the checker.
"""
from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

from graph.confidence import latest_timestamp, noisy_or, path_confidence
from reasoning.groundedness_checker import indexed_edge_ids

LOOKUP_PATH = Path(__file__).resolve().parents[1] / "data" / "attack_technique_lookup.json"

# Fixed a-priori from the lookup table's documented severity — NOT tuned on the benchmark.
SEVERITY_WEIGHT = {"high": 0.8, "medium": 0.5, "low": 0.3}
DEFAULT_SEVERITY = "medium"

TECHNIQUE_RELATIONS = {"MATCHES_TECHNIQUE"}
INDICATOR_RELATIONS = {"INDICATES"}


def _rel(edge: Mapping[str, Any]) -> str:
    return str(edge.get("type") or edge.get("relation") or "")


@lru_cache(maxsize=1)
def _severity_by_technique() -> dict[str, str]:
    try:
        data = json.loads(LOOKUP_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return {p["technique_id"]: p.get("severity", DEFAULT_SEVERITY) for p in data.get("patterns", [])}


def technique_label(node_id: str) -> str:
    """``attack:T1052`` -> ``T1052``; other ids returned unchanged."""
    return node_id.split(":", 1)[1] if node_id.startswith("attack:") else node_id


def severity_weight(technique_node: str, node_attrs: Optional[Mapping[str, Any]] = None) -> float:
    sev = None
    if node_attrs:
        sev = node_attrs.get("severity") or (node_attrs.get("attributes") or {}).get("severity")
    sev = sev or _severity_by_technique().get(technique_label(technique_node), DEFAULT_SEVERITY)
    return SEVERITY_WEIGHT.get(str(sev).lower(), SEVERITY_WEIGHT[DEFAULT_SEVERITY])


def technique_prevalence(graph: Any) -> dict[str, float]:
    """Fraction of User nodes that have >=1 MATCHES_TECHNIQUE edge to each technique node.

    ``graph`` is a networkx (Multi)DiGraph, e.g. ``store.graph``.
    """
    users = [n for n, d in graph.nodes(data=True) if d.get("type") == "User"]
    if not users:
        return {}
    exhibiting: dict[str, set[str]] = defaultdict(set)
    for u in users:
        for _, target, data in graph.out_edges(u, data=True):
            if _rel(data) in TECHNIQUE_RELATIONS:
                exhibiting[target].add(u)
    return {t: len(us) / len(users) for t, us in exhibiting.items()}


def find_evidence_paths(subgraph: Mapping[str, Any], focus: str) -> list[dict[str, Any]]:
    """All focus->technique evidence paths in ``subgraph`` with propagated confidence.

    Returned paths are sorted by confidence (desc).  Each has: ``technique``,
    ``nodes``, ``edge_ids``, ``relations``, ``timestamp``, ``confidence``, ``pattern``.
    """
    edges = list(subgraph.get("edges", []))
    ids = indexed_edge_ids(subgraph)
    nodes = {n.get("id"): n for n in subgraph.get("nodes", [])}
    own = [e for e in edges if e.get("source") == focus]
    as_of = latest_timestamp(own) or latest_timestamp(edges)

    # Index focus -> X edges by (X, timestamp) to pair with X -INDICATES-> T from the same event.
    focus_out: dict[tuple[str, str], list[int]] = defaultdict(list)
    for i, e in enumerate(edges):
        if e.get("source") == focus and _rel(e) not in TECHNIQUE_RELATIONS:
            focus_out[(e.get("target"), str(e.get("timestamp")))].append(i)

    paths: list[dict[str, Any]] = []
    for i, e in enumerate(edges):
        rel = _rel(e)
        if rel in TECHNIQUE_RELATIONS and e.get("source") == focus:
            chain = [i]
        elif rel in INDICATOR_RELATIONS:
            first = focus_out.get((e.get("source"), str(e.get("timestamp"))))
            if not first:
                continue
            chain = [first[0], i]
        else:
            continue
        chain_edges = [edges[j] for j in chain]
        technique = chain_edges[-1].get("target")
        if (nodes.get(technique) or {}).get("type") not in (None, "AttackTechnique") and not str(technique).startswith("attack:"):
            continue
        paths.append({
            "technique": technique,
            "technique_id": technique_label(str(technique)),
            "nodes": [focus] + [ce.get("target") for ce in chain_edges],
            "edge_ids": [ids[j] for j in chain],
            "relations": [_rel(ce) for ce in chain_edges],
            "timestamp": chain_edges[-1].get("timestamp"),
            "pattern": chain_edges[-1].get("pattern"),
            "confidence": round(path_confidence(chain_edges, as_of=as_of), 4),
        })
    paths.sort(key=lambda p: (-p["confidence"], p["technique"], len(p["edge_ids"])))
    return paths


TOP_PATHS_PER_TECHNIQUE = 3


def summarize_techniques(paths: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Per technique: best path, top-N paths, number of supporting paths."""
    out: dict[str, dict[str, Any]] = {}
    for p in paths:  # paths already sorted best-first
        t = p["technique"]
        if t not in out:
            out[t] = {"best": p, "count": 0, "top": []}
        out[t]["count"] += 1
        if len(out[t]["top"]) < TOP_PATHS_PER_TECHNIQUE:
            out[t]["top"].append(p)
    return out


def behavioral_risk(
    subgraph: Mapping[str, Any],
    focus: str,
    prevalence: Optional[Mapping[str, float]] = None,
) -> dict[str, Any]:
    """Noisy-OR risk over distinct techniques, weighted by severity, confidence and peer rarity."""
    paths = find_evidence_paths(subgraph, focus)
    per_t = summarize_techniques(paths)
    nodes = {n.get("id"): n for n in subgraph.get("nodes", [])}
    contributions = []
    for t, info in per_t.items():
        best = info["best"]
        rarity = 1.0 - float((prevalence or {}).get(t, 0.0))
        s = severity_weight(t, nodes.get(t)) * best["confidence"] * rarity
        contributions.append({
            "technique": t,
            "technique_id": best["technique_id"],
            "pattern": best["pattern"],
            "support": info["count"],
            "path_confidence": best["confidence"],
            "peer_prevalence": round(1.0 - rarity, 4),
            "contribution": round(s, 4),
            "edge_ids": best["edge_ids"],
            "supporting_edge_ids": list(dict.fromkeys(e for p in info["top"] for e in p["edge_ids"])),
        })
    contributions.sort(key=lambda c: -c["contribution"])
    risk = noisy_or(c["contribution"] for c in contributions)
    # Overall evidence confidence: strength of the best-supported path (0 if no evidence).
    conf = max((c["path_confidence"] for c in contributions), default=0.0)
    return {
        "risk": round(risk, 4),
        "propagated_confidence": round(conf, 4),
        "techniques": contributions,
        "paths": paths,
    }
