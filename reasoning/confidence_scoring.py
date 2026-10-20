"""Week 9 — confidence stage, run AFTER the groundedness check.

Pipeline:  verdict_generator -> groundedness_checker -> attach_confidence -> API

Only evidence the groundedness checker *verified* may contribute confidence.
An evidence path counts if every edge on it was cited and verified; an
unverified verdict therefore ends up with low (often zero) propagated
confidence even if its narrative sounded certain.  This is the coupling
between the Week 8 novelty and the Week 9 confidence score.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Optional

from graph.confidence import decayed_edge_confidence, latest_timestamp, to_percent
from reasoning.evidence import find_evidence_paths
from reasoning.groundedness_checker import indexed_edge_ids

# Verdict labels from the Week 7 spec, derived from the (checked) risk score.
LABEL_THRESHOLDS = ((0.7, "high_risk"), (0.4, "suspicious"))


def verdict_label(risk_score: float) -> str:
    for threshold, label in LABEL_THRESHOLDS:
        if risk_score >= threshold:
            return label
    return "benign"


def attach_confidence(verdict: Mapping[str, Any], subgraph: Mapping[str, Any], focus: Optional[str]) -> dict:
    """Return a copy of ``verdict`` with propagated-confidence fields added.

    Adds: ``propagated_confidence`` (0-1), ``confidence_pct`` (0-100),
    ``evidence_paths`` (verified technique paths, best first) and ``verdict_label``.
    """
    out = dict(verdict)
    g = out.get("groundedness") or {}
    verified = set(map(str, g.get("verified_edges") or out.get("cited_edges") or []))

    paths = find_evidence_paths(subgraph, focus) if focus else []
    supported = [p for p in paths if set(p["edge_ids"]) <= verified]

    if supported:
        conf = max(p["confidence"] for p in supported)
    else:
        # No verified technique path: fall back to the average decayed confidence
        # of the verified cited edges themselves (0 if nothing was verified).
        ids = indexed_edge_ids(subgraph)
        edges = list(subgraph.get("edges", []))
        cited = [edges[i] for i, eid in enumerate(ids) if eid in verified]
        as_of = latest_timestamp(edges)
        conf = (sum(decayed_edge_confidence(e, as_of) for e in cited) / len(cited)) if cited else 0.0

    out["propagated_confidence"] = round(conf, 4)
    out["confidence_pct"] = to_percent(conf)
    out["evidence_paths"] = supported[:10]
    # Every entity on a verified evidence path (used by the benchmark's retrieval-accuracy metric).
    out["evidence_entities"] = sorted({n for p in supported for n in p["nodes"][1:-1]})
    out["evidence_techniques"] = sorted({p["technique"] for p in supported})
    try:
        out["verdict_label"] = verdict_label(float(out.get("risk_score", 0.0)))
    except (TypeError, ValueError):
        out["verdict_label"] = "benign"
    return out
