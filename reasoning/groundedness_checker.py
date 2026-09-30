"""Groundedness checker: verify that every edge a verdict cites really exists
in the subgraph the verdict was generated from.

Pipeline position:  verdict_generator -> check_groundedness -> API response

Policy (fail-safe, never fail-confident):
  1. Every id in verdict["cited_edges"] must exist in subgraph.edges.
  2. If any are missing, regenerate the verdict with an explicit instruction to
     use ONLY the listed edges, up to MAX_RETRIES times.
  3. If still ungrounded, downgrade risk_score by 20% and append "[unverified]"
     to the explanation instead of presenting a false-confidence result.
"""
from __future__ import annotations

import copy
import logging
from collections.abc import Callable, Iterable, Mapping
from typing import Any

logger = logging.getLogger(__name__)

MAX_RETRIES = 2
DOWNGRADE_FACTOR = 0.8  # 20% reduction
UNVERIFIED_TAG = "[unverified]"

# regenerate(subgraph, allowed_edge_ids, instruction) -> new verdict dict
Regenerator = Callable[[Any, list, str], Mapping]

_EDGE_ID_KEYS = ("id", "edge_id")


def _edge_id(edge: Any) -> str | None:
    """Best-effort id extraction from a str, dict or object edge."""
    if isinstance(edge, str):
        return edge
    if isinstance(edge, Mapping):
        for key in _EDGE_ID_KEYS:
            if edge.get(key) is not None:
                return str(edge[key])
        return None
    for key in _EDGE_ID_KEYS:
        value = getattr(edge, key, None)
        if value is not None:
            return str(value)
    return None


def indexed_edge_ids(subgraph: Any) -> list[str]:
    """Edge ids in subgraph order. Edges without an id/edge_id get the stable
    positional id ``e<index>`` so generator and checker always agree."""
    edges = subgraph.get("edges") if isinstance(subgraph, Mapping) else getattr(subgraph, "edges", None)
    if edges is None:
        return []
    if isinstance(edges, Mapping):
        return [str(k) for k in edges]
    return [_edge_id(e) or f"e{i}" for i, e in enumerate(edges)]


def get_edge_ids(subgraph: Any) -> set[str]:
    """Set of edge ids present in ``subgraph`` (see ``indexed_edge_ids``)."""
    return set(indexed_edge_ids(subgraph))


def find_missing_edges(verdict: Mapping, subgraph: Any) -> list[str]:
    """Cited edge ids that do not exist in the subgraph (order preserved, de-duplicated)."""
    available = get_edge_ids(subgraph)
    missing: list[str] = []
    for cited in verdict.get("cited_edges") or []:
        cid = str(cited)
        if cid not in available and cid not in missing:
            missing.append(cid)
    return missing


def build_retry_instruction(allowed_edge_ids: Iterable[str], missing: Iterable[str]) -> str:
    allowed = sorted(allowed_edge_ids)
    return (
        "Your previous verdict cited edge ids that do not exist in the evidence graph: "
        f"{sorted(missing)}. Regenerate the verdict and cite ONLY edges from this list: "
        f"{allowed}. Do not invent, guess or paraphrase edge ids. If the listed edges do "
        "not support a conclusion, say so and lower the risk score accordingly."
    )


def _append_unverified(verdict: dict) -> None:
    """Append the [unverified] tag to whichever explanation field the verdict uses."""
    for key in ("explanation", "narrative"):
        text = verdict.get(key)
        if isinstance(text, str) and text:
            if UNVERIFIED_TAG not in text:
                verdict[key] = f"{text.rstrip()} {UNVERIFIED_TAG}"
            return
    verdict["explanation"] = UNVERIFIED_TAG


def _downgrade(verdict: dict) -> None:
    score = verdict.get("risk_score")
    if isinstance(score, (int, float)) and not isinstance(score, bool):
        verdict["risk_score"] = round(score * DOWNGRADE_FACTOR, 4)


def _annotate(verdict: dict, status: str, attempts: int, missing: list[str], available: set[str]) -> dict:
    verdict["groundedness"] = {
        "status": status,  # "grounded" | "regenerated" | "unverified"
        "retries_used": attempts,
        "missing_edges": missing,
        "verified_edges": [str(c) for c in verdict.get("cited_edges") or [] if str(c) in available],
    }
    if "grounded" in verdict:  # keep the legacy flag truthful
        verdict["grounded"] = status != "unverified"
    return verdict


def check_groundedness(
    verdict: Mapping,
    subgraph: Any,
    regenerate: Regenerator | None = None,
    max_retries: int = MAX_RETRIES,
) -> dict:
    """Return a groundedness-checked copy of ``verdict``. The input is never mutated.

    ``regenerate`` re-invokes verdict_generator; see api/routes/incidents.py for
    wiring. Without it no retries are possible and an ungrounded verdict is
    downgraded immediately.
    """
    available = get_edge_ids(subgraph)
    current = copy.deepcopy(dict(verdict))
    missing = find_missing_edges(current, subgraph)

    if not missing:
        return _annotate(current, "grounded", 0, [], available)

    retries = 0
    while missing and regenerate is not None and retries < max_retries:
        retries += 1
        logger.warning(
            "Ungrounded verdict (attempt %d/%d): missing edges %s", retries, max_retries, missing
        )
        instruction = build_retry_instruction(available, missing)
        try:
            candidate = regenerate(subgraph, sorted(available), instruction)
        except Exception:  # a failed LLM call counts as a failed attempt
            logger.exception("verdict regeneration failed")
            continue
        current = copy.deepcopy(dict(candidate))
        missing = find_missing_edges(current, subgraph)

    if not missing:
        return _annotate(current, "regenerated", retries, [], available)

    logger.error("Verdict still ungrounded after %d retries: %s", retries, missing)
    _downgrade(current)
    _append_unverified(current)
    return _annotate(current, "unverified", retries, missing, available)


def verify_verdict(verdict: Mapping, subgraph: Any) -> bool:
    """Backward-compatible boolean check (True if every cited edge exists)."""
    return not find_missing_edges(verdict, subgraph)
