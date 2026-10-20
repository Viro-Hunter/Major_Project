"""Week 9 — confidence propagation along graph paths.

Every edge carries an extraction confidence in [0, 1] (0.9 for direct log
evidence, lower for derived/inferred links).  A *path* through the graph is
only as trustworthy as all of its links together, and old evidence is worth
less than fresh evidence, so:

    path_confidence = PRODUCT_i ( c_i * DAILY_DECAY ** age_days_i )

where ``age_days_i`` is measured from the edge timestamp to an ``as_of``
reference time.

Why ``as_of`` and not "now": CERT r4.2 events are from 2010.  Decaying against
the wall clock would multiply every edge by ~0.95**5800 ≈ 0 and make the score
useless.  The reference is therefore the time of the investigation window —
by default the newest timestamp among the edges being scored.  The live API
passes the newest event in the analysed subgraph; a production deployment
would pass ``datetime.now()``.

The legacy half-life helpers (``apply_decay``, ``multiply_path_confidence``,
``compute_edge_confidence``) are kept unchanged for backward compatibility.
"""
from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any, List, Optional

DAILY_DECAY = 0.95             # Week 9 spec: confidence *= 0.95 ** days_since_edge
DECAY_HALF_LIFE_HOURS = 72     # legacy half-life model (kept for compatibility)


# --------------------------------------------------------------------------- #
# Legacy helpers (pre-Week 9) — unchanged behaviour
# --------------------------------------------------------------------------- #
def apply_decay(edge_conf: float, hours_old: float, half_life: float = DECAY_HALF_LIFE_HOURS) -> float:
    if hours_old <= 0:
        return edge_conf
    return edge_conf * (0.5 ** (hours_old / half_life))


def multiply_path_confidence(confidences: List[float]) -> float:
    p = 1.0
    for c in confidences:
        p *= max(0.0, min(1.0, c))
    return p


def compute_edge_confidence(base: float, trust: float = 1.0, hours_old: float = 0) -> float:
    decayed = apply_decay(base * trust, hours_old)
    return max(0.0, min(1.0, decayed))


# --------------------------------------------------------------------------- #
# Week 9 — multiplicative path confidence with daily decay
# --------------------------------------------------------------------------- #
def parse_timestamp(value: Any) -> Optional[datetime]:
    """Parse ISO-8601 or CERT ``MM/DD/YYYY HH:MM:SS``; return None if unparseable."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    text = str(value).strip()
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        pass
    try:
        return datetime.strptime(text, "%m/%d/%Y %H:%M:%S")
    except ValueError:
        return None


def edge_age_days(edge: Mapping[str, Any], as_of: Optional[datetime]) -> float:
    """Age of an edge in (fractional) days relative to ``as_of``; 0 if unknown or in the future."""
    ts = parse_timestamp(edge.get("timestamp"))
    if ts is None or as_of is None:
        return 0.0
    return max(0.0, (as_of - ts).total_seconds() / 86_400.0)


def decayed_edge_confidence(
    edge: Mapping[str, Any],
    as_of: Optional[datetime] = None,
    daily_decay: float = DAILY_DECAY,
) -> float:
    """``confidence * daily_decay ** age_days`` clamped to [0, 1]. Missing confidence counts as 1.0."""
    try:
        base = float(edge.get("confidence", 1.0))
    except (TypeError, ValueError):
        base = 1.0
    base = max(0.0, min(1.0, base))
    return max(0.0, min(1.0, base * (daily_decay ** edge_age_days(edge, as_of))))


def latest_timestamp(edges: Iterable[Mapping[str, Any]]) -> Optional[datetime]:
    """Newest parseable timestamp among ``edges`` (the default ``as_of`` reference)."""
    stamps = [t for t in (parse_timestamp(e.get("timestamp")) for e in edges) if t is not None]
    return max(stamps) if stamps else None


def path_confidence(
    edges: Iterable[Mapping[str, Any]],
    as_of: Optional[datetime] = None,
    daily_decay: float = DAILY_DECAY,
) -> float:
    """Propagated confidence of a path: product of each edge's decayed confidence.

    ``edges`` is the ordered list of edge dicts along the path (each with
    ``confidence`` and optionally ``timestamp``).  If ``as_of`` is omitted the
    newest timestamp on the path is used, so a path made only of same-day
    evidence is not decayed at all.  An empty path has confidence 1.0 (the
    multiplicative identity) — callers decide whether that is meaningful.
    """
    edges = list(edges)
    if as_of is None:
        as_of = latest_timestamp(edges)
    p = 1.0
    for edge in edges:
        p *= decayed_edge_confidence(edge, as_of, daily_decay)
    return p


def noisy_or(values: Iterable[float]) -> float:
    """Combine independent pieces of evidence: 1 - PRODUCT(1 - v)."""
    remaining = 1.0
    for v in values:
        remaining *= 1.0 - max(0.0, min(1.0, float(v)))
    return 1.0 - remaining


def to_percent(value: float) -> float:
    """0.8123 -> 81.2 (for dashboard display)."""
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return 0.0
    return round(100.0 * float(value), 1)
