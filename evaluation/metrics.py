"""Week 10 — evaluation metrics (pure functions, no I/O except the timings CSV).

The five metrics from the SoP / Objective 5:

1. retrieval_accuracy            — F1 of entities the system surfaced as evidence vs ground-truth entities
2. graph_completeness            — entities found in the graph / entities expected from the raw logs
3. threat_correlation_precision  — precision/recall on (entity, entity) links, e.g. (user, ATT&CK technique)
4. response_time                 — indexing time and per-query latency, logged to CSV
5. threat_detection_effectiveness — precision / recall / F1 / false-positive rate vs insider labels
"""
from __future__ import annotations

import csv
import statistics
import time
from collections.abc import Hashable, Iterable, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Optional


def _prf(tp: int, fp: int, fn: int) -> dict[str, float]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "tp": tp, "fp": fp, "fn": fn}


# 1 -------------------------------------------------------------------------
def retrieval_accuracy(predicted_entities: Iterable[Hashable], ground_truth_entities: Iterable[Hashable]) -> dict[str, float]:
    """Set-based precision/recall/F1. Two empty sets score a perfect 1.0 (nothing to find, nothing claimed)."""
    pred, truth = set(predicted_entities), set(ground_truth_entities)
    if not pred and not truth:
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0, "tp": 0, "fp": 0, "fn": 0}
    tp = len(pred & truth)
    return _prf(tp, len(pred - truth), len(truth - pred))


def macro_average(results: Iterable[Mapping[str, float]], keys=("precision", "recall", "f1")) -> dict[str, float]:
    results = list(results)
    if not results:
        return {k: 0.0 for k in keys}
    return {k: sum(r[k] for r in results) / len(results) for k in keys}


# 2 -------------------------------------------------------------------------
def graph_completeness(graph_store: Any, expected_entity_count: Optional[int] = None,
                       expected_entities: Optional[Iterable[str]] = None) -> dict[str, Any]:
    """found / expected.

    With ``expected_entities`` (ids derived independently from the raw logs) only ids that
    actually exist in the graph count as found, and the missing ones are returned.
    With only ``expected_entity_count`` the ratio is ``min(nodes, expected) / expected``.
    """
    graph = getattr(graph_store, "graph", graph_store)
    if expected_entities is not None:
        expected = set(expected_entities)
        found = {e for e in expected if graph.has_node(e)}
        ratio = len(found) / len(expected) if expected else 1.0
        return {"ratio": ratio, "found": len(found), "expected": len(expected), "missing": sorted(expected - found)}
    if not expected_entity_count:
        raise ValueError("give expected_entity_count > 0 or expected_entities")
    n = graph.number_of_nodes()
    return {"ratio": min(n, expected_entity_count) / expected_entity_count, "found": n, "expected": expected_entity_count, "missing": []}


# 3 -------------------------------------------------------------------------
def threat_correlation_precision(predicted_edges: Iterable[tuple], ground_truth_edges: Iterable[tuple],
                                 directed: bool = True) -> dict[str, float]:
    """Precision/recall/F1 on linked entity pairs. ``directed=False`` treats (a, b) == (b, a)."""
    norm = (lambda e: tuple(e[:2])) if directed else (lambda e: tuple(sorted(map(str, e[:2]))))
    pred = {norm(e) for e in predicted_edges}
    truth = {norm(e) for e in ground_truth_edges}
    if not pred and not truth:
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0, "tp": 0, "fp": 0, "fn": 0}
    return _prf(len(pred & truth), len(pred - truth), len(truth - pred))


# 4 -------------------------------------------------------------------------
class ResponseTimer:
    """Collects (phase, label, seconds) rows; ``with timer.measure("query", user): ...``."""

    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    @contextmanager
    def measure(self, phase: str, label: str = ""):
        t0 = time.perf_counter()
        try:
            yield
        finally:
            self.rows.append({"phase": phase, "label": label, "seconds": time.perf_counter() - t0})

    def record(self, phase: str, label: str, seconds: float) -> None:
        self.rows.append({"phase": phase, "label": label, "seconds": float(seconds)})

    def summary(self) -> dict[str, dict[str, float]]:
        return response_time_summary(self.rows)

    def write_csv(self, path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=["phase", "label", "seconds"])
            w.writeheader()
            for r in self.rows:
                w.writerow({**r, "seconds": f"{r['seconds']:.6f}"})
        return path


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def response_time_summary(rows: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, float]]:
    by_phase: dict[str, list[float]] = {}
    for r in rows:
        by_phase.setdefault(r["phase"], []).append(float(r["seconds"]))
    return {
        phase: {"count": len(v), "total_s": sum(v), "mean_s": statistics.fmean(v),
                "p50_s": _percentile(v, 0.5), "p95_s": _percentile(v, 0.95), "max_s": max(v)}
        for phase, v in by_phase.items()
    }


# 5 -------------------------------------------------------------------------
def threat_detection_effectiveness(predictions: Mapping[Hashable, bool], labels: Mapping[Hashable, bool]) -> dict[str, float]:
    """Binary detection quality over the entities present in ``labels``.

    Entities missing from ``predictions`` count as predicted benign.
    """
    tp = fp = fn = tn = 0
    for entity, is_threat in labels.items():
        flagged = bool(predictions.get(entity, False))
        if flagged and is_threat:
            tp += 1
        elif flagged and not is_threat:
            fp += 1
        elif not flagged and is_threat:
            fn += 1
        else:
            tn += 1
    out = _prf(tp, fp, fn)
    out.update(tn=tn, fpr=fp / (fp + tn) if fp + tn else 0.0,
               accuracy=(tp + tn) / max(tp + fp + fn + tn, 1), support=tp + fp + fn + tn)
    return out
