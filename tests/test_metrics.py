"""Week 10 — each metric on a tiny synthetic example with hand-computed answers."""
import csv

import pytest

from evaluation.metrics import (
    ResponseTimer,
    graph_completeness,
    macro_average,
    response_time_summary,
    retrieval_accuracy,
    threat_correlation_precision,
    threat_detection_effectiveness,
)
from graph.graph_store import GraphStore


def test_retrieval_accuracy_hand_computed():
    # pred {a,b,c,d}, truth {b,c,e}: tp=2 fp=2 fn=1 -> P=0.5 R=2/3 F1=2*0.5*0.6667/1.1667=0.5714
    r = retrieval_accuracy(["a", "b", "c", "d"], ["b", "c", "e"])
    assert (r["tp"], r["fp"], r["fn"]) == (2, 2, 1)
    assert r["precision"] == pytest.approx(0.5)
    assert r["recall"] == pytest.approx(2 / 3)
    assert r["f1"] == pytest.approx(4 / 7)
    assert retrieval_accuracy([], [])["f1"] == 1.0
    assert retrieval_accuracy(["x"], [])["precision"] == 0.0


def test_macro_average():
    avg = macro_average([{"precision": 1.0, "recall": 0.5, "f1": 2 / 3}, {"precision": 0.0, "recall": 0.0, "f1": 0.0}])
    assert avg["precision"] == 0.5 and avg["recall"] == 0.25


def test_graph_completeness_by_ids_and_by_count():
    s = GraphStore()
    for n in ("u1", "h1", "f1"):
        s.add_entity({"id": n, "type": "X"})
    r = graph_completeness(s, expected_entities=["u1", "h1", "f1", "d1"])
    assert r["ratio"] == pytest.approx(0.75) and r["missing"] == ["d1"]
    assert graph_completeness(s, expected_entity_count=6)["ratio"] == pytest.approx(0.5)
    assert graph_completeness(s, expected_entity_count=2)["ratio"] == 1.0  # capped
    with pytest.raises(ValueError):
        graph_completeness(s)


def test_threat_correlation_precision():
    pred = [("u1", "T1052"), ("u1", "T1005"), ("u2", "T1078")]
    truth = [("u1", "T1052"), ("u2", "T1078"), ("u2", "T1048"), ("u3", "T1567")]
    r = threat_correlation_precision(pred, truth)  # tp=2 fp=1 fn=2
    assert r["precision"] == pytest.approx(2 / 3)
    assert r["recall"] == pytest.approx(0.5)
    assert r["f1"] == pytest.approx(4 / 7)
    und = threat_correlation_precision([("b", "a")], [("a", "b")], directed=False)
    assert und["precision"] == 1.0


def test_detection_effectiveness_confusion_matrix():
    labels = {"a": True, "b": True, "c": False, "d": False, "e": False}
    preds = {"a": True, "b": False, "c": True, "d": False}  # e missing -> benign
    r = threat_detection_effectiveness(preds, labels)  # tp=1 fn=1 fp=1 tn=2
    assert (r["tp"], r["fp"], r["fn"], r["tn"]) == (1, 1, 1, 2)
    assert r["precision"] == 0.5 and r["recall"] == 0.5 and r["f1"] == 0.5
    assert r["fpr"] == pytest.approx(1 / 3)
    assert r["accuracy"] == pytest.approx(0.6)


def test_response_timer_summary_and_csv(tmp_path):
    rows = [{"phase": "query", "label": str(i), "seconds": s} for i, s in enumerate([0.1, 0.2, 0.3, 0.4])]
    summ = response_time_summary(rows)["query"]
    assert summ["count"] == 4
    assert summ["mean_s"] == pytest.approx(0.25)
    assert summ["p50_s"] == pytest.approx(0.25)   # midpoint of 0.2 and 0.3
    assert summ["p95_s"] == pytest.approx(0.385)  # 0.3 + 0.85 * 0.1
    t = ResponseTimer()
    with t.measure("indexing", "graph"):
        pass
    t.record("query", "u1", 0.5)
    out = t.write_csv(tmp_path / "timings.csv")
    with out.open() as fh:
        rows = list(csv.DictReader(fh))
    assert [r["phase"] for r in rows] == ["indexing", "query"]
