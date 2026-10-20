"""Week 10 — labelled-set construction, answer-key parsing and a small benchmark smoke run."""
import argparse
import json

from evaluation import scenarios
from evaluation.scenarios import build_injected_set, load_answer_key, story_entity_ids


def test_injected_set_is_seeded_and_labelled():
    a = build_injected_set(n_users=6, n_insiders=3, rows_per_user=10, seed=7)
    b = build_injected_set(n_users=6, n_insiders=3, rows_per_user=10, seed=7)
    assert a.labels == b.labels and a.truth_pairs == b.truth_pairs
    assert sum(a.labels.values()) == 3 and set(a.scenario_of.values()) == {"S1", "S2", "S3"}
    injected = [r for rows in a.rows_by_log.values() for r in rows if r["id"] in a.malicious_ids]
    assert injected and all(a.labels[r["user"]] for r in injected)
    # hand-labelled techniques include ones the lookup table cannot produce (coverage gap is measured)
    assert any(t == "attack:T1056" for _, t in a.truth_pairs)


def test_story_entity_ids_match_builder_convention():
    assert story_entity_ids("file", {"pc": "PC-1", "filename": "X.doc"}) == {"host:PC-1", "file:X.doc"}
    assert story_entity_ids("email", {"pc": "PC-1", "id": "{A}"}) == {"host:PC-1", "email:{A}"}
    assert story_entity_ids("http", {"pc": "PC-1", "url": "http://x"}) == {"host:PC-1", "net:http://x"}


def test_answer_key_parser(tmp_path):
    d = tmp_path / "answers" / "r4.2-1"
    d.mkdir(parents=True)
    (d / "r4.2-1-ABC1234.csv").write_text(
        "logon,{A1B2-C3D4E5F6-G7H8I9J0},01/04/2010 23:10:00,ABC1234,PC-1,Logon\n"
        "http,{K1L2-M3N4O5P6-Q7R8S9T0},01/04/2010 23:20:00,ABC1234,PC-1,http://wikileaks.org/x,some, text\n"
    )
    (tmp_path / "answers" / "insiders.csv").write_text(
        "dataset,scenario,details,user,start,end\n4.2,1,r4.2-1-ABC1234.csv,ABC1234,01/04/2010,01/05/2010\n"
        "5.2,1,x,ZZZ9999,01/04/2010,01/05/2010\n")
    key = load_answer_key(tmp_path / "answers")
    assert key["insiders"] == {"ABC1234"}
    assert key["scenario_of"] == {"ABC1234": "S1"}
    http = next(r for r in key["rows"] if r["_log"] == "http")
    assert http["url"] == "http://wikileaks.org/x" and http["content"] == "some, text"


def test_benchmark_smoke(tmp_path, monkeypatch):
    from evaluation import run_benchmark as rb

    monkeypatch.setattr(rb, "RESULTS", tmp_path)
    args = argparse.Namespace(mode="injected", users=8, insiders=3, rows_per_user=15, seed=1, llm=False,
                              hallucination_rate=1.0, retry_failure_rate=0.0)
    r = rb.run(args)
    assert set(r["headline"]) >= {"retrieval_accuracy_f1", "graph_completeness", "threat_correlation_precision",
                                  "mean_query_latency_s", "detection_f1"}
    assert r["graph_completeness"]["ratio"] == 1.0
    f = r["groundedness_fault_injection"]
    assert f["injected"] == 8 and f["caught"] == 8 and f["recovered_by_retry"] == 8  # retries always succeed here
    assert f["clean_false_alarms"] == 0
    for name in ("benchmark_report.md", "benchmark.json", "timings.csv", "per_user.csv"):
        assert (tmp_path / name).exists()
    assert json.loads((tmp_path / "benchmark.json").read_text())["label_mode"] == "injected"
