"""Week 9 — evidence paths, behavioural risk, and the post-groundedness confidence stage."""
import pytest
from fastapi.testclient import TestClient

from graph.graph_store import GraphStore
from reasoning.confidence_scoring import attach_confidence, verdict_label
from reasoning.evidence import behavioral_risk, find_evidence_paths, technique_prevalence

T = "2010-01-05T23:30:00"


def _store():
    s = GraphStore()
    for u in ("alice", "bob", "carol", "dave"):
        s.add_entity({"id": u, "type": "User"})
    s.add_entity({"id": "device:d1", "type": "Device"})
    s.add_entity({"id": "attack:T1052", "type": "AttackTechnique", "attributes": {"severity": "high"}})
    s.add_entity({"id": "attack:T1567", "type": "AttackTechnique", "attributes": {"severity": "high"}})
    # alice: USB chain (user -> device -> technique) + direct technique edge from the same event
    s.add_relation("alice", "device:d1", "CONNECTED_DEVICE", 0.85, T)
    s.add_relation("device:d1", "attack:T1052", "INDICATES", 0.65, T, pattern="usb_device_connect")
    s.add_relation("alice", "attack:T1052", "MATCHES_TECHNIQUE", 0.75, T, pattern="usb_device_connect")
    # every user emails attachments externally -> T1567 is "normal" for this population
    for u in ("alice", "bob", "carol", "dave"):
        s.add_relation(u, "attack:T1567", "MATCHES_TECHNIQUE", 0.75, T, pattern="external_email_with_attachment")
    return s


def test_evidence_paths_include_direct_and_story_chain():
    s = _store()
    sg = s.get_subgraph_dict("alice", hops=1)
    paths = find_evidence_paths(sg, "alice")
    kinds = {(p["technique_id"], tuple(p["relations"])) for p in paths}
    assert ("T1052", ("MATCHES_TECHNIQUE",)) in kinds
    assert ("T1052", ("CONNECTED_DEVICE", "INDICATES")) in kinds
    chain = next(p for p in paths if len(p["edge_ids"]) == 2)
    assert chain["confidence"] == pytest.approx(0.85 * 0.65)
    assert all(p["nodes"][0] == "alice" for p in paths)
    # other users' technique edges are never attributed to alice
    assert all(p["nodes"][0] == "alice" for p in find_evidence_paths(s.get_subgraph_dict("alice", hops=2), "alice"))


def test_peer_prevalence_discounts_common_behaviour():
    s = _store()
    prev = technique_prevalence(s.graph)
    assert prev["attack:T1567"] == 1.0 and prev["attack:T1052"] == 0.25
    bob = behavioral_risk(s.get_subgraph_dict("bob", hops=1), "bob", prev)
    alice = behavioral_risk(s.get_subgraph_dict("alice", hops=1), "alice", prev)
    assert bob["risk"] == 0.0  # only population-wide behaviour
    # alice: 0.8 (high) * 0.75 (best path) * (1 - 0.25) = 0.45
    assert alice["risk"] == pytest.approx(0.45)


def test_confidence_counts_only_verified_paths():
    s = _store()
    sg = s.get_subgraph_dict("alice", hops=1)
    paths = find_evidence_paths(sg, "alice")
    direct = next(p for p in paths if p["technique_id"] == "T1052" and len(p["edge_ids"]) == 1)
    good = {"risk_score": 0.5, "cited_edges": direct["edge_ids"],
            "groundedness": {"status": "grounded", "verified_edges": direct["edge_ids"]}}
    out = attach_confidence(good, sg, "alice")
    assert out["propagated_confidence"] == pytest.approx(0.75)
    assert out["confidence_pct"] == 75.0 and out["verdict_label"] == "suspicious"

    unverified = {"risk_score": 0.4, "cited_edges": ["bogus"],
                  "groundedness": {"status": "unverified", "verified_edges": []}}
    out = attach_confidence(unverified, sg, "alice")
    assert out["propagated_confidence"] == 0.0 and out["evidence_paths"] == []


def test_verdict_labels():
    assert verdict_label(0.1) == "benign"
    assert verdict_label(0.4) == "suspicious"
    assert verdict_label(0.72) == "high_risk"


def test_api_returns_confidence_and_queue(monkeypatch):
    monkeypatch.setenv("CYBERGRAPHRAG_OFFLINE", "1")
    from api.main import app
    import graph.graph_store as gs

    s = _store()
    monkeypatch.setattr(gs.store, "graph", s.graph)
    monkeypatch.setattr(gs.store, "g", s.graph)
    client = TestClient(app)
    data = client.post("/incidents/analyze", json={"entity": "alice", "query": "Is alice exfiltrating data?"}).json()
    v = data["verdict"]
    assert v["groundedness"]["status"] == "grounded"
    assert 0 < v["confidence_pct"] <= 100
    assert v["verdict_label"] in {"benign", "suspicious", "high_risk"}
    assert "_context" not in data["subgraph"]

    q = client.get("/incidents/queue?limit=10").json()
    assert q["incidents"][0]["entity"] == "alice"
    assert {"risk_score", "confidence_pct", "verdict_label", "techniques"} <= set(q["incidents"][0])


def test_behaviour_summary_in_queue_and_verdict(monkeypatch):
    monkeypatch.setenv("CYBERGRAPHRAG_OFFLINE", "1")
    from api.main import app
    import graph.graph_store as gs

    s = _store()
    monkeypatch.setattr(gs.store, "graph", s.graph)
    monkeypatch.setattr(gs.store, "g", s.graph)
    c = TestClient(app)
    row = c.get("/incidents/queue").json()["incidents"][0]
    b = {x["technique_id"]: x for x in row["behaviour"]}
    assert b["T1052"]["peer_prevalence"] == 0.25 and b["T1052"]["first_seen"] == T and b["T1052"]["verified"] is None
    v = c.post("/incidents/analyze", json={"entity": "alice", "query": "q", "hops": 1}).json()["verdict"]
    vb = {x["technique_id"]: x for x in v["behaviour"]}
    assert vb["T1052"]["verified"] is True and vb["T1052"]["support"] == 2
