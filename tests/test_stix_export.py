"""STIX 2.1 export: validated with the OASIS stix2-validator, MITRE objects embedded natively."""
import json

import pytest
from fastapi.testclient import TestClient
from stix2validator import ValidationOptions, validate_string

from intel.stix_export import build_stix_bundle, mitre_objects
from tests.test_evidence_and_confidence_stage import _store


def _validate(bundle: dict):
    res = validate_string(json.dumps(bundle), ValidationOptions(version="2.1", strict=False))
    assert res.is_valid, [str(e) for e in res.errors]


def test_mitre_bundle_has_official_ids():
    ap = mitre_objects()["T1052"]
    assert ap["id"] == "attack-pattern--e6415f09-df0e-48de-9aba-928c902b7549"
    assert ap["name"] == "Exfiltration Over Physical Medium" and ap["spec_version"] == "2.1"


def test_api_stix_export_is_valid_and_complete(monkeypatch):
    monkeypatch.setenv("CYBERGRAPHRAG_OFFLINE", "1")
    from api.main import app
    import graph.graph_store as gs

    s = _store()
    monkeypatch.setattr(gs.store, "graph", s.graph)
    monkeypatch.setattr(gs.store, "g", s.graph)
    bundle = TestClient(app).get("/incidents/alice/stix").json()
    _validate(bundle)
    types = {o["type"] for o in bundle["objects"]}
    assert {"report", "threat-actor", "attack-pattern", "relationship", "sighting", "observed-data", "note",
            "user-account", "identity"} <= types
    uses = [o for o in bundle["objects"] if o["type"] == "relationship" and o["relationship_type"] == "uses"]
    targets = {u["target_ref"] for u in uses}
    assert mitre_objects()["T1052"]["id"] in targets  # official MITRE id, not a re-minted one
    t1052 = next(u for u in uses if u["target_ref"] == mitre_objects()["T1052"]["id"])
    assert 0 < t1052["confidence"] <= 100
    report = next(o for o in bundle["objects"] if o["type"] == "report")
    assert report["x_cybergraphrag_groundedness"] == "grounded"
    ids = {o["id"] for o in bundle["objects"]}
    assert set(report["object_refs"]) <= ids  # every reference resolves inside the bundle


def test_unverified_verdict_exports_no_evidence():
    s = _store()
    sg = s.get_subgraph_dict("alice", hops=1)
    v = {"risk_score": 0.3, "narrative": "x [unverified]", "verdict_label": "benign", "propagated_confidence": 0.0,
         "evidence_paths": [], "groundedness": {"status": "unverified", "verified_edges": [], "missing_edges": ["e9"]}}
    b = build_stix_bundle(v, sg, "alice")
    _validate(b)
    assert not [o for o in b["objects"] if o["type"] in ("sighting", "attack-pattern")]
    note = next(o for o in b["objects"] if o["type"] == "note")
    assert "unverified" in note["content"]
