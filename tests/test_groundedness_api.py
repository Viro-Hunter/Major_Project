from fastapi.testclient import TestClient

from api.main import app
import api.routes.incidents as incidents

client = TestClient(app)
BODY = {"entity": "AAM0658", "query": "Why is user linked to host?"}

FAKE_SUBGRAPH = {
    "nodes": [
        {"id": "AAM0658", "type": "User"},
        {"id": "PC-001", "type": "Host"},
        {"id": "T1078", "type": "AttackTechnique"},
    ],
    "edges": [  # no ids on purpose: they get positional ids e0, e1
        {"source": "AAM0658", "target": "PC-001", "type": "LOGGED_IN_FROM", "confidence": 0.9},
        {"source": "AAM0658", "target": "T1078", "type": "MATCHES_TECHNIQUE", "confidence": 0.9},
    ],
}


def _setup(monkeypatch, responses):
    calls = []

    def fake_generate(subgraph, query, extra_instruction=None):
        calls.append(extra_instruction)
        return dict(responses.pop(0))

    monkeypatch.setattr(incidents, "get_entity_subgraph", lambda *a, **k: dict(FAKE_SUBGRAPH))
    monkeypatch.setattr(incidents, "semantic_search", lambda *a, **k: [])
    monkeypatch.setattr(incidents, "generate_verdict", fake_generate)
    return calls


def test_api_downgrades_after_two_failed_retries(monkeypatch):
    bad = {"narrative": "Made-up evidence.", "risk_score": 0.9,
           "cited_edges": ["does-not-exist"], "grounded": True}
    calls = _setup(monkeypatch, [bad, bad, bad])

    data = client.post("/incidents/analyze", json=BODY).json()

    assert len(calls) == 3                      # 1 initial + 2 retries
    assert "ONLY" in calls[1]                   # retry carries the explicit constraint
    assert data["verdict"]["groundedness"]["status"] == "unverified"
    assert data["verdict"]["risk_score"] == 0.72   # 0.9 * 0.8
    assert data["verdict"]["narrative"].endswith("[unverified]")
    assert data["grounded"] is False


def test_api_recovers_on_retry(monkeypatch):
    bad = {"narrative": "Made-up evidence.", "risk_score": 0.9, "cited_edges": ["nope"]}
    good = {"narrative": "Real evidence.", "risk_score": 0.85, "cited_edges": ["e0", "e1"]}
    calls = _setup(monkeypatch, [bad, good])

    data = client.post("/incidents/analyze", json=BODY).json()

    assert len(calls) == 2
    assert data["verdict"]["groundedness"]["status"] == "regenerated"
    assert data["verdict"]["risk_score"] == 0.85
    assert data["grounded"] is True
