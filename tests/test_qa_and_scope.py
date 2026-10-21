"""Question answering: scope guard, grounded answers, honest fallback, robust JSON extraction."""
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from reasoning.scope_guard import check_scope
from reasoning.verdict_generator import extract_json_object
from tests.test_evidence_and_confidence_stage import _store


@pytest.mark.parametrize("q", ["is he gay?", "Does he like men?", "what religion is she", "Is she pregnant?",
                               "Which caste is he from?", "who did he vote for", "does he have a girlfriend", "Is he depressed?"])
def test_protected_questions_refused(q):
    d = check_scope(q)
    assert not d.in_scope and "work activity" in d.message


@pytest.mark.parametrize("q", ["Is this person taking company data?", "What did this person do late at night?",
                               "Did he plug in a USB drive straight after logging in?", "Did he transfer files to a thin client?",
                               "What looks like data theft here?", "Why was this person flagged?", "Show the BI report access"])
def test_work_questions_allowed(q):
    assert check_scope(q).in_scope


@pytest.mark.parametrize("text", [
    '{"answer": "ok fine", "cited_edges": []}',
    'Here is the answer:\n{"answer": "ok fine", "cited_edges": []}\nThanks!',
    '<think>let me reason {not json}</think>```json\n{"answer": "ok fine", "cited_edges": []}\n```',
])
def test_extract_json_tolerates_real_model_wrappers(text):
    assert extract_json_object(text)["answer"] == "ok fine"


@pytest.fixture
def client(monkeypatch):
    from api.main import app
    import graph.graph_store as gs
    from action import audit_log

    s = _store()
    monkeypatch.setattr(gs.store, "graph", s.graph)
    monkeypatch.setattr(gs.store, "g", s.graph)
    audit_log.clear()
    return TestClient(app)


def test_refused_question_never_reaches_model_and_is_logged(client, monkeypatch):
    import llm.client
    from action.audit_log import get_logs

    monkeypatch.delenv("CYBERGRAPHRAG_OFFLINE", raising=False)
    monkeypatch.setattr(llm.client.LLMClient, "call", lambda *a, **k: pytest.fail("model must not be called"))
    r = client.post("/incidents/ask", json={"entity": "alice", "question": "is he gay?"}).json()
    assert r["refused"] and r["model"] == "scope-guard"
    assert any(l.get("action_type") == "question_refused" or "question_refused" in json.dumps(l) for l in get_logs(10))


def test_offline_answer_is_question_aware_and_cites_records(client, monkeypatch):
    monkeypatch.setenv("CYBERGRAPHRAG_OFFLINE", "1")
    night = client.post("/incidents/ask", json={"entity": "alice", "question": "What did she do late at night?"}).json()
    usb = client.post("/incidents/ask", json={"entity": "alice", "question": "Did she use a USB drive?"}).json()
    assert night["answer"] != usb["answer"]
    assert "at night" in night["answer"] and night["cited_edges"] and night["model"] == "rules-engine"
    assert "USB" in usb["answer"] and usb["status"] == "grounded"
    other = client.post("/incidents/ask", json={"entity": "alice", "question": "Summarise her career"}).json()
    assert other["supported"] is False and "Connect an AI model" in other["answer"]


def test_llm_answer_checked_and_model_refusal_respected(client, monkeypatch):
    import llm.client

    monkeypatch.delenv("CYBERGRAPHRAG_OFFLINE", raising=False)
    replies = iter(['Sure! {"answer": "She plugged in a USB drive at 11:30 PM.", "cited_edges": ["e0", "e999"]}',
                    '{"answer": "She plugged in a USB drive at 11:30 PM.", "cited_edges": ["e999"]}'])
    monkeypatch.setattr(llm.client.LLMClient, "call", lambda self, s, u: SimpleNamespace(content=next(replies), model=self.model))
    r = client.post("/incidents/ask", json={"entity": "alice", "question": "Did she use USB?"}).json()
    assert r["status"] == "unverified" and r["missing_edges"] == ["e999"]  # invented id caught after one retry

    monkeypatch.setattr(llm.client.LLMClient, "call", lambda self, s, u: SimpleNamespace(content='{"out_of_scope": "protected"}', model=self.model))
    r = client.post("/incidents/ask", json={"entity": "alice", "question": "What kind of person is she?"}).json()
    assert r["refused"] and r["kind"] == "protected" and "AI" in r["category"]

    # questions the logs simply cannot answer get a neutral reply, not the protected-characteristics refusal
    monkeypatch.setattr(llm.client.LLMClient, "call", lambda self, s, u: SimpleNamespace(content='{"out_of_scope": "not_in_logs"}', model="meta-llama/x:free"))
    r = client.post("/incidents/ask", json={"entity": "alice", "question": "did she eat popcorn?"}).json()
    assert r["kind"] == "not_in_logs" and "don't record" in r["answer"] and "unlawful" not in r["answer"]
    assert r["model"] == "meta-llama/x:free"  # the model that actually answered (routers pick per request)


def test_non_json_reply_gets_one_format_retry(client, monkeypatch):
    import llm.client

    monkeypatch.delenv("CYBERGRAPHRAG_OFFLINE", raising=False)
    replies = iter(["She used a USB drive a few times.", '{"answer": "She plugged in a USB drive.", "cited_edges": ["e0"]}'])
    monkeypatch.setattr(llm.client.LLMClient, "call", lambda self, s, u: SimpleNamespace(content=next(replies), model=self.model))
    r = client.post("/incidents/ask", json={"entity": "alice", "question": "Did she use USB?"}).json()
    assert r["status"] == "grounded" and r["model"] != "rules-engine"


def test_attribute_questions_answered_honestly_offline(client, monkeypatch):
    monkeypatch.setenv("CYBERGRAPHRAG_OFFLINE", "1")
    r = client.post("/incidents/ask", json={"entity": "alice", "question": "what usb version did he use?"}).json()
    assert "not details such as brand, model, version" in r["answer"] and r["kind"] == "not_in_logs"


def test_risk_comes_from_evidence_not_the_model(client, monkeypatch):
    import llm.client

    monkeypatch.delenv("CYBERGRAPHRAG_OFFLINE", raising=False)
    monkeypatch.setattr(llm.client.LLMClient, "call", lambda self, s, u: SimpleNamespace(
        content='{"narrative": "She plugged in a USB drive late at night.", "risk_score": 0.99, "cited_edges": ["e0"]}', model="m"))
    v = client.post("/incidents/analyze", json={"entity": "alice", "query": "q", "hops": 1}).json()["verdict"]
    assert v["model_risk"] == 0.99 and v["risk_score"] == pytest.approx(0.45, abs=0.01)  # evidence-based (see test_peer_prevalence)


def test_model_failure_reason_reported(client, monkeypatch):
    import llm.client

    monkeypatch.delenv("CYBERGRAPHRAG_OFFLINE", raising=False)
    def boom(self, s, u):
        raise RuntimeError("Error code: 429 - rate limited")
    monkeypatch.setattr(llm.client.LLMClient, "call", boom)
    r = client.post("/incidents/ask", json={"entity": "alice", "question": "Did she use a USB drive?"}).json()
    assert r["model"] == "rules-engine" and "rate-limited" in r["fallback_reason"]
    v = client.post("/incidents/analyze", json={"entity": "alice", "query": "q", "hops": 1}).json()["verdict"]
    assert v["model"] == "template-fallback" and "rate-limited" in v["fallback_reason"]
