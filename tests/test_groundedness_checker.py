"""Tests for reasoning.groundedness_checker."""
import copy

import pytest

from reasoning.groundedness_checker import UNVERIFIED_TAG, check_groundedness

SUBGRAPH = {
    "nodes": [{"id": "AAM0658"}, {"id": "PC-101"}, {"id": "10.0.0.5"}],
    "edges": [
        {"id": "e1", "source": "AAM0658", "target": "PC-101", "type": "LOGGED_ON"},
        {"id": "e2", "source": "PC-101", "target": "10.0.0.5", "type": "CONNECTED_TO"},
    ],
}


def make_verdict(cited, score=0.9, explanation="User logged on then connected externally."):
    return {"cited_edges": cited, "risk_score": score, "explanation": explanation}


class FakeGenerator:
    """Stands in for verdict_generator; returns queued verdicts and records calls."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, subgraph, allowed_edge_ids, instruction):
        self.calls.append({"allowed": allowed_edge_ids, "instruction": instruction})
        return self.responses.pop(0)


def test_grounded_verdict_passes_untouched():
    verdict = make_verdict(["e1", "e2"])
    original = copy.deepcopy(verdict)
    gen = FakeGenerator()

    result = check_groundedness(verdict, SUBGRAPH, regenerate=gen)

    assert gen.calls == []  # no regeneration
    assert result["risk_score"] == original["risk_score"]
    assert result["explanation"] == original["explanation"]
    assert result["cited_edges"] == original["cited_edges"]
    assert UNVERIFIED_TAG not in result["explanation"]
    assert result["groundedness"]["status"] == "grounded"
    assert verdict == original  # input never mutated


def test_nonexistent_edge_triggers_regeneration():
    bad = make_verdict(["e1", "e99"])
    good = make_verdict(["e1", "e2"], score=0.85, explanation="Regenerated, grounded.")
    gen = FakeGenerator(good)

    result = check_groundedness(bad, SUBGRAPH, regenerate=gen)

    assert len(gen.calls) == 1
    assert sorted(gen.calls[0]["allowed"]) == ["e1", "e2"]
    assert "ONLY" in gen.calls[0]["instruction"]
    assert "e99" in gen.calls[0]["instruction"]
    assert result["cited_edges"] == ["e1", "e2"]
    assert result["risk_score"] == 0.85  # not downgraded
    assert UNVERIFIED_TAG not in result["explanation"]
    assert result["groundedness"]["status"] == "regenerated"
    assert result["groundedness"]["retries_used"] == 1


def test_two_failed_retries_flag_unverified_and_downgrade():
    bad = make_verdict(["e99"], score=0.9)
    gen = FakeGenerator(make_verdict(["e98"], score=0.9), make_verdict(["e97"], score=0.9))

    result = check_groundedness(bad, SUBGRAPH, regenerate=gen)

    assert len(gen.calls) == 2  # exactly two retries, no more
    assert result["risk_score"] == pytest.approx(0.72)  # 0.9 * 0.8
    assert result["explanation"].endswith(UNVERIFIED_TAG)
    assert result["groundedness"]["status"] == "unverified"
    assert result["groundedness"]["missing_edges"] == ["e97"]


def test_retry_that_raises_counts_as_failed_attempt():
    bad = make_verdict(["e99"], score=0.5)
    calls = {"n": 0}

    def flaky(subgraph, allowed, instruction):
        calls["n"] += 1
        raise RuntimeError("LLM down")

    result = check_groundedness(bad, SUBGRAPH, regenerate=flaky)

    assert calls["n"] == 2
    assert result["risk_score"] == pytest.approx(0.4)
    assert UNVERIFIED_TAG in result["explanation"]


def test_no_regenerator_downgrades_immediately():
    result = check_groundedness(make_verdict(["e99"], score=1.0), SUBGRAPH)
    assert result["risk_score"] == pytest.approx(0.8)
    assert result["groundedness"]["retries_used"] == 0


def test_tag_is_not_duplicated_and_narrative_field_supported():
    verdict = {"cited_edges": ["nope"], "risk_score": 0.5, "narrative": "Story."}
    result = check_groundedness(verdict, SUBGRAPH)
    assert result["narrative"] == f"Story. {UNVERIFIED_TAG}"
    assert result["narrative"].count(UNVERIFIED_TAG) == 1


def test_edge_shapes_supported():
    as_mapping = {"edges": {"e1": {}, "e2": {}}}
    as_ids = {"edges": ["e1", "e2"]}
    for sg in (as_mapping, as_ids):
        assert check_groundedness(make_verdict(["e1"]), sg)["groundedness"]["status"] == "grounded"


def test_edges_without_ids_get_positional_ids():
    from reasoning.groundedness_checker import indexed_edge_ids, verify_verdict

    sg = {"edges": [{"source": "a", "target": "b"}, {"source": "b", "target": "c"}]}
    assert indexed_edge_ids(sg) == ["e0", "e1"]
    assert verify_verdict({"cited_edges": ["e0", "e1"]}, sg)
    assert not verify_verdict({"cited_edges": ["e7"]}, sg)


def test_legacy_grounded_flag_is_updated():
    result = check_groundedness({"cited_edges": ["zzz"], "risk_score": 0.5, "grounded": True}, SUBGRAPH)
    assert result["grounded"] is False
    ok = check_groundedness({"cited_edges": ["e1"], "risk_score": 0.5, "grounded": True}, SUBGRAPH)
    assert ok["grounded"] is True
