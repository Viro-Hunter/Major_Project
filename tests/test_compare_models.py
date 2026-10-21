"""Model comparison end to end with a fake LLM that sometimes cites edges that do not exist."""
import json
import re
from types import SimpleNamespace

import llm.client


class FakeLLMClient:
    calls = 0

    def __init__(self, *a, **k):
        self.model, self.provider = "fake/llm-70b", "openrouter"

    def call(self, system, user):
        FakeLLMClient.calls += 1
        if "Extract graph entities" in system:
            return SimpleNamespace(content='{"entities": [], "relations": []}')
        ids = re.findall(r'"id": "(e\d+)"', user)[:3]
        retry = "ONLY" in user or "only" in system.lower() and "allowed" in user.lower()
        cited = ids if retry or FakeLLMClient.calls % 3 else ids + ["e999999"]  # every 3rd first answer hallucinates
        return SimpleNamespace(content=json.dumps({
            "narrative": "Off-hours USB activity followed by file copies.", "risk_score": 0.55,
            "confidence": 0.7, "evidence_edges": len(cited), "cited_edges": cited}))


def test_compare_models_runs_template_llm_and_hybrid(tmp_path, monkeypatch):
    from evaluation import compare_models as cm, run_benchmark as rb

    monkeypatch.setattr(llm.client, "LLMClient", FakeLLMClient)
    monkeypatch.setattr(rb, "RESULTS", tmp_path)
    monkeypatch.setattr(cm, "ROOT", tmp_path.parent)
    (tmp_path.parent / "evaluation" / "results").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("sys.argv", ["compare_models.py", "--mode", "injected", "--users", "6", "--insiders", "3",
                                     "--rows-per-user", "12", "--hybrid"])
    assert cm.main() == 0
    md = (tmp_path.parent / "evaluation" / "results" / "model_comparison.md").read_text()
    assert "fake/llm-70b" in md and "template-fallback" in md and "LLM extraction" in md
    llm_run = json.loads((tmp_path / "benchmark_cmp_llm.json").read_text())
    g = llm_run["groundedness_live"]
    assert g.get("regenerated", 0) >= 1  # hallucinated citations were caught and repaired
    assert sum(g.values()) == 6
