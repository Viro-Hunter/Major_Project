"""Hybrid extraction: LLM relations are grounded in the event window and capped at 0.6 confidence."""
import json
from types import SimpleNamespace

from extraction.llm_enrichment import LLM_CONFIDENCE_CAP, enrich_with_llm
from scripts.build_graph_from_cert import build_graph_from_rows

ROWS = {
    "logon": [{"id": "{L1}", "date": "01/05/2010 23:10:00", "user": "ABC0001", "pc": "PC-1111", "activity": "Logon"}],
    "device": [{"id": "{D1}", "date": "01/05/2010 23:15:00", "user": "ABC0001", "pc": "PC-1111", "activity": "Connect"}],
    "file": [{"id": "{F1}", "date": "01/05/2010 23:20:00", "user": "ABC0001", "pc": "PC-1111", "filename": "SECRET01.doc", "content": "x"}],
    "email": [], "http": [],
}


class FakeLLM:
    def __init__(self, payload):
        self.payload, self.calls = payload, 0

    def call(self, system, user):
        self.calls += 1
        return SimpleNamespace(content=self.payload if isinstance(self.payload, str) else json.dumps(self.payload))


def test_grounded_relations_added_hallucinations_rejected():
    store = build_graph_from_rows(ROWS)
    before = store.num_edges()
    llm = FakeLLM({"entities": [{"id": "ABC0001", "type": "User"}, {"id": "SECRET01.doc", "type": "FileResource"},
                                {"id": "T1052", "type": "AttackTechnique"}, {"id": "PAYROLL_ALL.xlsx", "type": "FileResource"}],
                   "relations": [
                       {"source": "ABC0001", "target": "SECRET01.doc", "type": "ACCESSED", "confidence": 0.9},
                       {"source": "ABC0001", "target": "T1052", "type": "MATCHES_TECHNIQUE", "confidence": 0.6},
                       {"source": "ABC0001", "target": "PAYROLL_ALL.xlsx", "type": "ACCESSED", "confidence": 0.9},  # invented
                       {"source": "ABC0001", "target": "T9999", "type": "MATCHES_TECHNIQUE"},                       # unknown technique
                       {"source": "ABC0001", "target": "SECRET01.doc", "type": "DELETED_EVIDENCE"},               # not in vocabulary
                   ]})
    stats = enrich_with_llm(store, ROWS, llm)
    assert stats.windows == 1 and llm.calls == 1
    assert stats.relations_added == 2 and stats.relations_rejected == 3
    llm_edges = [(u, v, d) for u, v, d in store.graph.edges(data=True) if d.get("extractor") == "llm"]
    assert {(u, v) for u, v, _ in llm_edges} == {("ABC0001", "file:SECRET01.doc"), ("ABC0001", "attack:T1052")}
    assert all(d["confidence"] <= LLM_CONFIDENCE_CAP for *_, d in llm_edges)  # 0.9 claimed -> capped
    assert store.num_edges() == before + 2
    assert not store.graph.has_node("file:PAYROLL_ALL.xlsx")


def test_malformed_llm_output_counts_as_failure_and_graph_unchanged():
    store = build_graph_from_rows(ROWS)
    before = store.num_edges()
    stats = enrich_with_llm(store, ROWS, FakeLLM("sorry, I cannot help with that"))
    assert stats.llm_failures == 1 and store.num_edges() == before
