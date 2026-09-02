import pytest

from graph.graph_store import GraphStore
from retrieval.graph_retriever import retrieve_subgraph


def graph_fixture():
    store = GraphStore()
    store.add_entity({"id": "u1", "type": "User", "attributes": {"name": "alice finance"}})
    store.add_entity({"id": "h1", "type": "Host", "attributes": {"name": "finance workstation"}})
    store.add_entity({"id": "f1", "type": "FileResource", "attributes": {"name": "confidential report"}})
    store.add_entity({"id": "t1", "type": "AttackTechnique", "attributes": {"technique": "Data from Local System"}})
    store.add_entity({"id": "x1", "type": "Host", "attributes": {"name": "far host"}})
    store.add_relation("u1", "h1", "LOGGED_IN_FROM", 0.95, action="login")
    store.add_relation("h1", "f1", "ACCESSED", 0.9, action="read")
    store.add_relation("f1", "t1", "MATCHES_TECHNIQUE", 0.8, pattern="sensitive_file_access")
    store.add_relation("u1", "x1", "WEAK_LINK", 0.2, action="noise")
    return store


@pytest.mark.parametrize("question", [
    "Why is the user linked to the confidential report?",
    "Show the path to the attack technique.",
    "Which host is connected to the user?",
    "Why did the user access finance data?",
    "What is the path from the account to the file?",
])
def test_retrieval_returns_relevant_bounded_paths(question):
    result = retrieve_subgraph("u1", question, graph_fixture())
    assert "subgraph" in result and "paths" in result
    assert set(result["subgraph"].nodes) == {"u1", "h1", "f1"}
    assert result["paths"]
    assert all(path["hops"] <= 2 for path in result["paths"])
    assert result["paths"][0]["score"] >= 0


def test_retrieval_prunes_low_confidence_edges():
    result = retrieve_subgraph("u1", "Which host is connected?", graph_fixture(), confidence_threshold=0.5)
    assert "x1" not in result["subgraph"]


def test_retrieval_rejects_unknown_entity_and_invalid_bounds():
    store = graph_fixture()
    with pytest.raises(KeyError):
        retrieve_subgraph("missing", "What is it?", store)
    with pytest.raises(ValueError):
        retrieve_subgraph("u1", "What is it?", store, max_hops=-1)
