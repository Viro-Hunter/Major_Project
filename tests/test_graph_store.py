import json

import pytest

from graph.graph_store import GraphStore


def make_store() -> GraphStore:
    store = GraphStore()
    for node_id, node_type in (("u1", "User"), ("h1", "Host"), ("f1", "FileResource"), ("t1", "AttackTechnique")):
        store.add_entity({"id": node_id, "type": node_type, "attributes": {"name": node_id}})
    return store


def test_add_entity_stores_common_and_custom_attributes():
    store = GraphStore()
    assert store.add_entity({"id": "u1", "type": "User", "confidence": 0.8, "attributes": {"department": "finance"}}) == "u1"
    assert store.graph.nodes["u1"]["type"] == "User"
    assert store.graph.nodes["u1"]["department"] == "finance"
    assert store.graph.nodes["u1"]["attributes"] == {"department": "finance"}


def test_add_relation_supports_parallel_typed_edges():
    store = make_store()
    first = store.add_relation("u1", "h1", "LOGGED_IN_FROM", 0.9, "2020-01-01T08:00:00")
    second = store.add_relation("u1", "h1", "ACCESSED", 0.7, "2020-01-01T08:01:00")
    assert first != second
    assert store.graph.number_of_edges("u1", "h1") == 2
    assert {edge["type"] for edge in store.graph.get_edge_data("u1", "h1").values()} == {"LOGGED_IN_FROM", "ACCESSED"}


def test_get_subgraph_returns_nodes_within_hops():
    store = make_store()
    store.add_relation("u1", "h1", "LOGGED_IN_FROM")
    store.add_relation("h1", "f1", "ACCESSED")
    store.add_relation("f1", "t1", "MATCHES_TECHNIQUE")
    assert set(store.get_subgraph("u1", hops=2).nodes) == {"u1", "h1", "f1"}
    assert set(store.get_subgraph("u1", hops=0).nodes) == {"u1"}
    with pytest.raises(KeyError):
        store.get_subgraph("missing")


def test_to_json_round_trips():
    store = make_store()
    store.add_relation("u1", "h1", "LOGGED_IN_FROM", 0.9)
    payload = json.loads(store.to_json())
    assert {node["id"] for node in payload["nodes"]} == {"u1", "h1", "f1", "t1"}
    assert len(payload["links"]) == 1
