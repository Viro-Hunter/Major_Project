"""Question-aware retrieval over the NetworkX graph store — hybrid."""
from __future__ import annotations

import re
from typing import Any

import networkx as nx

from graph.graph_store import GraphStore

DEFAULT_MAX_HOPS = 2
DEFAULT_CONFIDENCE_THRESHOLD = 0.5
_STOPWORDS = {"the", "a", "an", "is", "are", "was", "were", "to", "of", "and", "or", "in", "on", "for", "did", "what", "when", "why", "how", "which", "who"}


def _keywords(text: str) -> set[str]:
    return {word for word in re.findall(r"[a-z0-9_]+", text.lower()) if word not in _STOPWORDS and len(word) > 2}


def _attribute_text(attributes: dict[str, Any]) -> str:
    return " ".join(str(value) for value in attributes.values())


def _best_edge(graph: nx.MultiDiGraph, source: str, target: str, threshold: float) -> tuple[Any, dict[str, Any]] | None:
    candidates = [(key, data) for key, data in graph.get_edge_data(source, target, default={}).items() if float(data.get("confidence", 1.0)) >= threshold]
    return max(candidates, key=lambda item: float(item[1].get("confidence", 1.0)), default=None)


def retrieve_subgraph(
    entity_id: str,
    question: str,
    graph_store: GraphStore,
    max_hops: int = DEFAULT_MAX_HOPS,
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
) -> dict[str, Any]:
    """Retrieve a confidence-pruned neighborhood and rank root-to-node paths."""
    if max_hops < 0:
        raise ValueError("max_hops must be non-negative")
    if not 0.0 <= confidence_threshold <= 1.0:
        raise ValueError("confidence_threshold must be between 0 and 1")
    graph = graph_store.graph
    if entity_id not in graph:
        raise KeyError(f"unknown entity: {entity_id}")

    filtered = nx.MultiDiGraph()
    filtered.add_nodes_from(graph.nodes(data=True))
    for source, target, key, data in graph.edges(keys=True, data=True):
        if float(data.get("confidence", 1.0)) >= confidence_threshold:
            filtered.add_edge(source, target, key=key, **data)

    undirected = filtered.to_undirected()
    distances = nx.single_source_shortest_path_length(undirected, entity_id, cutoff=max_hops)
    nodes = set(distances)
    subgraph = filtered.subgraph(nodes).copy()
    terms = _keywords(question)
    paths: list[dict[str, Any]] = []
    for target in nodes:
        if target == entity_id:
            continue
        node_path = nx.shortest_path(undirected, entity_id, target)
        edge_summaries = []
        matched_terms: set[str] = set()
        for left, right in zip(node_path, node_path[1:]):
            edge = _best_edge(filtered, left, right, confidence_threshold) or _best_edge(filtered, right, left, confidence_threshold)
            if edge is None:
                continue
            key, data = edge
            edge_summaries.append({"source": left, "target": right, "key": key, **data})
            matched_terms.update(terms & _keywords(_attribute_text(data)))
        for node in node_path:
            matched_terms.update(terms & _keywords(_attribute_text(dict(filtered.nodes[node]))))
        score = len(matched_terms) / max(len(terms), 1)
        paths.append({"nodes": node_path, "edges": edge_summaries, "hops": len(node_path) - 1, "score": round(score, 4), "matched_terms": sorted(matched_terms)})

    paths.sort(key=lambda path: (-path["score"], path["hops"], path["nodes"][-1]))
    return {"subgraph": subgraph, "paths": paths, "max_hops": max_hops, "confidence_threshold": confidence_threshold}


# Advanced pipeline helper
def get_entity_subgraph(store: GraphStore, entity: str, hops: int = 2, query: str = ""):
    """Advanced helper: return dict nodes/edges for dashboard (compatible with store.get_subgraph_dict)."""
    # Prefer the store's dict helper if available
    if hasattr(store, "get_subgraph_dict"):
        return store.get_subgraph_dict(entity, hops=hops)
    # Fallback: use retrieve_subgraph with empty question and convert
    if entity not in store.graph:
        return {"nodes": [], "edges": []}
    result = retrieve_subgraph(entity, query or "", store, max_hops=hops)
    # result["subgraph"] is MultiDiGraph, convert to dict
    g = result["subgraph"]
    nodes = [{"id": n, **dict(g.nodes[n])} for n in g.nodes]
    edges = []
    for u, v, k, data in g.edges(keys=True, data=True):
        e = {"source": u, "target": v, "key": k, **data}
        if "relation" not in e and "type" in e:
            e["relation"] = e["type"]
        edges.append(e)
    return {"nodes": nodes, "edges": edges}
