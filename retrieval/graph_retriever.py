"""Question-aware retrieval over the NetworkX graph store — hybrid."""
from __future__ import annotations

import re
from typing import Any

import networkx as nx

from graph.confidence import latest_timestamp, path_confidence
from graph.graph_store import GraphStore, edge_record

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

    # Bounded BFS over edges that pass the confidence threshold (either direction),
    # touching only the neighbourhood instead of copying the whole graph per query.
    def _strong(data: dict[str, Any]) -> bool:
        return float(data.get("confidence", 1.0)) >= confidence_threshold

    distances: dict[str, int] = {entity_id: 0}
    frontier = [entity_id]
    for depth in range(1, max_hops + 1):
        nxt = []
        for node in frontier:
            for _, nb, data in graph.out_edges(node, data=True):
                if nb not in distances and _strong(data):
                    distances[nb] = depth
                    nxt.append(nb)
            for nb, _, data in graph.in_edges(node, data=True):
                if nb not in distances and _strong(data):
                    distances[nb] = depth
                    nxt.append(nb)
        frontier = nxt
    nodes = set(distances)
    filtered = nx.MultiDiGraph()
    filtered.add_nodes_from((n, graph.nodes[n]) for n in nodes)
    for source, target, key, data in graph.edges(nodes, keys=True, data=True):
        if target in nodes and _strong(data):
            filtered.add_edge(source, target, key=key, **data)
    subgraph = filtered
    undirected = filtered.to_undirected(as_view=True)
    shortest = nx.single_source_shortest_path(undirected, entity_id, cutoff=max_hops)
    terms = _keywords(question)
    # Week 9: decay is measured against the newest evidence in the retrieved
    # neighbourhood (see graph/confidence.py for why not wall-clock time).
    # Anchor to the focus entity's own events; other users reachable at 2 hops may
    # have much later activity that would otherwise decay this entity's evidence to ~0.
    as_of = latest_timestamp(
        data for u, v, data in subgraph.edges(data=True) if entity_id in (u, v)
    ) or latest_timestamp(data for _, _, data in subgraph.edges(data=True))
    paths: list[dict[str, Any]] = []
    for target in nodes:
        if target == entity_id:
            continue
        node_path = shortest[target]
        edge_summaries = []
        matched_terms: set[str] = set()
        for left, right in zip(node_path, node_path[1:]):
            edge = _best_edge(filtered, left, right, confidence_threshold)
            src, dst = left, right
            if edge is None:
                edge = _best_edge(filtered, right, left, confidence_threshold)
                src, dst = right, left  # report the edge in its true direction
            if edge is None:
                continue
            key, data = edge
            edge_summaries.append(edge_record(src, dst, key, data))
            matched_terms.update(terms & _keywords(_attribute_text(data)))
        for node in node_path:
            matched_terms.update(terms & _keywords(_attribute_text(dict(filtered.nodes[node]))))
        score = len(matched_terms) / max(len(terms), 1)
        confidence = path_confidence(edge_summaries, as_of=as_of) if edge_summaries else 0.0
        paths.append({
            "nodes": node_path,
            "edges": edge_summaries,
            "hops": len(node_path) - 1,
            "score": round(score, 4),
            "matched_terms": sorted(matched_terms),
            "confidence": round(confidence, 4),
        })

    # Relevance first; among equally relevant paths prefer shorter, then more trustworthy ones.
    paths.sort(key=lambda path: (-path["score"], path["hops"], -path["confidence"], path["nodes"][-1]))
    return {
        "subgraph": subgraph,
        "paths": paths,
        "max_hops": max_hops,
        "confidence_threshold": confidence_threshold,
        "as_of": as_of.isoformat() if as_of else None,
    }


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
        edges.append(edge_record(u, v, k, data))
    return {"nodes": nodes, "edges": edges}
