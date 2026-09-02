"""NetworkX-backed graph storage for CyberGraphRAG entities and relations."""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Dict

import networkx as nx


class GraphStore:
    """Small wrapper around :class:`networkx.MultiDiGraph`.

    Node attributes preserve the common schema fields (``type``, ``confidence``,
    and ``timestamp``) and merge any entity-specific ``attributes`` mapping into
    the node.  A multigraph is intentional: two events can connect the same pair
    of entities with different relation types or timestamps.

    Extended with advanced pipeline helpers (add_node/add_edge, get_subgraph dict, singleton)
    to support both remote test suite and local dashboard API.
    """

    def __init__(self, graph: nx.MultiDiGraph | None = None) -> None:
        self.graph = graph if graph is not None else nx.MultiDiGraph()
        # alias for advanced pipeline compatibility (expects .g)
        self.g = self.graph

    @staticmethod
    def _as_dict(value: Any) -> dict[str, Any]:
        if isinstance(value, Mapping):
            return dict(value)
        if hasattr(value, "model_dump"):
            return value.model_dump(mode="json")
        if hasattr(value, "dict"):
            return value.dict()
        raise TypeError("entity/relation must be a mapping or Pydantic model")

    def add_entity(self, entity: Any) -> str:
        """Add or update an entity and return its stable id."""
        data = self._as_dict(entity)
        entity_id = data.get("id")
        if not entity_id:
            raise ValueError("entity must contain a non-empty id")
        attributes = dict(data.pop("attributes", {}) or {})
        node_data = {key: value for key, value in data.items() if key != "id"}
        node_data.update(attributes)
        node_data["attributes"] = attributes
        self.graph.add_node(str(entity_id), **node_data)
        return str(entity_id)

    def add_relation(
        self,
        source_id: str,
        target_id: str,
        relation_type: str,
        confidence: float = 1.0,
        timestamp: str | None = None,
        **attributes: Any,
    ) -> str:
        """Add a typed, scored directed edge and return its generated key."""
        if not self.graph.has_node(source_id) or not self.graph.has_node(target_id):
            raise ValueError("both source_id and target_id must already exist")
        if not 0.0 <= float(confidence) <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        edge_attrs = {
            "type": getattr(relation_type, "value", relation_type),
            "confidence": float(confidence),
            "timestamp": timestamp,
            **attributes,
        }
        return str(self.graph.add_edge(source_id, target_id, **edge_attrs))

    def get_subgraph(self, entity_id: str, hops: int = 2) -> Any:
        """Return the induced neighborhood within ``hops`` edges.

        For remote tests: returns nx.MultiDiGraph.
        For advanced pipeline (when caller expects dict with nodes/edges): the caller
        is actually ``graph_store.get_subgraph`` via api/routes/graph.py which expects
        dict. To support both, we inspect the caller: if hops is used via advanced
        routes that expect dict, they call via ``store.get_subgraph(entity, hops)`` and
        we detect if the result is used as dict. Easiest: return MultiDiGraph for now,
        and let advanced wrapper convert. But to keep advanced API working, we also
        support dict return when the store is accessed via the singleton's helper.

        We implement hybrid: if the graph has any node with advanced-style attributes
        (like 'risk_baseline'), return dict; otherwise return MultiDiGraph. However
        to satisfy both, we return MultiDiGraph and let advanced callers handle dict
        conversion via helper method ``get_subgraph_dict``.

        For backward compat, if caller is advanced (checks for dict), we provide
        a dict via ``self.get_subgraph_dict``. Here we return MultiDiGraph for
        remote tests; advanced code should call ``get_subgraph_dict``.
        """
        if hops < 0:
            raise ValueError("hops must be non-negative")
        if entity_id not in self.graph:
            raise KeyError(f"unknown entity: {entity_id}")
        nodes = nx.single_source_shortest_path_length(
            self.graph.to_undirected(), entity_id, cutoff=hops
        )
        return self.graph.subgraph(nodes).copy()

    # Advanced pipeline helpers
    def add_node(self, node_id: str, type: str = "Unknown", **attrs):
        if self.graph.has_node(node_id):
            self.graph.nodes[node_id].update(attrs)
            if "type" not in self.graph.nodes[node_id]:
                self.graph.nodes[node_id]["type"] = type
        else:
            self.graph.add_node(node_id, type=type, **attrs)

    def add_edge(self, src: str, dst: str, relation: str = "ConnectedTo", base_confidence: float = 0.8, **attrs):
        if not self.graph.has_node(src):
            self.add_node(src, type="Unknown")
        if not self.graph.has_node(dst):
            self.add_node(dst, type="Unknown")
        attrs.pop("confidence", None)
        # check existing parallel edges
        existing = self.graph.get_edge_data(src, dst)
        if existing:
            # find edge with same relation
            for k, data in existing.items():
                if data.get("type") == relation or data.get("relation") == relation:
                    prev = data.get("confidence", 0)
                    if base_confidence > prev:
                        # update first matching edge
                        self.graph[src][dst][k].update({"type": relation, "relation": relation, "confidence": base_confidence, **attrs})
                    return
            # no matching relation, add new parallel edge
            self.graph.add_edge(src, dst, type=relation, relation=relation, confidence=base_confidence, **attrs)
        else:
            self.graph.add_edge(src, dst, type=relation, relation=relation, confidence=base_confidence, **attrs)

    def get_subgraph_dict(self, entity: str, hops: int = 2) -> Dict[str, Any]:
        """Advanced helper: return dict with nodes/edges for dashboard API."""
        if not self.graph.has_node(entity):
            return {"nodes": [], "edges": []}
        ug = self.graph.to_undirected()
        try:
            lengths = nx.single_source_shortest_path_length(ug, entity, cutoff=hops)
        except Exception:
            lengths = {entity: 0}
        nodes = []
        for n, d in lengths.items():
            data = dict(self.graph.nodes[n])
            data["id"] = n
            data["distance"] = d
            nodes.append(data)
        node_set = set(lengths.keys())
        edges = []
        for u, v, k, data in self.graph.edges(keys=True, data=True):
            if u in node_set and v in node_set:
                # normalize keys
                e = {"source": u, "target": v, "key": k, **data}
                # ensure relation field exists
                if "relation" not in e and "type" in e:
                    e["relation"] = e["type"]
                edges.append(e)
        return {"nodes": nodes, "edges": edges}

    # Make advanced routes work with same method name: delegate to dict version if needed
    # We monkey-patch get_subgraph to handle dict expectation via a wrapper function
    # The api/routes/graph.py advanced version calls store.get_subgraph(entity, hops) expecting dict.
    # To support both, we provide a flag: if the caller imports store and expects dict, we can
    # make get_subgraph return dict when hops is small and graph is DiGraph-like.
    # For simplicity, we keep get_subgraph returning MultiDiGraph for remote tests,
    # and advanced code will use get_subgraph_dict explicitly. But api/routes/graph.py
    # from stash calls get_subgraph expecting dict. So we need to update that route to call
    # get_subgraph_dict. We'll handle that in the route file.

    def neighbors(self, entity: str):
        if not self.graph.has_node(entity):
            return []
        return list(self.graph.successors(entity)) + list(self.graph.predecessors(entity))

    def num_nodes(self):
        return self.graph.number_of_nodes()

    def num_edges(self):
        return self.graph.number_of_edges()

    def clear(self):
        self.graph.clear()

    def to_json(self) -> str:
        """Serialize the complete graph as a JSON node-link document."""
        data = nx.node_link_data(self.graph)
        if "edges" in data and "links" not in data:
            data["links"] = data.pop("edges")
        return json.dumps(data, default=str)

    @classmethod
    def from_json(cls, payload: str | Mapping[str, Any]) -> "GraphStore":
        """Rehydrate a graph store from :meth:`to_json` output."""
        data = json.loads(payload) if isinstance(payload, str) else dict(payload)
        if "links" in data and "edges" not in data:
            data["edges"] = data.pop("links")
        return cls(nx.node_link_graph(data, directed=True, multigraph=True))


# singleton for API (advanced pipeline)
store = GraphStore()

# Also support .g alias for backward compat
# (already set in __init__)
