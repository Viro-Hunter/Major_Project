"""NetworkX-backed graph storage for CyberGraphRAG entities and relations."""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import networkx as nx


class GraphStore:
    """Small wrapper around :class:`networkx.MultiDiGraph`.

    Node attributes preserve the common schema fields (``type``, ``confidence``,
    and ``timestamp``) and merge any entity-specific ``attributes`` mapping into
    the node.  A multigraph is intentional: two events can connect the same pair
    of entities with different relation types or timestamps.
    """

    def __init__(self, graph: nx.MultiDiGraph | None = None) -> None:
        self.graph = graph if graph is not None else nx.MultiDiGraph()

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

    def get_subgraph(self, entity_id: str, hops: int = 2) -> nx.MultiDiGraph:
        """Return the induced directed neighborhood within ``hops`` edges."""
        if hops < 0:
            raise ValueError("hops must be non-negative")
        if entity_id not in self.graph:
            raise KeyError(f"unknown entity: {entity_id}")
        nodes = nx.single_source_shortest_path_length(
            self.graph.to_undirected(), entity_id, cutoff=hops
        )
        return self.graph.subgraph(nodes).copy()

    def to_json(self) -> str:
        """Serialize the complete graph as a JSON node-link document."""
        data = nx.node_link_data(self.graph)
        # ``edges`` is the NetworkX 3.x default; ``links`` keeps the API
        # contract stable for the dashboard and older NetworkX consumers.
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
