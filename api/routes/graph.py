"""Graph exploration API routes."""
from __future__ import annotations

import json
from typing import Any

import networkx as nx
from fastapi import APIRouter, HTTPException, Query

from graph.graph_store import GraphStore

router = APIRouter(tags=["graph"])
graph_store = GraphStore()


def _node_link(graph: nx.MultiDiGraph) -> dict[str, Any]:
    return json.loads(GraphStore(graph).to_json())


@router.get("/graph/subgraph/{entity_id}")
async def get_graph_subgraph(
    entity_id: str,
    hops: int = Query(default=2, ge=0, le=10),
) -> dict[str, Any]:
    """Return an entity neighborhood in Cytoscape/vis-compatible node-link JSON."""
    try:
        subgraph = graph_store.get_subgraph(entity_id, hops=hops)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _node_link(subgraph)
