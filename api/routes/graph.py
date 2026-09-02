"""Graph exploration API routes — hybrid for both remote and advanced pipelines."""
from __future__ import annotations

import json
from typing import Any

import networkx as nx
from fastapi import APIRouter, HTTPException, Query

from graph.graph_store import GraphStore, store

router = APIRouter(tags=["graph"])
# keep remote singleton for compatibility (was graph_store = GraphStore())
graph_store = store


def _node_link(graph: nx.MultiDiGraph) -> dict[str, Any]:
    return json.loads(GraphStore(graph).to_json())


# Advanced pipeline routes (query param)
@router.get("/graph/subgraph")
async def get_subgraph_query(entity: str = Query(..., description="Entity ID e.g. d.kapoor"), hops: int = Query(2, ge=0, le=10)):
    """Advanced route: /graph/subgraph?entity=ID&hops=2 — returns dict nodes/edges."""
    try:
        # use dict helper for dashboard
        return store.get_subgraph_dict(entity, hops=hops)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# Remote placeholder route (path param) — keep for vis-network EntityGraph
@router.get("/graph/subgraph/{entity_id}")
async def get_graph_subgraph(entity_id: str, hops: int = Query(default=2, ge=0, le=10)) -> dict[str, Any]:
    """Return an entity neighborhood in Cytoscape/vis-compatible node-link JSON."""
    try:
        subgraph = graph_store.get_subgraph(entity_id, hops=hops)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _node_link(subgraph)


@router.get("/graph/neighbors")
async def get_neighbors_query(entity: str = Query(...)):
    """Advanced alias for neighbors via query param."""
    return {"entity": entity, "neighbors": store.neighbors(entity)}


@router.get("/graph/stats")
async def get_stats():
    return {"nodes": store.num_nodes(), "edges": store.num_edges()}
