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


@router.get("/graph/entities")
async def list_entities(
    q: str = Query("", description="Search prefix, case-insensitive"),
    type: str = Query(None, description="Filter by node type e.g. User, Host"),
    limit: int = Query(50, ge=1, le=500, description="Max results"),
):
    """List entity IDs — used for dropdown/search. Supports ?q= & ?type= & ?limit="""
    nodes = []
    ql = q.lower().strip()
    for nid, data in store.graph.nodes(data=True):
        ntype = data.get("type", "")
        if type and ntype != type:
            continue
        if ql and ql not in nid.lower() and ql not in str(ntype).lower():
            continue
        nodes.append({"id": nid, "type": ntype, "degree": store.graph.degree(nid)})
    # sort: users first, then by degree desc, then alphabetically
    def sort_key(x):
        is_user = 0 if x["type"] == "User" else 1
        return (is_user, -x["degree"], x["id"])
    nodes.sort(key=sort_key)
    return {"entities": nodes[:limit], "total": len(nodes)}


@router.get("/graph/search")
async def search_entities(q: str = Query(..., min_length=1), limit: int = Query(20, ge=1, le=100)):
    """Alias for /graph/entities?q="""
    return await list_entities(q=q, limit=limit)


@router.get("/graph/timeline/{entity_id}")
async def get_timeline(entity_id: str, limit: int = Query(50, ge=1, le=200)):
    """Dissected timeline: User A accessed file X from PC G at time xyz → technique K.

    Returns chronological edges for entity, with human-readable story.
    """
    if entity_id not in store.graph:
        raise HTTPException(status_code=404, detail=f"unknown entity: {entity_id}")
    # Collect all edges where entity is source or target, or where entity is in the path
    # For story, take 1-hop neighborhood and sort by timestamp
    edges = []
    for src, dst, key, data in store.graph.edges(keys=True, data=True):
        if src == entity_id or dst == entity_id:
            edges.append({"source": src, "target": dst, "key": key, **data})
    # Also include 2-hop technique links via file/device
    # e.g., file → technique where file was accessed by user
    # Find files/devices accessed by user, then their technique links
    try:
        # Use get_subgraph_dict to get 2-hop neighborhood, then filter
        sub = store.get_subgraph_dict(entity_id, hops=2)
        for e in sub.get("edges", []):
            if e not in edges and (e.get("source") == entity_id or e.get("target") == entity_id):
                # already included
                continue
    except Exception:
        pass

    def story_for(edge):
        src = edge.get("source")
        dst = edge.get("target")
        typ = edge.get("type") or edge.get("relation") or "UNKNOWN"
        ts = edge.get("timestamp") or ""
        # Human story
        if typ == "LOGGED_IN_FROM" or typ == "OBSERVED_ON":
            return f"{src} observed on {dst} at {ts}"
        if typ == "ACCESSED":
            return f"{src} accessed file {dst} at {ts}"
        if typ == "LOCATED_ON":
            return f"File {src} located on {dst} at {ts}"
        if typ == "SENT_EMAIL_TO":
            return f"{src} sent email {dst} at {ts} to {edge.get('to','')}"
        if typ == "MATCHES_TECHNIQUE":
            pat = edge.get("pattern", "")
            return f"{src} matched technique {dst} ({pat}) at {ts}"
        if typ == "INDICATES":
            return f"{src} indicates {dst} at {ts}"
        # generic
        return f"{src} —{typ}→ {dst} at {ts}"

    # Sort by timestamp
    def ts_key(e):
        try:
            from datetime import datetime

            return datetime.fromisoformat(str(e.get("timestamp", "")))
        except Exception:
            return str(e.get("timestamp", ""))

    edges.sort(key=lambda e: str(e.get("timestamp", "")))

    # Add story field
    for e in edges:
        e["story"] = story_for(e)

    # Cap
    total = len(edges)
    edges = edges[:limit]

    # Also build a high-level incident summary: group by time
    summary = f"User {entity_id} has {total} events; showing {len(edges)} most recent. "
    if any(e.get("type") == "MATCHES_TECHNIQUE" for e in edges):
        summary += "Technique matches indicate insider behavior."
    else:
        summary += "No technique matches in this window — appears benign."

    return {"entity": entity_id, "total_events": total, "events": edges, "summary": summary}
