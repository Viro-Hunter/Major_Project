"""Incident investigation — hybrid for remote and advanced pipelines."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, HTTPException
from pydantic import BaseModel, Field

from api.routes.graph import graph_store
from graph.graph_store import GraphStore, store
from retrieval.graph_retriever import get_entity_subgraph, retrieve_subgraph
from retrieval.router import classify_query
from retrieval.vector_retriever import semantic_search
from reasoning.verdict_generator import generate_verdict
from reasoning.groundedness_checker import verify_verdict
from action.gate import should_auto_execute
from action.audit_log import log_action

router = APIRouter(tags=["incidents"])


class IncidentQuery(BaseModel):
    entity_id: str = Field(min_length=1)
    question: str = Field(min_length=1)


class AnalyzeRequest(BaseModel):
    entity: str
    query: str
    threshold: Optional[float] = 0.7
    hops: Optional[int] = 2


def _serialize_result(result: dict[str, Any]) -> dict[str, Any]:
    graph = result["subgraph"]
    # handle both dict and MultiDiGraph
    if isinstance(graph, dict):
        return result
    node_link = json.loads(GraphStore(graph).to_json())
    return {**result, "subgraph": node_link}


# Remote route
@router.post("/incidents/query")
async def query_incident(payload: IncidentQuery) -> dict[str, Any]:
    route = classify_query(payload.question)
    try:
        result = retrieve_subgraph(
            payload.entity_id,
            payload.question,
            graph_store,
            max_hops=2 if route == "structural" else 1,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"route": route, "entity_id": payload.entity_id, "question": payload.question, **_serialize_result(result)}


# Advanced route
@router.post("/incidents/analyze")
async def analyze(req: AnalyzeRequest):
    qtype = classify_query(req.query)
    subgraph = get_entity_subgraph(store, req.entity, hops=req.hops or 2, query=req.query)
    if qtype in ("lookup", "hybrid"):
        ranked = semantic_search(req.query, subgraph, top_k=10)
        subgraph["_ranked"] = ranked
    verdict = generate_verdict(subgraph, req.query)
    grounded = verify_verdict(verdict, subgraph)
    decision = should_auto_execute(verdict["risk_score"])
    log_action("analyze", verdict, executed_by="api", status=decision, details={"entity": req.entity, "query": req.query, "qtype": qtype})
    return {
        "entity": req.entity,
        "query": req.query,
        "query_type": qtype,
        "subgraph": subgraph,
        "verdict": verdict,
        "grounded": grounded,
        "decision": decision,
        "graph_stats": {"nodes": store.num_nodes(), "edges": store.num_edges()},
    }


@router.post("/incidents/ingest")
async def ingest(events: List[Dict[str, Any]] = Body(..., description="List of event dicts")):
    from ingestion.schemas import Event
    from graph.updater import incremental_insert

    ev_objs = []
    for e in events:
        try:
            if "event_id" not in e:
                import uuid

                e["event_id"] = str(uuid.uuid4())
            if "timestamp" not in e:
                from datetime import datetime

                e["timestamp"] = datetime.utcnow().isoformat()
            ev_objs.append(Event(**e))
        except Exception:
            continue
    incremental_insert(store, ev_objs)
    return {"ingested": len(ev_objs), "nodes": store.num_nodes(), "edges": store.num_edges()}
