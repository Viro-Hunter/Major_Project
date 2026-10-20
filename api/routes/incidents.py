"""Incident investigation — hybrid for remote and advanced pipelines."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, HTTPException, Query
from pydantic import BaseModel, Field

from api.routes.graph import graph_store
from graph.graph_store import GraphStore, store
from retrieval.graph_retriever import get_entity_subgraph, retrieve_subgraph
from retrieval.router import classify_query
from retrieval.vector_retriever import semantic_search
from reasoning.verdict_generator import CONTEXT_KEY, generate_verdict
from reasoning.groundedness_checker import check_groundedness
from reasoning.confidence_scoring import attach_confidence, verdict_label
from reasoning.evidence import behavioral_risk, technique_prevalence
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


_prevalence_cache: dict[str, Any] = {"key": None, "value": {}}


def peer_prevalence(graph_store_: GraphStore | None = None) -> dict[str, float]:
    """Technique prevalence across all users, cached until the graph changes size."""
    st = graph_store_ or store
    key = (id(st.graph), st.num_nodes(), st.num_edges())
    if _prevalence_cache["key"] != key:
        _prevalence_cache["value"] = technique_prevalence(st.graph)
        _prevalence_cache["key"] = key
    return _prevalence_cache["value"]


def run_checked_verdict(subgraph: dict, entity: str, query: str) -> dict:
    """verdict_generator -> groundedness_checker -> confidence (the Week 9 pipeline tail)."""
    subgraph[CONTEXT_KEY] = {"focus": entity, "prevalence": peer_prevalence()}
    try:
        verdict = generate_verdict(subgraph, query)

        # Required groundedness gate: verify cited edges, retry up to 2x, else downgrade + [unverified]
        def regenerate(sg, allowed_edge_ids, instruction):
            return generate_verdict(sg, query, extra_instruction=instruction)

        verdict = check_groundedness(verdict, subgraph, regenerate=regenerate)
        # Week 9: propagated confidence over VERIFIED evidence paths only
        return attach_confidence(verdict, subgraph, entity)
    finally:
        subgraph.pop(CONTEXT_KEY, None)


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
    # Week 7 spec: return the full (groundedness-checked, confidence-scored) verdict as well.
    sg = get_entity_subgraph(store, payload.entity_id, hops=2, query=payload.question)
    verdict = run_checked_verdict(sg, payload.entity_id, payload.question)
    return {"route": route, "entity_id": payload.entity_id, "question": payload.question, **_serialize_result(result), "verdict": verdict}


@router.get("/incidents/queue")
async def incident_queue(limit: int = Query(25, ge=1, le=500), min_risk: float = Query(0.0, ge=0.0, le=1.0)):
    """Fast triage queue: every User scored with the evidence-path behavioural risk (no LLM call).

    Use POST /incidents/analyze on a queued entity for the full LLM + groundedness verdict.
    """
    prevalence = peer_prevalence()
    rows = []
    for nid, data in store.graph.nodes(data=True):
        if data.get("type") != "User":
            continue
        sg = store.get_subgraph_dict(nid, hops=1)
        analysis = behavioral_risk(sg, nid, prevalence)
        if analysis["risk"] < min_risk:
            continue
        rows.append({
            "entity": nid,
            "risk_score": analysis["risk"],
            "verdict_label": verdict_label(analysis["risk"]),
            "propagated_confidence": analysis["propagated_confidence"],
            "confidence_pct": round(100 * analysis["propagated_confidence"], 1),
            "techniques": [c["technique_id"] for c in analysis["techniques"]],
            "evidence_paths": len(analysis["paths"]),
            "decision": should_auto_execute(analysis["risk"]),
        })
    rows.sort(key=lambda r: (-r["risk_score"], -r["propagated_confidence"], r["entity"]))
    return {"incidents": rows[:limit], "total_users": len(rows), "mode": "behavioural-triage"}


# Advanced route
@router.post("/incidents/analyze")
async def analyze(req: AnalyzeRequest):
    qtype = classify_query(req.query)
    subgraph = get_entity_subgraph(store, req.entity, hops=req.hops or 2, query=req.query)
    if qtype in ("lookup", "hybrid"):
        ranked = semantic_search(req.query, subgraph, top_k=10)
        subgraph["_ranked"] = ranked

    # verdict -> groundedness gate (retry x2, else downgrade + [unverified]) -> confidence
    verdict = run_checked_verdict(subgraph, req.entity, req.query)
    grounded = verdict["groundedness"]["status"] != "unverified"

    # Gate and audit log now see the checked (possibly downgraded) verdict
    decision = should_auto_execute(verdict["risk_score"])
    log_action(
        "analyze",
        verdict,
        executed_by="api",
        status=decision,
        details={
            "entity": req.entity,
            "query": req.query,
            "qtype": qtype,
            "groundedness": verdict["groundedness"],
            "confidence_pct": verdict.get("confidence_pct"),
            "verdict_label": verdict.get("verdict_label"),
        },
    )
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
