"""Incident investigation query endpoint."""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from api.routes.graph import graph_store
from graph.graph_store import GraphStore
from retrieval.graph_retriever import retrieve_subgraph
from retrieval.router import classify_query

router = APIRouter(tags=["incidents"])


class IncidentQuery(BaseModel):
    entity_id: str = Field(min_length=1)
    question: str = Field(min_length=1)


def _serialize_result(result: dict[str, Any]) -> dict[str, Any]:
    graph = result["subgraph"]
    node_link = json.loads(GraphStore(graph).to_json())
    return {**result, "subgraph": node_link}


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
