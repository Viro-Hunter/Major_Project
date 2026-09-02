from fastapi import APIRouter
from graph.graph_store import store
from action.audit_log import get_logs

router = APIRouter(tags=["metrics"])

@router.get("/metrics")
async def metrics():
    logs = get_logs(100)
    return {
        "graph_nodes": store.num_nodes(),
        "graph_edges": store.num_edges(),
        "total_incidents": len(logs),
        "format": "json"
    }
