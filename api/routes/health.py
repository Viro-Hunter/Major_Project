from fastapi import APIRouter
from graph.graph_store import store

router = APIRouter()

@router.get("/health")
async def health():
    return {"status": "ok", "nodes": store.num_nodes(), "edges": store.num_edges()}

@router.get("/ready")
async def ready():
    return {"ready": True}
