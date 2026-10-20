import json
from pathlib import Path

from fastapi import APIRouter, HTTPException

from action.audit_log import get_logs
from graph.graph_store import store

router = APIRouter(tags=["metrics"])
BENCHMARK = Path(__file__).resolve().parents[2] / "evaluation" / "results" / "benchmark.json"


@router.get("/metrics")
async def metrics():
    logs = get_logs(100)
    return {
        "graph_nodes": store.num_nodes(),
        "graph_edges": store.num_edges(),
        "total_incidents": len(logs),
        "format": "json"
    }


@router.get("/metrics/benchmark")
async def benchmark():
    """Latest evaluation/run_benchmark.py output (the five Objective-5 metrics)."""
    if not BENCHMARK.exists():
        raise HTTPException(404, "No benchmark yet. Run: python evaluation/run_benchmark.py")
    return json.loads(BENCHMARK.read_text())
