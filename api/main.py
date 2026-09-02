from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes.health import router as health_router
from api.routes.graph import router as graph_router
from api.routes.incidents import router as incidents_router
from api.routes.actions import router as actions_router
from api.routes.metrics import router as metrics_router

app = FastAPI(title="CyberGraphRAG API", version="0.1.0", description="Insider Threat Detection via Graph-Augmented Retrieval")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# health at root for backwards compat
@app.get("/health")
async def health_check():
    """Health check endpoint for service status."""
    from graph.graph_store import store
    return {"status": "ok", "nodes": store.num_nodes(), "edges": store.num_edges()}

# mount routers
app.include_router(health_router)
app.include_router(graph_router)
app.include_router(incidents_router)
app.include_router(actions_router)
app.include_router(metrics_router)

# bootstrap demo graph on startup if empty
@app.on_event("startup")
async def bootstrap():
    try:
        from graph.graph_store import store
        if store.num_nodes() == 0:
            # minimal demo: create a few risky patterns
            store.add_node("d.kapoor", type="User", risk_baseline=0.3)
            store.add_node("C:\\data\\secrets.zip", type="File")
            store.add_node("192.168.1.50", type="IP")
            store.add_node("PC-ADMIN-01", type="Host")
            store.add_edge("d.kapoor", "C:\\data\\secrets.zip", relation="Exfiltration", base_confidence=0.92)
            store.add_edge("d.kapoor", "PC-ADMIN-01", relation="PrivEsc", base_confidence=0.88)
            store.add_edge("d.kapoor", "192.168.1.50", relation="ConnectedTo", base_confidence=0.75)
            print("Bootstrapped demo graph: 4 nodes, 3 edges")
    except Exception as e:
        print(f"Bootstrap failed: {e}")
