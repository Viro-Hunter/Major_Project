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
        from pathlib import Path
        from graph.graph_store import GraphStore, store

        if store.num_nodes() != 0:
            return

        # 1) Try pre-built 15% graph (robust Week 12 path: 10-20% sample, ~80k rows, many entities)
        prebuilt = Path(__file__).resolve().parents[1] / "data" / "cert_graph_15pct.json"
        if prebuilt.exists():
            try:
                loaded = GraphStore.from_json(prebuilt.read_text())
                store.graph = loaded.graph
                store.g = store.graph
                print(f"Loaded prebuilt 15% graph from {prebuilt}: {store.num_nodes()} nodes, {store.num_edges()} edges")
                # Enrich demo entities so dashboard default AAM0658/d.kapoor always has visible subgraph
                for nid, ntype in [("d.kapoor", "User"), ("AAM0658", "User")]:
                    if not store.graph.has_node(nid):
                        store.add_node(nid, type=ntype)
                # Ensure AAM0658 has at least 3 edges for vis-network demo (if isolated, add demo cluster)
                if store.graph.degree("AAM0658") < 2:
                    for nid, ntype in [("PC-001", "Host"), ("confidential_report.pdf", "FileResource"), ("T1078", "AttackTechnique")]:
                        if not store.graph.has_node(nid):
                            store.add_node(nid, type=ntype)
                    for src, dst, rel in [("AAM0658", "PC-001", "LOGGED_IN_FROM"), ("AAM0658", "confidential_report.pdf", "ACCESSED"), ("AAM0658", "T1078", "MATCHES_TECHNIQUE")]:
                        if not store.graph.has_edge(src, dst):
                            store.add_edge(src, dst, relation=rel, base_confidence=0.9)
                if store.graph.degree("d.kapoor") < 2:
                    for nid, ntype in [("C:\\data\\secrets.zip", "File"), ("PC-ADMIN-01", "Host")]:
                        if not store.graph.has_node(nid):
                            store.add_node(nid, type=ntype)
                    for src, dst, rel in [("d.kapoor", "C:\\data\\secrets.zip", "Exfiltration"), ("d.kapoor", "PC-ADMIN-01", "PrivEsc")]:
                        if not store.graph.has_edge(src, dst):
                            store.add_edge(src, dst, relation=rel, base_confidence=0.9)
                print(f"Enriched demo entities: {store.num_nodes()} nodes, {store.num_edges()} edges")
                return
            except Exception as e:
                print(f"Failed to load prebuilt graph: {e}")

        # 2) Try live build from demo CSVs (15% sample, ~50-80k rows) — may take 2-4s
        try:
            import os

            ratio = os.getenv("CERT_SAMPLE_RATIO")
            if ratio is not None:
                # explicit env gate: 0 = disable large build, keep minimal
                if float(ratio) == 0:
                    raise RuntimeError("CERT_SAMPLE_RATIO=0 — skip large build")
            # Lazy import to avoid heavy import at startup
            from scripts.build_graph_from_cert import build_graph

            # 15% ~ 200 users * 80 rows each = ~80k rows across 5 logs
            # Tuned to stay under 5s on 8GB RAM; Week 12 will use 100% via same builder
            users = int(os.getenv("CERT_USERS", "200"))
            rows = int(os.getenv("CERT_ROWS_PER_USER", "80"))
            print(f"Building 15% demo graph from CERT (users={users}, rows/user={rows})...")
            built = build_graph(user_limit=users, rows_per_user=rows)
            store.graph = built.graph
            store.g = store.graph
            print(f"Built 15% graph: {store.num_nodes()} nodes, {store.num_edges()} edges — Week 12 will scale to 100% via same builder")
            # Ensure at least the two demo entities exist for dashboard
            for nid, ntype in [("d.kapoor", "User"), ("AAM0658", "User")]:
                if not store.graph.has_node(nid):
                    store.add_node(nid, type=ntype)
            return
        except Exception as e:
            print(f"Large build skipped/failed ({e}), falling back to minimal 8-node demo")

        # 3) Fallback minimal (always works offline)
        store.add_node("d.kapoor", type="User", risk_baseline=0.3)
        store.add_node("C:\\data\\secrets.zip", type="File")
        store.add_node("192.168.1.50", type="IP")
        store.add_node("PC-ADMIN-01", type="Host")
        store.add_edge("d.kapoor", "C:\\data\\secrets.zip", relation="Exfiltration", base_confidence=0.92)
        store.add_edge("d.kapoor", "PC-ADMIN-01", relation="PrivEsc", base_confidence=0.88)
        store.add_edge("d.kapoor", "192.168.1.50", relation="ConnectedTo", base_confidence=0.75)
        store.add_node("AAM0658", type="User")
        store.add_node("PC-001", type="Host")
        store.add_node("confidential_report.pdf", type="FileResource")
        store.add_node("T1078", type="AttackTechnique")
        store.add_edge("AAM0658", "PC-001", relation="LOGGED_IN_FROM", base_confidence=0.9)
        store.add_edge("AAM0658", "confidential_report.pdf", relation="ACCESSED", base_confidence=0.85)
        store.add_edge("AAM0658", "T1078", relation="MATCHES_TECHNIQUE", base_confidence=0.88)
        store.add_edge("PC-001", "confidential_report.pdf", relation="ACCESSED", base_confidence=0.7)
        print("Bootstrapped minimal demo graph: 8 nodes, 7 edges (d.kapoor + AAM0658)")
    except Exception as e:
        print(f"Bootstrap failed: {e}")
