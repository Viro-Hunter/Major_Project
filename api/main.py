from fastapi import FastAPI

from api.routes.graph import router as graph_router
from api.routes.incidents import router as incidents_router

app = FastAPI(title="CyberGraphRAG API", version="0.1.0")
app.include_router(graph_router)
app.include_router(incidents_router)


@app.get("/health")
async def health_check():
    """Health check endpoint for service status."""
    return {"status": "ok"}
