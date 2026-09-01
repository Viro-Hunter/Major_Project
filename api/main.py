from fastapi import FastAPI

<<<<<<< HEAD
from api.routes.graph import router as graph_router

app = FastAPI(title="CyberGraphRAG API", version="0.1.0")
app.include_router(graph_router)
=======
app = FastAPI(title="CyberGraphRAG API", version="0.1.0")
>>>>>>> b41879e3bad66a46af7fd56c38399276053be697


@app.get("/health")
async def health_check():
    """Health check endpoint for service status."""
<<<<<<< HEAD
    return {"status": "ok"}
=======
    return {"status": "ok"}
>>>>>>> b41879e3bad66a46af7fd56c38399276053be697
