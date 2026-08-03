from fastapi import FastAPI

app = FastAPI(title="CyberGraphRAG API", version="0.1.0")


@app.get("/health")
async def health_check():
    """Health check endpoint for service status."""
    return {"status": "ok"}