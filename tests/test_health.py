from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


def test_health():
    """Test the health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "nodes" in data or data == {"status": "ok"}