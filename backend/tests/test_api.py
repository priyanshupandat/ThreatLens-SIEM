import os
os.environ["DATABASE_URL"] = "sqlite:///./test_siem.db"
os.environ["API_KEY"] = "test-key"

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)
HEADERS = {"X-API-Key": "test-key"}

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_ingest_requires_key():
    response = client.post("/api/v1/ingest", json={"event_type": "test"})
    assert response.status_code == 401

def test_ingest_event_and_detection():
    payload = {
        "tenant_id": "test-org",
        "source": "test",
        "hostname": "lab-host",
        "event_type": "failed_login",
        "severity": "high",
        "message": "Failed login for admin",
        "raw": {"event_id": 4625}
    }
    response = client.post("/api/v1/ingest", json=payload, headers=HEADERS)
    assert response.status_code == 201
    assert response.json()["tenant_id"] == "test-org"
    alerts = client.get("/api/v1/alerts?tenant_id=test-org")
    assert alerts.status_code == 200
    assert len(alerts.json()) >= 1
