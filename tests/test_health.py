"""Basic health-endpoint tests for Phase 0."""

from fastapi.testclient import TestClient

from app.main import create_app


def test_health_returns_ok():
    app = create_app()
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["app"] == "AgentWarden"
    assert "version" in data
    assert data["db"] == "ok"


def test_health_has_expected_keys():
    app = create_app()
    client = TestClient(app)
    data = client.get("/health").json()
    for key in ("status", "app", "version", "db", "ledger_head_seq"):
        assert key in data
