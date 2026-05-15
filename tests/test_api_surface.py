"""Smoke tests for FastAPI surface (no bootstrap / no vector index required)."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_health_endpoint():
    from api.main import app

    with TestClient(app) as client:
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json().get("status") == "ok"


def test_upload_route_registered():
    from api.main import app

    routes = [r.path for r in app.routes]
    assert "/v1/risk-report/upload" in routes
