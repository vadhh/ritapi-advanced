"""
Tests for bypass endpoints (no auth required).
"""


def test_healthz_returns_ok(client):
    resp = client.get("/healthz", headers={"User-Agent": "pytest/1.0"})
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_metrics_returns_prometheus_text(client):
    resp = client.get("/metrics", headers={"User-Agent": "pytest/1.0"})
    assert resp.status_code == 200
    assert "ritapi_requests_total" in resp.text


def test_dashboard_accessible_without_token(client):
    """Dashboard is open when DASHBOARD_TOKEN env var is not set."""
    resp = client.get("/dashboard", headers={"User-Agent": "pytest/1.0"})
    assert resp.status_code == 200
    assert "RitAPI" in resp.text
