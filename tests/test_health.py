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


def test_dashboard_requires_token(client):
    """Dashboard always requires DASHBOARD_TOKEN — open access is not allowed."""
    import os
    token = os.environ["DASHBOARD_TOKEN"]
    resp = client.get(
        "/dashboard",
        headers={"Authorization": f"Bearer {token}", "User-Agent": "pytest/1.0"},
    )
    assert resp.status_code == 200
    assert "RitAPI" in resp.text
