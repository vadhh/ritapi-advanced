"""
Admin and dashboard security tests.

Dashboard:
  - No token → 401 (when DASHBOARD_TOKEN is set)
  - Wrong token → 401
  - Valid token → 200
  - Missing DASHBOARD_TOKEN at startup → RuntimeError

Admin:
  - No credential → 401
  - Wrong admin secret → 401
  - Valid admin secret → 200 (token endpoint)
  - Valid SUPER_ADMIN JWT → 200
"""
import os

import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Dashboard security
# ---------------------------------------------------------------------------

def test_dashboard_no_token_returns_401(client):
    """Request without Authorization header must return 401."""
    response = client.get("/dashboard", follow_redirects=False)
    assert response.status_code == 401, (
        f"Dashboard without token must return 401, got {response.status_code}"
    )


def test_dashboard_wrong_token_returns_401(client):
    """Request with wrong token must return 401."""
    response = client.get(
        "/dashboard",
        headers={"Authorization": "Bearer wrong-token"},
        follow_redirects=False,
    )
    assert response.status_code == 401


def test_dashboard_valid_token_returns_200(client):
    """Request with correct DASHBOARD_TOKEN must succeed."""
    token = os.environ["DASHBOARD_TOKEN"]
    response = client.get(
        "/dashboard",
        headers={"Authorization": f"Bearer {token}"},
        follow_redirects=False,
    )
    assert response.status_code == 200


def test_dashboard_events_no_token_returns_401(client):
    """/dashboard/events without token must return 401."""
    response = client.get("/dashboard/events")
    assert response.status_code == 401


def test_dashboard_stats_no_token_returns_401(client):
    """/dashboard/stats without token must return 401."""
    response = client.get("/dashboard/stats")
    assert response.status_code == 401


def test_dashboard_status_no_token_returns_401(client):
    """/dashboard/status without token must return 401."""
    response = client.get("/dashboard/status")
    assert response.status_code == 401


def test_startup_fails_without_dashboard_token():
    """App startup must raise RuntimeError when DASHBOARD_TOKEN is not set."""
    import importlib

    original = os.environ.pop("DASHBOARD_TOKEN", None)
    try:
        import app.main as main_mod
        importlib.reload(main_mod)

        with pytest.raises(RuntimeError, match="DASHBOARD_TOKEN"):
            with TestClient(main_mod.app):
                pass
    finally:
        if original is not None:
            os.environ["DASHBOARD_TOKEN"] = original
        importlib.reload(main_mod)


def test_startup_fails_without_admin_secret():
    """App startup must raise RuntimeError when ADMIN_SECRET is not set."""
    import importlib

    original = os.environ.pop("ADMIN_SECRET", None)
    try:
        import app.main as main_mod
        importlib.reload(main_mod)

        with pytest.raises(RuntimeError, match="ADMIN_SECRET"):
            with TestClient(main_mod.app):
                pass
    finally:
        if original is not None:
            os.environ["ADMIN_SECRET"] = original
        importlib.reload(main_mod)


# ---------------------------------------------------------------------------
# Admin security
# ---------------------------------------------------------------------------

def test_admin_token_no_credential_returns_401(client):
    """POST /admin/token without credentials must return 401."""
    response = client.post(
        "/admin/token",
        json={"subject": "user", "role": "VIEWER"},
    )
    assert response.status_code == 401


def test_admin_token_wrong_secret_returns_401(client):
    """POST /admin/token with wrong X-Admin-Secret must return 401."""
    response = client.post(
        "/admin/token",
        json={"subject": "user", "role": "VIEWER"},
        headers={"X-Admin-Secret": "wrong-secret"},
    )
    assert response.status_code == 401


def test_admin_token_valid_secret_returns_200(client):
    """POST /admin/token with correct X-Admin-Secret must succeed."""
    response = client.post(
        "/admin/token",
        json={"subject": "test-user", "role": "VIEWER"},
        headers={"X-Admin-Secret": "test-admin-secret"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data


def test_admin_apikey_no_credential_returns_401(client):
    """POST /admin/apikey without credentials must return 401."""
    response = client.post(
        "/admin/apikey",
        json={"subject": "svc", "role": "VIEWER"},
    )
    assert response.status_code == 401


def test_admin_reload_no_credential_returns_401(client):
    """POST /admin/reload without credentials must return 401."""
    response = client.post("/admin/reload")
    assert response.status_code == 401


def test_admin_reload_valid_secret_returns_200(client):
    """POST /admin/reload with correct X-Admin-Secret must succeed."""
    response = client.post(
        "/admin/reload",
        headers={"X-Admin-Secret": "test-admin-secret"},
    )
    assert response.status_code == 200
    assert response.json()["reloaded"] is True
