"""
Tests for authentication enforcement.
"""


UA = "pytest-test-client/1.0"


def test_protected_route_no_auth_returns_401(client):
    resp = client.get("/some/protected/resource", headers={"User-Agent": UA})
    assert resp.status_code == 401
    data = resp.json()
    assert "Bearer" in resp.headers.get("www-authenticate", "")
    assert "error" in data


def test_protected_route_invalid_jwt_returns_401(client):
    resp = client.get(
        "/some/resource",
        headers={"Authorization": "Bearer notavalidtoken", "User-Agent": UA},
    )
    assert resp.status_code == 401


def test_protected_route_valid_jwt_passes_auth(client, auth_headers):
    # Route doesn't exist → 404 is expected (auth passed)
    resp = client.get("/some/resource", headers=auth_headers)
    assert resp.status_code == 404


def test_protected_route_invalid_api_key_returns_401(client):
    resp = client.get(
        "/some/resource",
        headers={"X-API-Key": "invalid-key-abc", "User-Agent": UA},
    )
    assert resp.status_code == 401


def test_protected_route_valid_api_key_passes_auth(client, redis):
    from app.auth.api_key_handler import issue_api_key
    raw_key = issue_api_key("test-svc", "VIEWER")
    resp = client.get(
        "/some/resource",
        headers={"X-API-Key": raw_key, "User-Agent": UA},
    )
    # Auth passed → 404 (route doesn't exist)
    assert resp.status_code == 404


def test_expired_api_key_returns_401(client, redis):
    from app.auth.api_key_handler import issue_api_key, revoke_api_key
    raw_key = issue_api_key("test-svc", "VIEWER")
    revoke_api_key(raw_key)
    resp = client.get(
        "/some/resource",
        headers={"X-API-Key": raw_key, "User-Agent": UA},
    )
    assert resp.status_code == 401


def test_bypass_healthz_no_auth(client):
    resp = client.get("/healthz", headers={"User-Agent": UA})
    assert resp.status_code == 200


def test_bypass_metrics_no_auth(client):
    resp = client.get("/metrics", headers={"User-Agent": UA})
    assert resp.status_code == 200
