"""
Tests for admin API — token issuance, API key management.
"""
import pytest

UA = "pytest-test-client/1.0"


def test_issue_token_with_admin_secret(client, admin_secret_headers):
    resp = client.post(
        "/admin/token",
        headers=admin_secret_headers,
        json={"subject": "new-service", "role": "OPERATOR"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["role"] == "OPERATOR"
    assert data["token_type"] == "bearer"


def test_issue_token_invalid_role(client, admin_secret_headers):
    resp = client.post(
        "/admin/token",
        headers=admin_secret_headers,
        json={"subject": "svc", "role": "GODMODE"},
    )
    assert resp.status_code == 422


def test_issue_token_without_credentials_returns_401(client):
    resp = client.post(
        "/admin/token",
        headers={"User-Agent": UA, "Content-Type": "application/json"},
        json={"subject": "svc", "role": "VIEWER"},
    )
    assert resp.status_code == 401


def test_issue_api_key_with_admin_secret(client, admin_secret_headers, redis):
    resp = client.post(
        "/admin/apikey",
        headers=admin_secret_headers,
        json={"subject": "test-svc", "role": "VIEWER"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "api_key" in data
    assert len(data["api_key"]) == 64  # 32 bytes hex
    assert data["role"] == "VIEWER"
    assert data["expires_in_seconds"] is None  # no TTL


def test_issue_api_key_with_ttl(client, admin_secret_headers, redis):
    resp = client.post(
        "/admin/apikey",
        headers=admin_secret_headers,
        json={"subject": "temp-svc", "role": "AUDITOR", "ttl_days": 7},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["expires_in_seconds"] == 7 * 86400


def test_revoke_api_key(client, admin_secret_headers, redis):
    # Issue a key
    issue_resp = client.post(
        "/admin/apikey",
        headers=admin_secret_headers,
        json={"subject": "temp", "role": "VIEWER"},
    )
    raw_key = issue_resp.json()["api_key"]

    # Revoke it
    resp = client.request(
        "DELETE",
        "/admin/apikey",
        headers=admin_secret_headers,
        json={"api_key": raw_key},
    )
    assert resp.status_code == 200
    assert resp.json()["revoked"] is True

    # Using the revoked key should now fail auth on other routes
    auth_resp = client.get(
        "/some/resource",
        headers={"X-API-Key": raw_key, "User-Agent": UA},
    )
    assert auth_resp.status_code == 401


def test_revoke_nonexistent_key_returns_404(client, admin_secret_headers):
    resp = client.request(
        "DELETE",
        "/admin/apikey",
        headers=admin_secret_headers,
        json={"api_key": "a" * 64},
    )
    assert resp.status_code == 404


def test_rotate_api_key(client, admin_secret_headers, redis):
    # Issue original key
    issue_resp = client.post(
        "/admin/apikey",
        headers=admin_secret_headers,
        json={"subject": "svc-to-rotate", "role": "OPERATOR"},
    )
    old_key = issue_resp.json()["api_key"]

    # Rotate it
    rotate_resp = client.post(
        "/admin/apikey/rotate",
        headers=admin_secret_headers,
        json={"old_api_key": old_key},
    )
    assert rotate_resp.status_code == 200
    new_key = rotate_resp.json()["api_key"]
    assert new_key != old_key

    # Old key should now be invalid
    old_resp = client.get(
        "/some/resource",
        headers={"X-API-Key": old_key, "User-Agent": UA},
    )
    assert old_resp.status_code == 401

    # New key should work
    new_resp = client.get(
        "/some/resource",
        headers={"X-API-Key": new_key, "User-Agent": UA},
    )
    assert new_resp.status_code == 404  # auth passed, route not found


def test_issue_token_with_super_admin_jwt(client, super_admin_headers, redis):
    resp = client.post(
        "/admin/token",
        headers={**super_admin_headers, "Content-Type": "application/json"},
        json={"subject": "new-user", "role": "VIEWER"},
    )
    assert resp.status_code == 200
