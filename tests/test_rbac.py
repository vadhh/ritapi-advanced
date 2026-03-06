"""
RBAC enforcement tests.

Verifies that role hierarchy is enforced on admin endpoints:
  - VIEWER cannot issue tokens or API keys
  - AUDITOR cannot issue tokens or API keys
  - OPERATOR cannot issue tokens or API keys
  - ADMIN can issue API keys but NOT tokens (SUPER_ADMIN only)
  - SUPER_ADMIN can do everything
  - Missing role claim is rejected

Tests use admin endpoints since they are the only RBAC-protected routes.
"""
from datetime import UTC

import pytest

from app.auth.jwt_handler import create_access_token

UA = "pytest-test-client/1.0"
CT = "application/json"


def _headers(role: str) -> dict:
    token = create_access_token(f"test-{role.lower()}", role)
    return {
        "Authorization": f"Bearer {token}",
        "User-Agent": UA,
        "Content-Type": CT,
    }


# ---------------------------------------------------------------------------
# POST /admin/token — requires SUPER_ADMIN
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("role", ["VIEWER", "AUDITOR", "OPERATOR", "ADMIN"])
def test_issue_token_blocked_for_insufficient_role(client, role):
    resp = client.post(
        "/admin/token",
        headers=_headers(role),
        json={"subject": "svc", "role": "VIEWER"},
    )
    assert resp.status_code in (401, 403), \
        f"Role {role} should be rejected for /admin/token, got {resp.status_code}"


def test_issue_token_allowed_for_super_admin(client, redis):
    resp = client.post(
        "/admin/token",
        headers=_headers("SUPER_ADMIN"),
        json={"subject": "svc", "role": "VIEWER"},
    )
    assert resp.status_code == 200
    assert "access_token" in resp.json()


# ---------------------------------------------------------------------------
# POST /admin/apikey — requires ADMIN
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("role", ["VIEWER", "AUDITOR", "OPERATOR"])
def test_issue_apikey_blocked_for_insufficient_role(client, role):
    resp = client.post(
        "/admin/apikey",
        headers=_headers(role),
        json={"subject": "svc", "role": "VIEWER"},
    )
    assert resp.status_code in (401, 403), \
        f"Role {role} should be rejected for /admin/apikey, got {resp.status_code}"


@pytest.mark.parametrize("role", ["ADMIN", "SUPER_ADMIN"])
def test_issue_apikey_allowed_for_admin_plus(client, redis, role):
    resp = client.post(
        "/admin/apikey",
        headers=_headers(role),
        json={"subject": "svc", "role": "VIEWER"},
    )
    assert resp.status_code == 200
    assert "api_key" in resp.json()


# ---------------------------------------------------------------------------
# DELETE /admin/apikey — requires ADMIN
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("role", ["VIEWER", "AUDITOR", "OPERATOR"])
def test_revoke_apikey_blocked_for_insufficient_role(client, role):
    resp = client.request(
        "DELETE",
        "/admin/apikey",
        headers=_headers(role),
        json={"api_key": "a" * 64},
    )
    assert resp.status_code in (401, 403)


def test_revoke_apikey_allowed_for_admin(client, redis):
    from app.auth.api_key_handler import issue_api_key
    raw_key = issue_api_key("test-revoke-rbac", "VIEWER")
    resp = client.request(
        "DELETE",
        "/admin/apikey",
        headers=_headers("ADMIN"),
        json={"api_key": raw_key},
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Role hierarchy: SUPER_ADMIN > ADMIN > OPERATOR > AUDITOR > VIEWER
# ---------------------------------------------------------------------------

def test_role_hierarchy_super_admin_can_do_admin_operations(client, redis):
    """SUPER_ADMIN has all ADMIN permissions too."""
    resp = client.post(
        "/admin/apikey",
        headers=_headers("SUPER_ADMIN"),
        json={"subject": "svc", "role": "AUDITOR"},
    )
    assert resp.status_code == 200


def test_missing_role_claim_rejected(client):
    """JWT with no role claim is rejected by admin endpoints."""
    from datetime import datetime, timedelta

    from jose import jwt as jose_jwt

    from app.auth.jwt_handler import ALGORITHM, SECRET_KEY
    # Issue a token without a role field
    payload = {
        "sub": "no-role-user",
        "exp": datetime.now(UTC) + timedelta(minutes=60),
    }
    token = jose_jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    resp = client.post(
        "/admin/token",
        headers={
            "Authorization": f"Bearer {token}",
            "User-Agent": UA,
            "Content-Type": CT,
        },
        json={"subject": "svc", "role": "VIEWER"},
    )
    assert resp.status_code in (401, 403)


def test_invalid_role_string_rejected(client):
    """JWT with an unrecognised role string is rejected."""
    from datetime import datetime, timedelta

    from jose import jwt as jose_jwt

    from app.auth.jwt_handler import ALGORITHM, SECRET_KEY
    payload = {
        "sub": "bad-role-user",
        "role": "GOD_MODE",
        "exp": datetime.now(UTC) + timedelta(minutes=60),
    }
    token = jose_jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    resp = client.post(
        "/admin/token",
        headers={
            "Authorization": f"Bearer {token}",
            "User-Agent": UA,
            "Content-Type": CT,
        },
        json={"subject": "svc", "role": "VIEWER"},
    )
    assert resp.status_code in (401, 403)
