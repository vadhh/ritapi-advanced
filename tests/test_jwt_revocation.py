"""Tests for L-5: JWT revocation via Redis-backed denylist."""
import time
import uuid

import pytest


# ── jwt_denylist helpers ───────────────────────────────────────────────────

def test_is_revoked_returns_false_for_unknown_jti(redis):
    """Unknown jti must not be considered revoked."""
    from app.utils.jwt_denylist import is_revoked
    assert is_revoked(str(uuid.uuid4())) is False


def test_add_and_is_revoked(redis):
    """jti added to denylist must be revoked."""
    from app.utils.jwt_denylist import add_to_denylist, is_revoked
    jti = str(uuid.uuid4())
    add_to_denylist(jti, ttl=60)
    assert is_revoked(jti) is True


def test_is_revoked_fails_open_when_redis_unavailable():
    """is_revoked must return False (fail-open) when Redis is unavailable."""
    from unittest.mock import patch
    from app.utils.redis_client import RedisClientSingleton
    from app.utils.jwt_denylist import is_revoked
    RedisClientSingleton.reset()
    with patch("app.utils.redis_client.RedisClientSingleton.get_client", return_value=None):
        assert is_revoked(str(uuid.uuid4())) is False


def test_add_to_denylist_noops_when_redis_unavailable():
    """add_to_denylist must not raise when Redis is unavailable."""
    from unittest.mock import patch
    from app.utils.redis_client import RedisClientSingleton
    from app.utils.jwt_denylist import add_to_denylist
    RedisClientSingleton.reset()
    with patch("app.utils.redis_client.RedisClientSingleton.get_client", return_value=None):
        add_to_denylist(str(uuid.uuid4()), ttl=60)  # must not raise


# ── verify_token + denylist integration ───────────────────────────────────

def test_issued_token_has_jti_claim(redis):
    """create_access_token must embed a jti claim."""
    import os
    from jose import jwt as jose_jwt
    from app.auth.jwt_handler import create_access_token
    token = create_access_token("alice", "VIEWER", "acme")
    payload = jose_jwt.decode(
        token,
        os.getenv("SECRET_KEY", "test-secret-key-32-bytes-minimum!!"),
        algorithms=["HS256"],
    )
    assert "jti" in payload
    assert len(payload["jti"]) == 36  # UUID4 string


def test_verify_token_returns_none_for_revoked_jti(redis):
    """verify_token must return None when the token's jti is in the denylist."""
    from app.auth.jwt_handler import create_access_token, verify_token
    from app.utils.jwt_denylist import add_to_denylist
    token = create_access_token("bob", "VIEWER", "acme")
    payload = verify_token(token)
    assert payload is not None, "Token should be valid before revocation"
    add_to_denylist(payload["jti"], ttl=300)
    assert verify_token(token) is None, "Token should be rejected after revocation"


def test_verify_token_still_works_for_non_revoked_token(redis):
    """verify_token must return payload for a valid, non-revoked token."""
    from app.auth.jwt_handler import create_access_token, verify_token
    token = create_access_token("carol", "VIEWER", "acme")
    assert verify_token(token) is not None


# ── POST /admin/token/revoke endpoint ─────────────────────────────────────

def test_revoke_endpoint_returns_200_with_revoked_true(client, admin_secret_headers, redis):
    """/admin/token/revoke must return {revoked: true} for a valid token."""
    from app.auth.jwt_handler import create_access_token
    token = create_access_token("dave", "VIEWER", "default")
    resp = client.post(
        "/admin/token/revoke",
        json={"token": token},
        headers=admin_secret_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("revoked") is True


def test_revoke_endpoint_makes_token_invalid(client, admin_secret_headers, redis):
    """/admin/token/revoke must cause verify_token to return None."""
    from app.auth.jwt_handler import create_access_token, verify_token
    token = create_access_token("eve", "VIEWER", "default")
    assert verify_token(token) is not None, "Token should be valid before revocation"
    client.post("/admin/token/revoke", json={"token": token}, headers=admin_secret_headers)
    assert verify_token(token) is None, "Token should be invalid after revocation"


def test_revoke_endpoint_returns_400_for_invalid_token(client, admin_secret_headers):
    """/admin/token/revoke must return 400 for a token that cannot be decoded."""
    resp = client.post(
        "/admin/token/revoke",
        json={"token": "not.a.jwt"},
        headers=admin_secret_headers,
    )
    assert resp.status_code == 400


def test_revoke_endpoint_returns_400_for_token_without_jti(client, admin_secret_headers):
    """/admin/token/revoke must return 400 when the token has no jti claim."""
    import os
    from datetime import UTC, datetime, timedelta
    from jose import jwt as jose_jwt
    secret = os.getenv("SECRET_KEY", "test-secret-key-32-bytes-minimum!!")
    token = jose_jwt.encode(
        {"sub": "legacy", "role": "VIEWER", "tid": "default", "exp": datetime.now(UTC) + timedelta(minutes=60)},
        secret,
        algorithm="HS256",
    )
    resp = client.post(
        "/admin/token/revoke",
        json={"token": token},
        headers=admin_secret_headers,
    )
    assert resp.status_code == 400
