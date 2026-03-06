"""
Redis failure / fail-open tests.

Verifies that when Redis is unavailable:
  - Rate limiting fails open (requests pass through, not 500)
  - Bot detection fails open
  - Exfiltration detection fails open
  - JWT auth still works (no Redis dependency)
  - API key auth returns 401 (cannot verify without Redis — correct behaviour)
  - mark_failed() + cooldown prevents thundering herd reconnection attempts

Uses unittest.mock.patch to simulate Redis being unavailable without
actually stopping the Redis server.
"""
from unittest.mock import patch

import pytest

UA = "pytest-test-client/1.0"


@pytest.fixture
def no_redis(redis):
    """Patch RedisClientSingleton.get_client to return None for the test duration."""
    with patch(
        "app.utils.redis_client.RedisClientSingleton.get_client",
        return_value=None,
    ):
        yield


# ---------------------------------------------------------------------------
# Rate limiting — fail-open
# ---------------------------------------------------------------------------

def test_rate_limit_fails_open_when_redis_unavailable(client, no_redis, auth_headers):
    """Rate limiter should let requests through when Redis is down, not error."""
    resp = client.get("/dashboard", headers=auth_headers)
    assert resp.status_code != 500
    assert resp.status_code != 429  # no Redis → no rate limit enforcement


# ---------------------------------------------------------------------------
# Bot detection — fail-open
# ---------------------------------------------------------------------------

def test_bot_detection_fails_open_when_redis_unavailable(client, no_redis):
    """Bot detection should pass requests through when Redis is down."""
    resp = client.get(
        "/healthz",
        headers={"X-Forwarded-For": "10.99.fail.1", "User-Agent": UA},
    )
    assert resp.status_code == 200  # healthz still works


def test_bot_detection_no_block_without_redis(client, no_redis):
    """Even suspicious UA should not be blocked when Redis is unavailable."""
    # Bot detection can't accumulate risk without Redis → no block
    resp = client.get(
        "/healthz",
        headers={"X-Forwarded-For": "10.99.fail.2", "User-Agent": ""},
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Exfiltration detection — fail-open
# ---------------------------------------------------------------------------

def test_exfiltration_fails_open_when_redis_unavailable(client, no_redis, auth_headers):
    """Exfiltration detection should not block when Redis is down."""
    for _ in range(60):  # exceed bulk_access threshold
        resp = client.get(
            "/healthz",
            headers={**auth_headers, "X-Forwarded-For": "10.99.fail.3"},
        )
    # Should never get 403 from exfiltration without Redis
    assert resp.status_code != 403


# ---------------------------------------------------------------------------
# JWT auth — works without Redis
# ---------------------------------------------------------------------------

def test_jwt_auth_works_without_redis(client, no_redis, auth_headers):
    """JWT verification is stateless and does not need Redis."""
    resp = client.get("/api/resource", headers=auth_headers)
    # 404 = auth passed, route doesn't exist. Not 401 or 500.
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# API key auth — 401 without Redis (correct: cannot verify)
# ---------------------------------------------------------------------------

def test_api_key_auth_returns_401_without_redis(client, no_redis):
    """API key validation requires Redis; 401 is the correct fail behaviour."""
    resp = client.get(
        "/api/resource",
        headers={"X-API-Key": "a" * 64, "User-Agent": UA},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# mark_failed + cooldown prevents reconnection flood
# ---------------------------------------------------------------------------

def test_mark_failed_sets_last_failure_timestamp():
    """mark_failed() sets _last_failure so subsequent calls respect cooldown."""
    from app.utils.redis_client import RedisClientSingleton

    original_instance = RedisClientSingleton._instance
    original_failure = RedisClientSingleton._last_failure

    try:
        RedisClientSingleton.mark_failed()
        assert RedisClientSingleton._instance is None
        assert RedisClientSingleton._last_failure > 0
        # Within cooldown window — get_client returns None without retrying
        result = RedisClientSingleton.get_client()
        assert result is None
    finally:
        # Restore state so other tests are not affected
        RedisClientSingleton._instance = original_instance
        RedisClientSingleton._last_failure = original_failure
        RedisClientSingleton._failure_logged = False


def test_reset_bypasses_cooldown(redis):
    """reset() clears cooldown so get_client() reconnects immediately."""
    from app.utils.redis_client import RedisClientSingleton
    RedisClientSingleton.reset()
    client = RedisClientSingleton.get_client()
    assert client is not None  # reconnected


# ---------------------------------------------------------------------------
# No 500s on any endpoint when Redis is down
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/healthz",
    "/metrics",
    "/dashboard",
    "/dashboard/status",
])
def test_no_500_on_bypass_paths_without_redis(client, no_redis, path):
    resp = client.get(path, headers={"User-Agent": UA})
    assert resp.status_code != 500
