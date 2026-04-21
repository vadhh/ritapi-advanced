"""Tests for L-3: REDIS_FAIL_MODE=closed behaviour."""
import os
from unittest.mock import patch

import pytest

UA = "pytest-test-client/1.0"


# ── is_fail_closed() helper ────────────────────────────────────────────────

def test_is_fail_closed_returns_false_by_default():
    from app.utils.redis_client import is_fail_closed
    with patch("app.utils.redis_client._FAIL_MODE", "open"):
        assert is_fail_closed() is False


def test_is_fail_closed_returns_true_when_set_to_closed():
    from app.utils.redis_client import is_fail_closed
    with patch("app.utils.redis_client._FAIL_MODE", "closed"):
        assert is_fail_closed() is True


def test_fail_mode_constant_is_lowercased_from_env():
    """_FAIL_MODE is normalised to lowercase at module load — env var CLOSED → constant 'closed'."""
    import app.utils.redis_client as rc_mod
    assert rc_mod._FAIL_MODE == rc_mod._FAIL_MODE.lower()


def test_is_fail_closed_rejects_unknown_values():
    from app.utils.redis_client import is_fail_closed
    with patch("app.utils.redis_client._FAIL_MODE", "strict"):
        assert is_fail_closed() is False


# ── RateLimitMiddleware ────────────────────────────────────────────────────

@pytest.fixture
def no_redis():
    """Patch RedisClientSingleton.get_client to return None."""
    with patch("app.utils.redis_client.RedisClientSingleton.get_client", return_value=None):
        yield


@pytest.fixture
def no_redis_closed():
    """Patch Redis unavailable AND fail-mode to closed."""
    with patch("app.utils.redis_client.RedisClientSingleton.get_client", return_value=None), \
         patch("app.utils.redis_client._FAIL_MODE", "closed"):
        yield


def test_rate_limit_returns_503_when_fail_closed(client, no_redis_closed):
    """Rate limiter must return 503 when Redis is down and REDIS_FAIL_MODE=closed."""
    resp = client.get("/dashboard", headers={"User-Agent": UA})
    assert resp.status_code == 503


def test_rate_limit_still_passes_through_when_fail_open(client, no_redis):
    """Rate limiter must pass through to next middleware (401 from auth) in default fail-open mode."""
    resp = client.get("/dashboard", headers={"User-Agent": UA})
    assert resp.status_code == 401


def test_rate_limit_skip_paths_bypass_fail_closed(client, no_redis_closed):
    """/healthz is a skip path — must never 503 even in fail-closed mode."""
    resp = client.get("/healthz", headers={"User-Agent": UA})
    assert resp.status_code == 200
