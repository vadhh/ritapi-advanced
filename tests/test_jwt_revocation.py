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
