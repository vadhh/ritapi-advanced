"""
Redis bug regression tests.

1. No double write: rate_limit must not call both SET NX and SETEX on the same key.
2. Pipeline fallback removed: exfiltration _incrby must use a single clean pipeline.
3. Exfiltration _incr must use pipeline (no two-step INCR + conditional EXPIRE).
"""
import inspect

import pytest


# ---------------------------------------------------------------------------
# Bug 1: Double write in rate_limit.py
# ---------------------------------------------------------------------------

def test_rate_limit_no_setex_after_set_nx():
    """rate_limit must NOT call setex after set(..., nx=True) — that resets the TTL.

    The correct pattern: redis.set(key, value, ex=ttl, nx=True) — one atomic op.
    """
    import app.middlewares.rate_limit as rl_mod

    src = inspect.getsource(rl_mod)
    assert "setex" not in src, (
        "rate_limit still calls redis.setex() — double write bug. "
        "redis.set(key, '1', ex=window, nx=True) already sets the TTL atomically."
    )


def test_rate_limit_set_nx_is_used_for_log_dedup():
    """rate_limit must use redis.set(..., nx=True) for log-dedup, not EXISTS+SET."""
    import app.middlewares.rate_limit as rl_mod

    src = inspect.getsource(rl_mod)
    assert "nx=True" in src, (
        "rate_limit must use SET NX EX for log-dedup deduplication"
    )


# ---------------------------------------------------------------------------
# Bug 2: Pipeline fallback in exfiltration _incrby
# ---------------------------------------------------------------------------

def test_exfil_incrby_no_try_except_fallback():
    """_incrby must not have a try/except fallback that re-executes the pipeline.

    The old fallback called pipe.execute() twice — once in the try block and once
    in the except — corrupting the count on Redis < 7.  Since Redis 7+ is required,
    the fallback is removed.
    """
    from app.middlewares.exfiltration_detection import _incrby

    src = inspect.getsource(_incrby)
    assert "except" not in src, (
        "_incrby still has a try/except fallback — this causes double execution "
        "of the pipeline on errors. Remove the fallback (Redis 7+ required)."
    )


def test_exfil_incrby_uses_pipeline():
    """_incrby must use a single atomic pipeline (INCRBY + EXPIRE NX)."""
    from unittest.mock import MagicMock

    from app.middlewares.exfiltration_detection import _incrby

    pipe_mock = MagicMock()
    pipe_mock.execute.return_value = [2048, True]

    redis_mock = MagicMock()
    redis_mock.pipeline.return_value = pipe_mock

    result = _incrby(redis_mock, "test:vol:key", 1024, 300)

    redis_mock.pipeline.assert_called_once()
    pipe_mock.incrby.assert_called_once_with("test:vol:key", 1024)
    pipe_mock.expire.assert_called_once()
    expire_args = pipe_mock.expire.call_args
    assert expire_args[1].get("nx") is True, "EXPIRE must use nx=True to avoid resetting TTL"
    pipe_mock.execute.assert_called_once()
    assert result == 2048


# ---------------------------------------------------------------------------
# Bug 3: Exfiltration _incr race condition
# ---------------------------------------------------------------------------

def test_exfil_incr_uses_pipeline():
    """_incr must use a pipeline (INCR + EXPIRE NX) not two separate round-trips."""
    from unittest.mock import MagicMock

    from app.middlewares.exfiltration_detection import _incr

    pipe_mock = MagicMock()
    pipe_mock.execute.return_value = [1, True]

    redis_mock = MagicMock()
    redis_mock.pipeline.return_value = pipe_mock

    result = _incr(redis_mock, "test:incr:key", 60)

    redis_mock.pipeline.assert_called_once()
    pipe_mock.incr.assert_called_once_with("test:incr:key")
    pipe_mock.expire.assert_called_once()
    assert pipe_mock.expire.call_args[1].get("nx") is True
    assert result == 1


def test_exfil_incr_no_conditional_expire():
    """_incr must not use if-conditional expire — that's a race condition."""
    from app.middlewares.exfiltration_detection import _incr

    src = inspect.getsource(_incr)
    assert "if val == 1" not in src and "if count == 1" not in src, (
        "_incr still uses conditional expire — race condition. "
        "Use pipeline with EXPIRE NX instead."
    )


def test_no_double_counting_with_pipeline(redis):
    """_incrby increments correctly across multiple calls — no double counting."""
    from app.middlewares.exfiltration_detection import _incrby

    key = "test:redis_bugs:incrby:no_double_count"
    v1 = _incrby(redis, key, 100, 60)
    v2 = _incrby(redis, key, 100, 60)
    v3 = _incrby(redis, key, 100, 60)

    assert v1 == 100, f"First incrby should be 100, got {v1}"
    assert v2 == 200, f"Second incrby should be 200, got {v2}"
    assert v3 == 300, f"Third incrby should be 300, got {v3}"


def test_ttl_preserved_on_second_write(redis):
    """_incrby must not reset TTL on second write (nx=True contract)."""
    import time

    from app.middlewares.exfiltration_detection import _incrby

    key = "test:redis_bugs:incrby:ttl_preserved"
    _incrby(redis, key, 500, 60)
    ttl_after_first = redis.ttl(key)
    assert ttl_after_first > 0, "TTL must be set on first write"

    time.sleep(0.05)

    _incrby(redis, key, 500, 60)
    ttl_after_second = redis.ttl(key)
    assert ttl_after_second > 0, "TTL must remain set after second write"
    # TTL should not be reset to 60 — it should be ≤ original TTL
    assert ttl_after_second <= ttl_after_first + 1, (
        f"TTL was reset on second write: {ttl_after_first} → {ttl_after_second}"
    )
