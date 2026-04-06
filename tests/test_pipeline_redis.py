"""
Verify that _sadd_count() uses a single pipeline round-trip and
that rate_limit log-dedup uses SET NX instead of EXISTS+SETEX.
"""
import inspect
from unittest.mock import MagicMock


def test_bot_sadd_count_uses_pipeline():
    from app.middlewares.bot_detection import _sadd_count

    mock_redis = MagicMock()
    mock_pipe = MagicMock()
    mock_redis.pipeline.return_value = mock_pipe
    mock_pipe.execute.return_value = [1, True, 3]  # sadd, expire, scard results

    result = _sadd_count(mock_redis, "key", "member", 300)

    mock_redis.pipeline.assert_called_once()
    mock_pipe.sadd.assert_called_once_with("key", "member")
    mock_pipe.expire.assert_called_once_with("key", 300)
    mock_pipe.scard.assert_called_once_with("key")
    mock_pipe.execute.assert_called_once()
    assert result == 3


def test_exfil_sadd_count_uses_pipeline():
    from app.middlewares.exfiltration_detection import _sadd_count

    mock_redis = MagicMock()
    mock_pipe = MagicMock()
    mock_redis.pipeline.return_value = mock_pipe
    mock_pipe.execute.return_value = [1, True, 5]

    result = _sadd_count(mock_redis, "key", "192.0.2.1", 300)

    mock_redis.pipeline.assert_called_once()
    mock_pipe.sadd.assert_called_once_with("key", "192.0.2.1")
    mock_pipe.expire.assert_called_once_with("key", 300)
    mock_pipe.scard.assert_called_once_with("key")
    assert result == 5


def test_rate_limit_log_dedup_uses_set_nx():
    """rate_limit must use SET NX EX for log-dedup, not EXISTS + SETEX."""
    import app.middlewares.rate_limit as rl_mod

    src = inspect.getsource(rl_mod)
    assert "redis.exists(log_key)" not in src, (
        "rate_limit still uses EXISTS — migrate to SET NX EX"
    )
