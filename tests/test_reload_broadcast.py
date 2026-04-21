"""Tests for L-1: multi-worker config reload via Redis pub/sub.

Task 1 covers: broadcast_reload() — happy path, Redis-unavailable, Redis-error.
Task 2 adds: reload_listener_task() behaviour — reacts to other-PID message, skips own-PID.
Task 3 adds: /admin/reload endpoint — workers_notified field, publishes to channel.
"""
import json
import os
import time
from unittest.mock import MagicMock, patch

import pytest


# ── broadcast_reload() ─────────────────────────────────────────────────────

def test_broadcast_reload_returns_subscriber_count(redis):
    """broadcast_reload publishes to the channel and returns the subscriber count."""
    from app.utils.reload_broadcaster import RELOAD_CHANNEL, broadcast_reload

    # Subscribe with a separate connection so there is 1 subscriber
    ps = redis.pubsub()
    ps.subscribe(RELOAD_CHANNEL)
    time.sleep(0.05)  # let subscription propagate

    count = broadcast_reload()
    # At least 1 subscriber (the one we just made)
    assert count >= 1

    # The published message must be valid JSON with a "pid" key
    deadline = time.monotonic() + 2
    msg = None
    while time.monotonic() < deadline:
        msg = ps.get_message(ignore_subscribe_messages=True, timeout=0.1)
        if msg and msg["type"] == "message":
            break
    try:
        assert msg is not None, "No message received on channel"
        data = json.loads(msg["data"])
        assert "pid" in data
        assert data["pid"] == os.getpid()
    finally:
        ps.unsubscribe(RELOAD_CHANNEL)
        ps.close()


def test_broadcast_reload_returns_zero_when_redis_unavailable():
    """broadcast_reload returns 0 without raising when Redis is down."""
    from app.utils.reload_broadcaster import broadcast_reload

    with patch("app.utils.reload_broadcaster.RedisClientSingleton.get_client", return_value=None):
        result = broadcast_reload()
    assert result == 0


def test_broadcast_reload_returns_zero_on_redis_error():
    """broadcast_reload returns 0 without raising when publish raises."""
    from app.utils.reload_broadcaster import broadcast_reload

    mock_redis = MagicMock()
    mock_redis.publish.side_effect = ConnectionError("boom")
    with patch("app.utils.reload_broadcaster.RedisClientSingleton.get_client", return_value=mock_redis):
        result = broadcast_reload()
    assert result == 0
