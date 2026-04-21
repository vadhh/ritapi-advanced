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


async def _wait_for_subscriber(redis_client, channel: str, timeout: float = 3.0) -> None:
    """Poll until at least one subscriber is registered on `channel`, or timeout.

    Must be awaited inside an async context so the event loop can let the
    listener task establish its subscription between polls.
    """
    import asyncio as _asyncio
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = redis_client.execute_command("PUBSUB", "NUMSUB", channel)
        # result is [channel_bytes, count] or [channel_str, count]
        count = result[1] if len(result) >= 2 else 0
        if count >= 1:
            return
        await _asyncio.sleep(0.05)
    raise TimeoutError(f"No subscriber on {channel!r} after {timeout}s")


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


# ── reload_listener_task() ─────────────────────────────────────────────────

def test_listener_reloads_on_message_from_other_pid(redis):
    """Listener calls reload_routes/reload_policies when it receives a message from another PID."""
    import asyncio
    from unittest.mock import patch

    from app.utils.reload_broadcaster import RELOAD_CHANNEL, reload_listener_task

    reloaded = {"routes": False, "policies": False}

    def fake_reload_routes():
        reloaded["routes"] = True

    def fake_reload_policies():
        reloaded["policies"] = True

    async def run():
        task = asyncio.create_task(reload_listener_task())
        await _wait_for_subscriber(redis, RELOAD_CHANNEL)

        # Publish from a fake PID (not our own)
        other_pid = os.getpid() + 9999
        payload = json.dumps({"pid": other_pid})
        redis.publish(RELOAD_CHANNEL, payload)
        await asyncio.sleep(0.3)  # let listener process
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    with patch("app.routing.service.reload_routes", fake_reload_routes), \
         patch("app.policies.service.reload_policies", fake_reload_policies):
        asyncio.run(run())

    assert reloaded["routes"], "reload_routes was not called"
    assert reloaded["policies"], "reload_policies was not called"


def test_listener_skips_self_published_message(redis):
    """Listener does NOT call reload when the message PID matches our own."""
    import asyncio
    from unittest.mock import patch

    from app.utils.reload_broadcaster import RELOAD_CHANNEL, reload_listener_task

    reloaded = {"routes": False, "policies": False}

    def fake_reload_routes():
        reloaded["routes"] = True

    def fake_reload_policies():
        reloaded["policies"] = True

    async def run():
        task = asyncio.create_task(reload_listener_task())
        await _wait_for_subscriber(redis, RELOAD_CHANNEL)

        # Publish with OUR OWN pid — should be ignored
        payload = json.dumps({"pid": os.getpid()})
        redis.publish(RELOAD_CHANNEL, payload)
        await asyncio.sleep(0.3)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    with patch("app.routing.service.reload_routes", fake_reload_routes), \
         patch("app.policies.service.reload_policies", fake_reload_policies):
        asyncio.run(run())

    assert not reloaded["routes"], "reload_routes should NOT have been called for self-message"
    assert not reloaded["policies"], "reload_policies should NOT have been called for self-message"


# ── /admin/reload endpoint ─────────────────────────────────────────────────

def test_reload_endpoint_returns_workers_notified(client, admin_secret_headers):
    """/admin/reload response must include a 'workers_notified' integer field."""
    resp = client.post("/admin/reload", headers=admin_secret_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "workers_notified" in data, "Missing 'workers_notified' in reload response"
    assert isinstance(data["workers_notified"], int)


def test_reload_endpoint_publishes_to_channel(client, admin_secret_headers, redis):
    """/admin/reload must publish a reload signal to the pub/sub channel."""
    from app.utils.reload_broadcaster import RELOAD_CHANNEL

    ps = redis.pubsub()
    ps.subscribe(RELOAD_CHANNEL)
    time.sleep(0.05)

    try:
        client.post("/admin/reload", headers=admin_secret_headers)

        deadline = time.monotonic() + 2
        msg = None
        while time.monotonic() < deadline:
            msg = ps.get_message(ignore_subscribe_messages=True, timeout=0.1)
            if msg and msg["type"] == "message":
                break

        assert msg is not None, "/admin/reload did not publish to the reload channel"
        data = json.loads(msg["data"])
        assert "pid" in data
    finally:
        ps.unsubscribe(RELOAD_CHANNEL)
        ps.close()
