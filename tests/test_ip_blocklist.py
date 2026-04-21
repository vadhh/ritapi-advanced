"""Tests for L-6: Per-IP permanent Redis blocklist."""
import pytest


# ── ip_blocklist helpers ───────────────────────────────────────────────────

def test_is_blocked_returns_false_for_unknown_ip(redis):
    from app.utils.ip_blocklist import is_blocked
    assert is_blocked("10.0.0.1") is False


def test_block_and_is_blocked(redis):
    from app.utils.ip_blocklist import block_ip, is_blocked, unblock_ip
    block_ip("10.0.0.2")
    assert is_blocked("10.0.0.2") is True
    unblock_ip("10.0.0.2")


def test_unblock_removes_ip(redis):
    from app.utils.ip_blocklist import block_ip, is_blocked, unblock_ip
    block_ip("10.0.0.3")
    unblock_ip("10.0.0.3")
    assert is_blocked("10.0.0.3") is False


def test_get_blocked_ips_returns_list(redis):
    from app.utils.ip_blocklist import block_ip, get_blocked_ips, unblock_ip
    block_ip("10.0.0.4")
    block_ip("10.0.0.5")
    ips = get_blocked_ips()
    assert "10.0.0.4" in ips
    assert "10.0.0.5" in ips
    unblock_ip("10.0.0.4")
    unblock_ip("10.0.0.5")


def test_is_blocked_fails_open_when_redis_unavailable():
    from unittest.mock import patch
    from app.utils.redis_client import RedisClientSingleton
    from app.utils.ip_blocklist import is_blocked
    RedisClientSingleton.reset()
    with patch("app.utils.redis_client.RedisClientSingleton.get_client", return_value=None):
        assert is_blocked("10.0.0.99") is False


# ── HardGateMiddleware integration ─────────────────────────────────────────

UA = "pytest-test-client/1.0"


def test_hard_gate_blocks_ip_in_redis_blocklist(client, redis):
    """HardGate must return 403 for an IP in the Redis blocklist."""
    from app.utils.ip_blocklist import block_ip, unblock_ip
    ip = "10.1.1.1"
    block_ip(ip)
    try:
        resp = client.get("/healthz", headers={"X-Forwarded-For": ip, "User-Agent": UA})
        assert resp.status_code == 403
    finally:
        unblock_ip(ip)


def test_hard_gate_allows_ip_after_unblock(client, redis):
    """HardGate must allow an IP that was unblocked."""
    from app.utils.ip_blocklist import block_ip, unblock_ip
    ip = "10.1.1.2"
    block_ip(ip)
    unblock_ip(ip)
    resp = client.get("/healthz", headers={"X-Forwarded-For": ip, "User-Agent": UA})
    assert resp.status_code == 200


def test_hard_gate_passes_unknown_ip(client, redis):
    """HardGate must not block an IP that was never added."""
    resp = client.get("/healthz", headers={"X-Forwarded-For": "10.1.1.3", "User-Agent": UA})
    assert resp.status_code == 200
