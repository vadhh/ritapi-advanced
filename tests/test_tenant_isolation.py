"""
Tests for multi-tenant isolation.

Verifies:
- Two requests with different X-Target-ID headers do not share Redis rate limit counters
- Request without X-Target-ID uses "default" tenant
- Per-tenant policy file is loaded when present; global policy is used when absent
- Redis key for tenant_a contains "tenant_a" and does not match tenant_b's key pattern
"""
import os
from pathlib import Path
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Redis key isolation tests (integration — require Redis)
# ---------------------------------------------------------------------------

_AUTH_UA = "pytest-test-client/1.0"
_IP_BASE = "10.99.tenant.{}"


def _auth(viewer_token: str, tenant_id: str | None = None, ip: str | None = None) -> dict:
    headers = {
        "Authorization": f"Bearer {viewer_token}",
        "User-Agent": _AUTH_UA,
    }
    if tenant_id:
        headers["X-Target-ID"] = tenant_id
    if ip:
        headers["X-Forwarded-For"] = ip
    return headers


def test_different_tenants_have_independent_rate_counters(client, redis, viewer_token):
    """Requests from tenant_a must not increment tenant_b's rate limit counter."""
    ip = _IP_BASE.format(10)
    path_key = "_dashboard"

    # Send a few requests as tenant_a
    for _ in range(3):
        client.get("/dashboard", headers=_auth(viewer_token, "tenant_a", ip))

    tenant_a_key = f"ritapi:tenant_a:rate:ip:{ip}:{path_key}"
    tenant_b_key = f"ritapi:tenant_b:rate:ip:{ip}:{path_key}"

    count_a = int(redis.get(tenant_a_key) or 0)
    count_b = int(redis.get(tenant_b_key) or 0)

    assert count_a > 0, f"tenant_a counter should be > 0 (got {count_a})"
    assert count_b == 0, f"tenant_b counter must be 0 when only tenant_a sent requests (got {count_b})"


def test_no_target_id_uses_default_tenant(client, redis, viewer_token):
    """Request without X-Target-ID must increment the 'default' tenant counter."""
    ip = _IP_BASE.format(11)
    path_key = "_dashboard"

    client.get("/dashboard", headers=_auth(viewer_token, ip=ip))

    default_key = f"ritapi:default:rate:ip:{ip}:{path_key}"
    count = int(redis.get(default_key) or 0)
    assert count > 0, f"'default' tenant counter should be > 0 (got {count})"


def test_tenant_a_key_does_not_match_tenant_b_pattern(client, redis, viewer_token):
    """Redis keys for tenant_a must not match tenant_b's key pattern."""
    ip_a = _IP_BASE.format(12)
    ip_b = _IP_BASE.format(13)

    client.get("/dashboard", headers=_auth(viewer_token, "alpha_co", ip_a))
    client.get("/dashboard", headers=_auth(viewer_token, "beta_co", ip_b))

    alpha_keys = list(redis.scan_iter("ritapi:alpha_co:*"))
    beta_keys = list(redis.scan_iter("ritapi:beta_co:*"))

    assert all(b"alpha_co" in k for k in alpha_keys), (
        "All alpha_co keys must contain 'alpha_co'"
    )
    assert all(b"beta_co" in k for k in beta_keys), (
        "All beta_co keys must contain 'beta_co'"
    )
    # Cross-check: alpha keys must not contain beta_co and vice versa
    for k in alpha_keys:
        assert b"beta_co" not in k, f"alpha key {k!r} must not contain 'beta_co'"
    for k in beta_keys:
        assert b"alpha_co" not in k, f"beta key {k!r} must not contain 'alpha_co'"


def test_two_tenants_can_hit_limit_independently(client, redis, viewer_token):
    """Exhausting tenant_a's rate limit must not affect tenant_b."""
    from app.middlewares.rate_limit import RATE_LIMIT

    ip = _IP_BASE.format(14)
    hit_429 = False

    # Exhaust tenant_a's rate limit
    for _ in range(RATE_LIMIT + 5):
        resp = client.get("/dashboard", headers=_auth(viewer_token, "ta_isolate", ip))
        if resp.status_code == 429:
            hit_429 = True
            break

    assert hit_429, "tenant_a should hit 429 after exhausting its rate limit"

    # tenant_b with same IP should start fresh (counter 0)
    resp_b = client.get("/dashboard", headers=_auth(viewer_token, "tb_isolate", ip))
    # tenant_b should not immediately get 429 (its counter was never incremented)
    assert resp_b.status_code != 429, (
        f"tenant_b must not be rate-limited just because tenant_a was (got {resp_b.status_code})"
    )


# ---------------------------------------------------------------------------
# Policy isolation tests (unit — no Redis needed)
# ---------------------------------------------------------------------------

def test_per_tenant_policy_loaded_when_file_present(tmp_path):
    """get_policy() must load the tenant-specific file when it exists."""
    from app.policies.service import get_policy

    tenant_dir = tmp_path / "tenants" / "acme_corp"
    tenant_dir.mkdir(parents=True)
    (tenant_dir / "auth.yml").write_text(
        "rate_limit:\n  requests: 7\n  window_seconds: 30\n"
    )

    with patch("app.policies.service._POLICIES_DIR", str(tmp_path)):
        policy = get_policy("auth", tenant_id="acme_corp")

    assert policy.rate_limit.requests == 7, (
        f"Expected tenant rate limit 7, got {policy.rate_limit.requests}"
    )
    assert policy.rate_limit.window_seconds == 30


def test_global_policy_used_when_no_tenant_file(tmp_path):
    """get_policy() must fall back to the global policy when no tenant file exists."""
    from app.policies.service import get_policy

    # Create global policy dir with auth.yml
    (tmp_path / "auth.yml").write_text(
        "rate_limit:\n  requests: 42\n  window_seconds: 60\n"
    )
    # No tenants/ subdirectory

    with patch("app.policies.service._POLICIES_DIR", str(tmp_path)):
        with patch("app.policies.service._loaded", False):
            with patch("app.policies.service._policies", {}):
                policy = get_policy("auth", tenant_id="unknown_tenant")

    assert policy.rate_limit.requests == 42, (
        f"Expected global rate limit 42, got {policy.rate_limit.requests}"
    )


def test_default_tenant_uses_global_policy(tmp_path):
    """tenant_id='default' must skip tenant file lookup entirely."""
    from app.policies.service import get_policy

    # Even if a tenants/default/ directory exists, it must not be consulted
    tenant_dir = tmp_path / "tenants" / "default"
    tenant_dir.mkdir(parents=True)
    (tenant_dir / "auth.yml").write_text(
        "rate_limit:\n  requests: 999\n  window_seconds: 1\n"
    )
    (tmp_path / "auth.yml").write_text(
        "rate_limit:\n  requests: 50\n  window_seconds: 60\n"
    )

    with patch("app.policies.service._POLICIES_DIR", str(tmp_path)):
        with patch("app.policies.service._loaded", False):
            with patch("app.policies.service._policies", {}):
                policy = get_policy("auth", tenant_id="default")

    # Must use global policy (50), not the tenants/default/ override (999)
    assert policy.rate_limit.requests == 50, (
        f"'default' tenant must use global policy (50), got {policy.rate_limit.requests}"
    )
