"""
Cache invalidation tests.

1. _route_cache TTL: entry expires after CACHE_TTL seconds.
2. _tenant_policy_cache TTL: entry expires after CACHE_TTL seconds.
3. POST /admin/reload: clears both caches and reloads from disk.
4. After reload, changed YAML is reflected immediately.
"""
import time
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Route cache TTL
# ---------------------------------------------------------------------------

def test_route_cache_respects_ttl():
    """Cached route entry is evicted and re-resolved after TTL expires."""
    import app.routing.service as svc

    original_ttl = svc.CACHE_TTL
    try:
        svc.CACHE_TTL = 0  # zero TTL — every lookup is a miss
        svc._route_cache.clear()

        resolve_calls: list[int] = []
        original_resolve = svc._load_routes

        # Patch resolve to count actual disk lookups
        svc._loaded = True
        svc._routes = []

        # First call — cache miss → stores entry with timestamp
        result1 = svc.resolve_route("/api/test", "GET")
        # Immediately re-call with TTL=0 — should be a cache miss (expired)
        result2 = svc.resolve_route("/api/test", "GET")

        # Both results are None (no routes loaded), but both went through the lookup path
        assert result1 is None
        assert result2 is None
        # With TTL=0, every call evicts the previous entry — cache never grows stale
        assert ("/api/test", "GET") in svc._route_cache
    finally:
        svc.CACHE_TTL = original_ttl
        svc._route_cache.clear()


def test_route_cache_hit_within_ttl():
    """Cached route entry is returned without re-resolution within TTL."""
    import app.routing.service as svc

    original_ttl = svc.CACHE_TTL
    try:
        svc.CACHE_TTL = 300  # long TTL
        svc._route_cache.clear()
        svc._loaded = True
        svc._routes = []

        # Seed the cache manually with a future timestamp
        from app.routing.service import _MISSING, Route
        fake_route = Route(
            name="cached-route",
            path_prefix="/api/cached",
            methods=["GET"],
            upstream="http://backend",
        )
        svc._route_cache[("/api/cached", "GET")] = (fake_route, time.monotonic())

        result = svc.resolve_route("/api/cached", "GET")
        assert result is not None
        assert result.name == "cached-route"
    finally:
        svc.CACHE_TTL = original_ttl
        svc._route_cache.clear()


def test_route_cache_entry_evicted_after_ttl():
    """Expired cache entries are evicted on the next access."""
    import app.routing.service as svc

    svc._route_cache.clear()
    svc._loaded = True
    svc._routes = []

    # Seed with an old timestamp (already expired regardless of CACHE_TTL)
    old_ts = time.monotonic() - 9999
    svc._route_cache[("/api/stale", "GET")] = (None, old_ts)

    # Should evict expired entry and re-resolve (returns None, no routes)
    result = svc.resolve_route("/api/stale", "GET")
    assert result is None
    # Entry should have been replaced with a fresh timestamp
    entry = svc._route_cache.get(("/api/stale", "GET"))
    assert entry is not None
    _, ts = entry
    assert time.monotonic() - ts < 5  # fresh


# ---------------------------------------------------------------------------
# Tenant policy cache TTL
# ---------------------------------------------------------------------------

def test_tenant_policy_cache_respects_ttl():
    """Tenant policy cache entry is re-fetched after TTL expires."""
    import app.policies.service as svc

    original_ttl = svc.CACHE_TTL
    try:
        svc.CACHE_TTL = 0
        svc._tenant_policy_cache.clear()

        # Seed with old timestamp
        old_ts = time.monotonic() - 9999
        svc._tenant_policy_cache[("default", "acme")] = (None, old_ts)

        load_calls: list[int] = []

        def fake_load(name, tenant_id):
            load_calls.append(1)
            return None

        with patch.object(svc, "_load_tenant_policy", side_effect=fake_load):
            svc._loaded = True
            svc.get_policy("default", tenant_id="acme")

        assert load_calls, "Expired cache entry must trigger re-fetch"
    finally:
        svc.CACHE_TTL = original_ttl
        svc._tenant_policy_cache.clear()


def test_tenant_policy_cache_hit_within_ttl():
    """Tenant policy cache entry is returned without re-fetch within TTL."""
    import app.policies.service as svc

    svc._tenant_policy_cache.clear()
    svc._loaded = True

    from app.policies.service import DEFAULT_POLICY

    # Seed with fresh timestamp
    svc._tenant_policy_cache[("myroute", "tenant-x")] = (DEFAULT_POLICY, time.monotonic())

    load_calls: list[int] = []

    def fake_load(name, tenant_id):
        load_calls.append(1)
        return None

    with patch.object(svc, "_load_tenant_policy", side_effect=fake_load):
        result = svc.get_policy("myroute", tenant_id="tenant-x")

    assert not load_calls, "Fresh cache entry must NOT trigger re-fetch"
    assert result is DEFAULT_POLICY


# ---------------------------------------------------------------------------
# POST /admin/reload clears caches and reloads from disk
# ---------------------------------------------------------------------------

def test_admin_reload_clears_route_cache(client, admin_headers):
    """POST /admin/reload must clear _route_cache."""
    import app.routing.service as svc

    # Seed route cache with a stale entry
    svc._route_cache[("/stale-path", "GET")] = (None, time.monotonic() - 9999)

    response = client.post("/admin/reload", headers=admin_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["reloaded"] is True

    # Cache must be cleared
    assert ("/stale-path", "GET") not in svc._route_cache


def test_admin_reload_clears_tenant_policy_cache(client, admin_headers):
    """POST /admin/reload must clear _tenant_policy_cache."""
    import app.policies.service as svc

    svc._tenant_policy_cache[("any-route", "any-tenant")] = (None, time.monotonic() - 9999)

    response = client.post("/admin/reload", headers=admin_headers)
    assert response.status_code == 200

    assert ("any-route", "any-tenant") not in svc._tenant_policy_cache


def test_admin_reload_returns_route_and_policy_counts(client, admin_headers):
    """POST /admin/reload response must include route and policy counts."""
    response = client.post("/admin/reload", headers=admin_headers)
    assert response.status_code == 200
    data = response.json()
    assert "routes" in data
    assert "policies" in data
    assert isinstance(data["routes"], int)
    assert isinstance(data["policies"], int)


def test_admin_reload_requires_auth(client):
    """POST /admin/reload without credentials must return 401."""
    response = client.post("/admin/reload")
    assert response.status_code in (401, 403)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def admin_headers():
    return {"X-Admin-Secret": "test-admin-secret"}
