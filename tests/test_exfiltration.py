"""
Exfiltration detection tests.

Integration tests use X-Forwarded-For headers to isolate per-test IPs,
preventing counter bleed across tests even with the autouse Redis flush.

Thresholds (from exfiltration_detection.py):
  BULK_ACCESS_THRESHOLD     = 50  hits to same endpoint/IP/60s → block
  CRAWL_ENDPOINT_THRESHOLD  = 30  distinct endpoints/IP/5min → block
  LARGE_RESPONSE_BYTES      = 1MB  → monitor (not block)
  VOLUME_THRESHOLD_BYTES    = 10MB → monitor (not block)
"""
import pytest
from app.middlewares.exfiltration_detection import (
    BULK_ACCESS_THRESHOLD,
    BULK_ACCESS_WINDOW,
    CRAWL_ENDPOINT_THRESHOLD,
    LARGE_RESPONSE_BYTES,
    VOLUME_THRESHOLD_BYTES,
    VOLUME_WINDOW,
    _incr,
    _incrby,
    _sadd_count,
)

_IP = "10.99.exfil.{}"


# ---------------------------------------------------------------------------
# Unit tests — Redis helpers
# ---------------------------------------------------------------------------

def test_incr_sets_ttl_on_first_write(redis):
    key = "test:exfil:incr:1"
    val = _incr(redis, key, 60)
    assert val == 1
    assert redis.ttl(key) > 0


def test_incr_accumulates(redis):
    key = "test:exfil:incr:2"
    _incr(redis, key, 60)
    _incr(redis, key, 60)
    val = _incr(redis, key, 60)
    assert val == 3


def test_incrby_sets_ttl_on_first_write(redis):
    key = "test:exfil:incrby:1"
    val = _incrby(redis, key, 1000, 300)
    assert val == 1000
    assert redis.ttl(key) > 0


def test_incrby_accumulates(redis):
    key = "test:exfil:incrby:2"
    _incrby(redis, key, 500, 300)
    val = _incrby(redis, key, 500, 300)
    assert val == 1000


def test_sadd_count_returns_cardinality(redis):
    key = "test:exfil:sadd:1"
    c1 = _sadd_count(redis, key, "endpoint_a", 300)
    c2 = _sadd_count(redis, key, "endpoint_b", 300)
    c3 = _sadd_count(redis, key, "endpoint_a", 300)  # duplicate
    assert c1 == 1
    assert c2 == 2
    assert c3 == 2  # still 2 — duplicate not counted


def test_sadd_count_sets_ttl(redis):
    key = "test:exfil:sadd:2"
    _sadd_count(redis, key, "ep", 300)
    assert redis.ttl(key) > 0


# ---------------------------------------------------------------------------
# Integration — BULK_ACCESS (same endpoint, same IP, > threshold → 403)
# ---------------------------------------------------------------------------

def test_bulk_access_triggers_block(client, redis):
    """Hitting same endpoint > BULK_ACCESS_THRESHOLD times from one IP → 403."""
    # No X-Forwarded-For → uses testclient IP (in bot bypass list) so bot detection
    # does not interfere before the exfiltration threshold is reached.
    headers = {"User-Agent": "pytest/1.0"}
    blocked = False
    for i in range(BULK_ACCESS_THRESHOLD + 5):
        resp = client.get("/healthz", headers=headers)
        if resp.status_code == 403:
            data = resp.json()
            assert "bulk_access" in data.get("detail", "").lower() or \
                   "suspicious" in data.get("detail", "").lower()
            blocked = True
            break
    assert blocked, f"BULK_ACCESS did not block after {BULK_ACCESS_THRESHOLD} hits"


def test_bulk_access_different_paths_not_blocked(client, redis):
    """Bulk access threshold is per-endpoint — rotating paths should not trigger it."""
    headers = {"X-Forwarded-For": _IP.format(2), "User-Agent": "pytest/1.0"}
    paths = [f"/healthz?v={i}" for i in range(BULK_ACCESS_THRESHOLD + 5)]
    for path in paths:
        resp = client.get(path, headers=headers)
        # None should be blocked by bulk_access (each path is distinct)
        assert resp.status_code != 403 or "bulk" not in resp.json().get("detail", "")


# ---------------------------------------------------------------------------
# Integration — SEQUENTIAL_CRAWL (> threshold distinct endpoints → 403)
# ---------------------------------------------------------------------------

def test_sequential_crawl_triggers_block(client, auth_headers, redis):
    """Accessing > CRAWL_ENDPOINT_THRESHOLD distinct endpoints → 403."""
    # No X-Forwarded-For → uses testclient IP (in bot bypass list) so bot detection
    # does not interfere before the exfiltration crawl threshold is reached.
    headers = {**auth_headers}
    blocked = False
    for i in range(CRAWL_ENDPOINT_THRESHOLD + 5):
        resp = client.get(f"/api/resource/{i}", headers=headers)
        if resp.status_code == 403:
            data = resp.json()
            assert "sequential_crawl" in data.get("detail", "").lower() or \
                   "suspicious" in data.get("detail", "").lower()
            blocked = True
            break
    assert blocked, f"SEQUENTIAL_CRAWL did not block after {CRAWL_ENDPOINT_THRESHOLD} distinct endpoints"


def test_sequential_crawl_same_endpoint_not_triggered(client, auth_headers, redis):
    """Hitting the same endpoint repeatedly does not trigger sequential crawl."""
    headers = {
        **auth_headers,
        "X-Forwarded-For": _IP.format(4),
    }
    for _ in range(CRAWL_ENDPOINT_THRESHOLD + 5):
        resp = client.get("/api/same-resource", headers=headers)
        # Should not be blocked by sequential_crawl (same endpoint each time)
        if resp.status_code == 403:
            # Only acceptable block reason is bulk_access (not crawl)
            detail = resp.json().get("detail", "")
            assert "sequential_crawl" not in detail.lower()


# ---------------------------------------------------------------------------
# Unit — detection thresholds are correctly configured
# ---------------------------------------------------------------------------

def test_bulk_access_threshold_value():
    assert BULK_ACCESS_THRESHOLD == 50


def test_crawl_endpoint_threshold_value():
    assert CRAWL_ENDPOINT_THRESHOLD == 30


def test_large_response_threshold_value():
    assert LARGE_RESPONSE_BYTES == 1 * 1024 * 1024


def test_volume_threshold_value():
    assert VOLUME_THRESHOLD_BYTES == 10 * 1024 * 1024
