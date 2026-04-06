"""
Sustained Load / Performance Validation — RitAPI Advanced
==========================================================

Four targeted enforcement scenarios executed in-process via httpx ASGI
transport against the real app and a live Redis instance.

  Test A — Clean burst       : 40 concurrent authenticated requests; no blocks
  Test B — Bot burst         : rapid suspicious-UA requests; handler never runs
  Test C — Injection burst   : attack payloads; route handler NEVER executes (invariant)
  Test D — Throttle stress   : single-IP flood on payment route; 429 consistent

All four tests share the mandatory invariant:
  Blocked requests NEVER reach the route handler.

Redis DB: uses DB from REDIS_URL env var (DB 15 in test session via conftest).
Rate limit: RATE_LIMIT_REQUESTS=20 (set by conftest).
Run:
    pytest tests/perf/test_load_enforcement.py -v -s
"""

import asyncio
import os
import statistics
import time
from collections import Counter

import httpx

# ── Routing knowledge (derived from configs/routing.yml and policies) ──────
#
#  /perf/probe   → default route → auth policy
#                  on_rate_limit: throttle (pass-through, NOT 429)
#                  on_injection: block (403)
#                  on_auth_failure: block (401)
#
#  /api/payment/* → payment route → payment policy
#                   on_rate_limit: block (429)
#                   RATE_LIMIT: 20 req / 60 s (matches conftest env var)
#
# Bulk-access exfil threshold: 50 same-path hits / IP / 60 s → 403
# Bot block risk threshold: 70 pts (cumulative per IP)

# ── App imports — conftest already set env vars before this module loads ───
import app.middlewares.rate_limit as _rl_module     # noqa: E402
from app.main import app                             # noqa: E402
from app.auth.jwt_handler import create_access_token # noqa: E402
from app.utils.redis_client import RedisClientSingleton  # noqa: E402


# ── Route-handler execution tracker ───────────────────────────────────────

_HANDLER_CALLS: list[str] = []


@app.get("/perf/probe")
def perf_probe():
    """Dedicated test route. Execution proves the handler was reached."""
    _HANDLER_CALLS.append("hit")
    return {"handler": "executed"}


@app.post("/perf/probe")
async def perf_probe_post():
    _HANDLER_CALLS.append("hit")
    return {"handler": "executed"}


# ── Helpers ────────────────────────────────────────────────────────────────

def _viewer_jwt(tenant: str) -> str:
    return create_access_token("perf-runner", "VIEWER", tenant_id=tenant)


def _flush_tenant(tenant: str) -> None:
    """Delete all Redis keys for the given tenant (test isolation)."""
    redis = RedisClientSingleton.get_client()
    if redis is None:
        return
    keys = redis.keys(f"ritapi:{tenant}:*")
    if keys:
        redis.delete(*keys)


def _pct(data: list[float], p: int) -> float:
    if not data:
        return 0.0
    s = sorted(data)
    k = (len(s) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


async def _req(client: httpx.AsyncClient, method: str, path: str,
               headers: dict, body=None) -> tuple[int, float]:
    t0 = time.perf_counter()
    if method == "POST":
        r = await client.post(path, headers=headers, json=body)
    else:
        r = await client.get(path, headers=headers)
    return r.status_code, (time.perf_counter() - t0) * 1000


def _print_result(label: str, results: list[tuple[int, float]],
                  handler_before: int) -> dict:
    statuses = Counter(s for s, _ in results)
    latencies = [ms for _, ms in results]
    total = len(results)
    avg_ms = statistics.mean(latencies) if latencies else 0.0
    p95_ms = _pct(latencies, 95)
    handler_calls = len(_HANDLER_CALLS) - handler_before

    # Categorise responses
    pass_codes  = {200, 201, 404}  # reached route layer
    block_codes = {400, 401, 403, 413, 429}
    pass_count  = sum(v for k, v in statuses.items() if k in pass_codes)
    block_count = sum(v for k, v in statuses.items() if k in block_codes)
    error_count = sum(v for k, v in statuses.items()
                      if k not in pass_codes and k not in block_codes)

    w = 62
    print(f"\n{'─'*w}")
    print(f"  {label}")
    print(f"{'─'*w}")
    print(f"  Requests      : {total}")
    print(f"  Status dist   : {dict(sorted(statuses.items()))}")
    print(f"  Pass-through  : {pass_count}   Blocked: {block_count}   Errors: {error_count}")
    print(f"  Avg latency   : {avg_ms:.1f} ms")
    print(f"  p95 latency   : {p95_ms:.1f} ms")
    print(f"  Handler calls : {handler_calls}")
    print(f"{'─'*w}")

    return {
        "total": total, "statuses": dict(statuses),
        "pass": pass_count, "blocked": block_count, "errors": error_count,
        "avg_ms": round(avg_ms, 1), "p95_ms": round(p95_ms, 1),
        "handler_calls": handler_calls,
    }


def _run(coro):
    """
    Run *coro* in a brand-new event loop, then leave a fresh loop installed
    as the thread's current loop so that older tests using
    asyncio.get_event_loop().run_until_complete(...) keep working after us.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()
        asyncio.set_event_loop(asyncio.new_event_loop())


def _new_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    )


# ══════════════════════════════════════════════════════════════════════════
# TEST A — Clean burst
# ══════════════════════════════════════════════════════════════════════════

def test_A_clean_burst():
    _run(_test_A_impl())


async def _test_A_impl():
    """
    40 concurrent authenticated GET requests to /perf/probe.

    Parameters chosen to stay below both active thresholds:
      - RATE_LIMIT = 20 (conftest) but on_rate_limit = throttle for this
        route → pass-through, not a block. Patched to 200 to suppress
        throttle noise and keep the test focused on clean-path behaviour.
      - BULK_ACCESS exfil threshold = 50; 40 requests stay under it.

    Expectation:
      All 40 return 200. Route handler runs for every request.
      Zero blocked, zero errors. p95 < 500 ms (in-process budget).
    """
    tenant = "perf-a"
    ip     = "10.100.1.1"
    jwt    = _viewer_jwt(tenant)

    _flush_tenant(tenant)
    _HANDLER_CALLS.clear()
    handler_before = 0

    # Patch rate limit high so throttle noise doesn't obscure clean-traffic result
    orig_rl = _rl_module.RATE_LIMIT
    _rl_module.RATE_LIMIT = 200
    try:
        headers = {
            "Authorization": f"Bearer {jwt}",
            "X-Target-ID": tenant,
            "X-Forwarded-For": ip,
            "User-Agent": "perf-runner/1.0",
        }

        sem = asyncio.Semaphore(20)
        async with _new_client() as client:
            async def _one():
                async with sem:
                    return await _req(client, "GET", "/perf/probe", headers)
            results = list(await asyncio.gather(*[_one() for _ in range(40)]))
    finally:
        _rl_module.RATE_LIMIT = orig_rl

    stats = _print_result(
        "Test A — Clean Burst (40 req, concurrency=20, JWT auth)",
        results, handler_before,
    )

    assert stats["errors"] == 0, f"5xx errors: {stats['statuses']}"
    assert stats["blocked"] == 0, (
        f"Clean traffic must not be blocked. "
        f"blocked={stats['blocked']}, statuses={stats['statuses']}"
    )
    assert stats["handler_calls"] == 40, (
        f"All 40 clean requests must reach the handler. "
        f"handler_calls={stats['handler_calls']}"
    )
    assert stats["p95_ms"] < 500, f"p95 {stats['p95_ms']} ms exceeds 500 ms budget"


# ══════════════════════════════════════════════════════════════════════════
# TEST B — Bot burst (handler-never-runs proof)
# ══════════════════════════════════════════════════════════════════════════

def test_B_bot_burst():
    _run(_test_B_impl())


async def _test_B_impl():
    """
    60 sequential requests with suspicious User-Agent and no auth.

    Risk accumulation (UA = 'python-requests/2.31.0' → score 60/req):
      After request 1 : risk = 60  (< 70 threshold)
      After request 2 : risk = 100 (≥ 70 threshold)
      Requests 3–60   : bot pre-block fires BEFORE call_next.
                        auth_failure detection also fires.
                        DecisionEngine blocks the first detection (auth_failure → 401).
                        Route handler NEVER executes.

    Handler-never-runs proof:
      The auth middleware blocks unauthenticated requests by appending
      auth_failure and calling call_next. DecisionEngine (innermost) intercepts
      auth_failure and returns 401 before the FastAPI route handler runs.
      The bot pre-block on request 3+ appends bot_block (also a block action),
      which DecisionEngine would reach if auth_failure were absent — but
      bot_block alone is also sufficient to prove handler isolation.

    Expectation:
      All 60 requests blocked (401). handler_calls == 0.
    """
    tenant = "perf-b"
    ip     = "10.100.2.1"

    _flush_tenant(tenant)
    handler_before = len(_HANDLER_CALLS)

    headers = {
        "X-Target-ID": tenant,
        "X-Forwarded-For": ip,
        "User-Agent": "python-requests/2.31.0",   # triggers SUSPICIOUS_USER_AGENT (60 pts)
        # No Authorization header — auth_failure fires
    }

    results: list[tuple[int, float]] = []
    async with _new_client() as client:
        for _ in range(60):
            results.append(await _req(client, "GET", "/perf/probe", headers))

    stats = _print_result(
        "Test B — Bot Burst (60 req, sequential, suspicious UA, no auth)",
        results, handler_before,
    )

    handler_calls = stats["handler_calls"]

    # Mandatory: handler never reached for unauthenticated/bot requests
    assert handler_calls == 0, (
        f"INVARIANT VIOLATED: handler executed {handler_calls} time(s). "
        f"Auth-failed/bot-blocked requests must never reach the route handler."
    )
    assert stats["errors"] == 0, f"5xx server errors: {stats['statuses']}"
    assert stats["blocked"] == 60, (
        f"All 60 requests must be blocked (401 auth_failure). "
        f"blocked={stats['blocked']}, statuses={stats['statuses']}"
    )


# ══════════════════════════════════════════════════════════════════════════
# TEST C — Injection burst (mandatory handler-never-runs invariant)
# ══════════════════════════════════════════════════════════════════════════

def test_C_injection_burst():
    _run(_test_C_impl())


async def _test_C_impl():
    """
    60 concurrent POST requests cycling 3 attack payloads.

    Injection detection runs PRE-call_next (before DecisionEngine, before
    the route handler). When any pattern matches:
      1. append_detection(injection) fires
      2. Middleware calls call_next → reaches DecisionEngine
      3. DecisionEngine sees injection detection → action=block → 403 returned
      4. FastAPI route handler at /perf/probe is never invoked

    Mandatory invariant:
      handler_calls MUST be zero for all 60 requests.
      Any non-zero value means injection bypassed the middleware stack.

    Expectation: blocked == 60, handler_calls == 0, zero 5xx.
    """
    tenant = "perf-c"
    ip     = "10.100.3.1"
    jwt    = _viewer_jwt(tenant)

    _flush_tenant(tenant)
    handler_before = len(_HANDLER_CALLS)

    headers = {
        "Authorization": f"Bearer {jwt}",
        "X-Target-ID": tenant,
        "X-Forwarded-For": ip,
        "User-Agent": "perf-runner/1.0",
        "Content-Type": "application/json",
    }

    payloads = [
        {"q": "' OR '1'='1"},                  # SQLi
        {"q": "<script>alert(document.cookie)</script>"},  # XSS
        {"q": "; cat /etc/passwd"},             # CMDi
    ]

    sem = asyncio.Semaphore(20)
    async with _new_client() as client:
        async def _attack(i: int):
            async with sem:
                return await _req(client, "POST", "/perf/probe", headers,
                                  body=payloads[i % 3])
        results = list(await asyncio.gather(*[_attack(i) for i in range(60)]))

    stats = _print_result(
        "Test C — Injection Burst (60 req, concurrency=20, 3 attack payloads)",
        results, handler_before,
    )

    handler_calls = stats["handler_calls"]

    # ── MANDATORY INVARIANT ─────────────────────────────────────────────
    assert handler_calls == 0, (
        f"INVARIANT VIOLATED: route handler executed {handler_calls} time(s) "
        f"on injection-blocked requests. "
        f"InjectionDetectionMiddleware must block before the handler runs."
    )
    # ───────────────────────────────────────────────────────────────────
    assert stats["blocked"] == 60, (
        f"All 60 attack requests must be blocked (403). "
        f"blocked={stats['blocked']}, statuses={stats['statuses']}"
    )
    assert stats["errors"] == 0, f"5xx server errors: {stats['statuses']}"


# ══════════════════════════════════════════════════════════════════════════
# TEST D — Throttle / 429 stress on payment route
# ══════════════════════════════════════════════════════════════════════════

def test_D_throttle_stress():
    _run(_test_D_impl())


async def _test_D_impl():
    """
    40 rapid requests from a single IP to /api/payment/test.

    Why payment route:
      - payment policy sets on_rate_limit: block → DecisionEngine returns 429
      - auth policy (used by /perf/probe) sets on_rate_limit: throttle → 200
      - Only payment-routed requests produce observable 429 responses

    Rate limit in effect:
      RATE_LIMIT_REQUESTS = 20 (conftest env var, same as payment policy rate_limit.requests)
      Requests 1–20: pass auth + reach route (no route registered → 404)
      Requests 21–40: rate_limit detection fires → DecisionEngine blocks → 429

    Expectation:
      ≥ 15 requests return 429 (concurrent dispatch may share some counter slots)
      Zero 5xx  (Redis pipeline must not surface as server errors)
      Zero 403  (clean JWT, no attack payload, < 50 bulk_access threshold)
    """
    tenant = "perf-d"
    ip     = "10.100.4.1"
    jwt    = _viewer_jwt(tenant)

    _flush_tenant(tenant)
    handler_before = len(_HANDLER_CALLS)

    headers = {
        "Authorization": f"Bearer {jwt}",
        "X-Target-ID": tenant,
        "X-Forwarded-For": ip,
        "User-Agent": "perf-runner/1.0",
    }

    sem = asyncio.Semaphore(25)
    async with _new_client() as client:
        async def _one():
            async with sem:
                return await _req(client, "GET", "/api/payment/test", headers)
        results = list(await asyncio.gather(*[_one() for _ in range(40)]))

    stats = _print_result(
        "Test D — Throttle Stress (40 req, single IP, payment route → 429 on breach)",
        results, handler_before,
    )

    statuses     = stats["statuses"]
    throttled    = statuses.get(429, 0)
    server_errs  = sum(v for k, v in statuses.items() if k >= 500)
    waf_blocks   = statuses.get(403, 0)
    handler_calls = stats["handler_calls"]

    print(f"  429 rate-blocked : {throttled}")
    print(f"  WAF 403 blocks   : {waf_blocks}  (expected 0)")
    print(f"  5xx server errs  : {server_errs}  (expected 0)")
    print(f"  Handler calls    : {handler_calls}  (expected 0 — no /perf/probe hits)")

    assert throttled >= 15, (
        f"Expected ≥15 rate-blocked (429) responses, got {throttled}. "
        f"payment policy on_rate_limit=block must fire for requests > 20/60s. "
        f"Full statuses: {statuses}"
    )
    assert server_errs == 0, (
        f"Redis pipeline instability: {server_errs} 5xx responses observed."
    )
    assert waf_blocks == 0, (
        f"Clean JWT GET to payment route must not hit WAF (403). "
        f"Got {waf_blocks}. Check exfil bulk_access or bot pre-block. "
        f"Statuses: {statuses}"
    )
    assert handler_calls == 0, (
        f"Handler calls = {handler_calls}; payment route has no FastAPI handler, "
        f"and blocked requests must not reach /perf/probe."
    )

    # Verify Redis stayed reachable throughout (no mark_failed called)
    redis = RedisClientSingleton.get_client()
    assert redis is not None, "Redis became unavailable during throttle stress test"
    assert redis.ping(), "Redis ping failed after throttle stress test"


# ══════════════════════════════════════════════════════════════════════════
# Final banner
# ══════════════════════════════════════════════════════════════════════════

def pytest_sessionfinish(session, exitstatus):
    passed = exitstatus == 0
    print("\n" + "═" * 62)
    print(f"  LOAD TEST COMPLETE — {'ALL PASSED' if passed else 'FAILURES DETECTED'}")
    print("═" * 62)
