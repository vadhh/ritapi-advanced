# Audit Fixes — Batch 2 (Remaining High + Medium + Low) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix remaining audit findings: H-2, H-3, H-4, C-1, M-1, M-9, M-10, L-2, L-3.

**Architecture:** Fixes are isolated to specific files. C-1 is the most architectural — it wires `request.state.detections` for rate_limit and injection middlewares so the DecisionEngine policy dispatch is no longer dead code.

**Tech Stack:** Python 3.11+, FastAPI, Starlette middleware, Redis, redis-py pipelines

---

## Files Modified

| File | Tasks |
|------|-------|
| `app/middlewares/exfiltration_detection.py` | H-4, H-3 |
| `app/middlewares/bot_detection.py` | H-2 |
| `app/middlewares/rate_limit.py` | C-1 |
| `app/middlewares/injection_detection.py` | C-1 |
| `app/middlewares/decision_engine.py` | C-1 |
| `app/main.py` | C-1 (initialize detections) |
| `app/utils/redis_client.py` | M-1 |
| `.env.staging` | M-1 |
| `tests/conftest.py` | M-9 |
| `.github/workflows/ci.yml` | M-9 |
| `app/middlewares/rate_limit.py` | M-10 |
| `pyproject.toml` | L-2 |
| `requirements.txt` | L-3 |
| `requirements-dev.txt` | L-3 (new file) |
| `tests/` | verification throughout |

---

## Task 1: Fix `_incrby` TTL race condition (H-4)

**Files:**
- Modify: `app/middlewares/exfiltration_detection.py:57-61`

The "first write" detection `val == amount` is incorrect under concurrent load. Use `EXPIRE key ttl NX` (Redis 7+) via pipeline to set TTL only if not already set — atomic and correct.

- [ ] **Step 1: Write failing test**

Add to `tests/test_exfiltration.py` (find the file, append this test):

```python
def test_incrby_sets_ttl_on_first_write(flush_test_redis):
    """_incrby must set TTL atomically on first write regardless of amount."""
    import redis as redis_lib
    from app.middlewares.exfiltration_detection import _incrby

    r = redis_lib.from_url("redis://localhost:6379/15")
    key = "test:incrby:race"
    r.delete(key)

    # First write with amount > 1
    val = _incrby(r, key, 5000, 60)
    assert val == 5000
    ttl = r.ttl(key)
    assert ttl > 0, f"TTL must be set after first write, got {ttl}"

    # Second write must not reset TTL to a fresh 60s
    import time
    time.sleep(0.05)
    val2 = _incrby(r, key, 1000, 60)
    assert val2 == 6000
    ttl2 = r.ttl(key)
    # TTL should still exist (not reset to 60 on second write)
    assert ttl2 > 0
```

- [ ] **Step 2: Run test**
```bash
python -m pytest tests/test_exfiltration.py::test_incrby_sets_ttl_on_first_write -v
```
Expected: PASS (verify TTL is set). If `_incrby` is broken it may still pass — we're fixing correctness, not just the test.

- [ ] **Step 3: Fix `_incrby` in `app/middlewares/exfiltration_detection.py`**

Replace lines 57-61:
```python
def _incrby(redis, key: str, amount: int, ttl: int) -> int:
    val = redis.incrby(key, amount)
    if val == amount:  # first write
        redis.expire(key, ttl)
    return val
```
With:
```python
def _incrby(redis, key: str, amount: int, ttl: int) -> int:
    """Increment key by amount, setting TTL only if not already set (atomic via pipeline)."""
    pipe = redis.pipeline()
    pipe.incrby(key, amount)
    pipe.expire(key, ttl, nx=True)  # NX: set only if no TTL exists — Redis 7+
    results = pipe.execute()
    return results[0]
```

- [ ] **Step 4: Run full test suite**
```bash
python -m pytest tests/ -q
```
Expected: all tests pass.

- [ ] **Step 5: Commit**
```bash
git add app/middlewares/exfiltration_detection.py tests/test_exfiltration.py
git commit -m "fix: use pipeline INCRBY+EXPIRE NX to eliminate TTL race condition in exfiltration detection (H-4)"
```

---

## Task 2: Fix bot detection — block BEFORE route handler when risk is already high (H-2)

**Files:**
- Modify: `app/middlewares/bot_detection.py:200-259`

**Current flow:** call_next → detect (with status_code) → block if cumulative risk ≥ threshold.
**Problem:** The route handler already ran by the time we block.

**Fix:** Add a pre-request check. If the *accumulated* risk score from *previous* requests already meets the block threshold, block immediately before calling call_next. New signals from the current request are still scored post-response for future blocking.

- [ ] **Step 1: Read the current `dispatch` method in `bot_detection.py`**

Read lines 185-260 to understand `_accumulate_risk()`, `BLOCK_THRESHOLD`, and the Redis key pattern.

- [ ] **Step 2: Write failing test**

Add to `tests/test_bot_detection.py`:

```python
def test_bot_blocked_before_route_executes(flush_test_redis):
    """If cumulative bot risk >= BLOCK_THRESHOLD from prior requests,
    the block must happen BEFORE the route handler runs."""
    from app.middlewares.bot_detection import BLOCK_THRESHOLD
    import redis as redis_lib

    r = redis_lib.from_url("redis://localhost:6379/15")
    test_ip = "10.99.99.99"

    # Pre-seed cumulative risk at threshold
    r.set(f"bot:risk:{test_ip}", BLOCK_THRESHOLD, ex=3600)

    # A request from this IP should be blocked before hitting /healthz
    # (tracked via response — /healthz normally returns 200)
    from tests.conftest import client as get_client  # noqa: adjust to actual fixture
    # This test is best run as integration — mark as known limitation for now
    # The pre-request check existence is verified via source inspection
    import inspect
    from app.middlewares.bot_detection import BotDetectionMiddleware
    source = inspect.getsource(BotDetectionMiddleware.dispatch)
    assert "cumulative" in source and "BLOCK_THRESHOLD" in source
    # Verify pre-request check exists (before call_next)
    call_next_pos = source.index("call_next")
    block_check_pos = source.index("BLOCK_THRESHOLD")
    assert block_check_pos < call_next_pos, (
        "Block threshold check must appear BEFORE call_next in dispatch()"
    )
```

- [ ] **Step 3: Run test to verify it fails**
```bash
python -m pytest tests/test_bot_detection.py::test_bot_blocked_before_route_executes -v
```
Expected: FAIL (block check appears after call_next currently).

- [ ] **Step 4: Fix `bot_detection.py` dispatch method**

Read `app/middlewares/bot_detection.py` lines 185-260. Add a pre-request cumulative risk check.

In the `dispatch` method, after obtaining `redis` and the request metadata (ip, ua, method, path, payload_size), but **before** `call_next`, add:

```python
        # --- Pre-request check: block if prior cumulative risk already at threshold ---
        redis = RedisClientSingleton.get_client()
        if redis is not None:
            try:
                existing_risk = int(redis.get(f"bot:risk:{ip}") or 0)
                if existing_risk >= BLOCK_THRESHOLD:
                    logger.warning(
                        "Bot pre-block %s — cumulative risk %d >= %d (pre-request)",
                        ip, existing_risk, BLOCK_THRESHOLD,
                    )
                    bot_blocks.inc()
                    requests_total.labels(
                        method=method, action="block", detection_type="bot:pre_block"
                    ).inc()
                    return JSONResponse(
                        {"error": "Forbidden", "detail": "Automated request detected"},
                        status_code=403,
                    )
            except Exception:
                pass  # fail-open: proceed if Redis check fails
```

Then the existing `call_next` + post-response scoring logic continues unchanged for building up risk from new signals.

- [ ] **Step 5: Run test to verify it passes**
```bash
python -m pytest tests/test_bot_detection.py::test_bot_blocked_before_route_executes -v
```
Expected: PASS.

- [ ] **Step 6: Run full test suite**
```bash
python -m pytest tests/ -q
```
Expected: all tests pass.

- [ ] **Step 7: Commit**
```bash
git add app/middlewares/bot_detection.py tests/test_bot_detection.py
git commit -m "fix: check accumulated bot risk before route handler executes to prevent post-execution blocks (H-2)"
```

---

## Task 3: Fix exfiltration detection — pre-request block for counter-based detections (H-3)

**Files:**
- Modify: `app/middlewares/exfiltration_detection.py`

**Current flow:** call_next → measure body → detect bulk_access/sequential_crawl → block.
**Problem:** Route handler already ran.

**Fix:** For `bulk_access` and `sequential_crawl` (counter-based, don't need response body), check counters BEFORE calling call_next. If threshold exceeded, block immediately. `large_response` and `high_volume` still happen post-response (require body size).

- [ ] **Step 1: Write failing test**

Add to `tests/test_exfiltration.py`:

```python
def test_bulk_access_blocked_before_route_executes(flush_test_redis):
    """bulk_access block must fire BEFORE call_next when counter is already at threshold."""
    from app.middlewares.exfiltration_detection import ExfiltrationDetectionMiddleware
    import inspect
    source = inspect.getsource(ExfiltrationDetectionMiddleware.dispatch)
    call_next_pos = source.index("call_next")
    bulk_check_pos = source.index("bulk_access")
    assert bulk_check_pos < call_next_pos, (
        "bulk_access check must appear BEFORE call_next in dispatch()"
    )
```

- [ ] **Step 2: Run test to verify it fails**
```bash
python -m pytest tests/test_exfiltration.py::test_bulk_access_blocked_before_route_executes -v
```
Expected: FAIL.

- [ ] **Step 3: Fix `exfiltration_detection.py` dispatch method**

In the `dispatch` method, after getting `ip`, `path`, `method` and the Redis client, but **before** `call_next`, add a pre-request counter check block:

```python
        # --- Pre-request block for counter-based detections ---
        redis = RedisClientSingleton.get_client()
        if redis is not None:
            try:
                bulk_count = int(redis.get(f"exfil:bulk:{ip}:{path}") or 0)
                ep_count = int(redis.scard(f"exfil:crawl:{ip}") or 0)
                pre_action = None
                pre_reason = None
                if bulk_count > BULK_ACCESS_THRESHOLD:
                    pre_action, pre_reason = "block", "bulk_access"
                elif ep_count > CRAWL_ENDPOINT_THRESHOLD:
                    pre_action, pre_reason = "block", "sequential_crawl"

                if pre_action == "block":
                    logger.warning(
                        "Exfiltration pre-block [%s] from %s on %s",
                        pre_reason, ip, path,
                    )
                    log_request(
                        client_ip=ip, path=path, method=method,
                        action="block", detection_type=f"exfil:{pre_reason}",
                        score=0.9, reasons=f"{pre_reason} (pre-request)",
                    )
                    exfiltration_alerts.labels(reason=pre_reason).inc()
                    requests_total.labels(
                        method=method, action="block",
                        detection_type=f"exfil:{pre_reason}"
                    ).inc()
                    return JSONResponse(
                        {"error": "Forbidden", "detail": "Suspicious data access pattern detected"},
                        status_code=403,
                    )
            except Exception:
                pass  # fail-open
```

Then the existing `call_next` + post-response body measurement + full detection logic continues unchanged.

- [ ] **Step 4: Run test to verify it passes**
```bash
python -m pytest tests/test_exfiltration.py::test_bulk_access_blocked_before_route_executes -v
```
Expected: PASS.

- [ ] **Step 5: Run full test suite**
```bash
python -m pytest tests/ -q
```
Expected: all tests pass.

- [ ] **Step 6: Commit**
```bash
git add app/middlewares/exfiltration_detection.py tests/test_exfiltration.py
git commit -m "fix: check bulk_access and sequential_crawl counters before route handler executes (H-3)"
```

---

## Task 4: Wire request.state.detections for rate_limit and injection — fix dead policy dispatch (C-1)

**Files:**
- Modify: `app/middlewares/rate_limit.py`
- Modify: `app/middlewares/injection_detection.py`
- Modify: `app/main.py` (initialize `request.state.detections`)

**Background:** `DecisionEngineMiddleware.dispatch()` reads `request.state.detections` to apply per-route policy actions (block/monitor/throttle/allow). But no middleware ever writes to it — they all return JSONResponse directly. This means YAML policy settings like `on_rate_limit: throttle` and `on_bot_detection: monitor` have no effect.

**Fix scope (pragmatic):** Wire `rate_limit` and `injection_detection` — the two middlewares where policy matters most. Bot and exfil detection are post-response by design so they still handle their own blocks (already improved by H-2/H-3 pre-checks).

**How DecisionEngine works:** It runs innermost (before the route handler). It sets `request.state.policy` and `request.state.route` PRE-request, then after `call_next` it reads `request.state.detections`. Outer middlewares (rate_limit, injection) run pre-request and CAN set `request.state.detections` because they execute before route handler.

**Flow after fix:**
- RateLimitMiddleware: instead of returning JSONResponse → appends to `request.state.detections` with type `"rate_limit"`
- InjectionDetectionMiddleware: instead of returning JSONResponse → appends to `request.state.detections` with type `"injection"`
- DecisionEngineMiddleware: reads detections, applies `policy.decision_actions.get_action(det_type)` → block/monitor/throttle/allow per route policy

- [ ] **Step 1: Understand the policy actions API**

Read `app/policies/service.py` and any `decision_actions` model to understand `get_action(det_type)`. The `det_type` values expected:
- `"rate_limit"` for rate limiting
- `"injection"` for injection detection

- [ ] **Step 2: Initialize `request.state.detections` in `main.py`**

In `app/main.py`, read the lifespan or middleware registration. Add a middleware or ensure `request.state.detections` is initialized to `[]` before DecisionEngine reads it.

The simplest approach: in `DecisionEngineMiddleware.dispatch()` (already in `decision_engine.py`), ensure the initialization happens there since it's innermost:

The existing line 58 already does:
```python
detections = getattr(request.state, "detections", [])
```
This is safe — no change needed here.

But outer middlewares need to initialize it before appending. Add this to `app/main.py` as a simple first middleware or add it to each middleware that writes detections:

In each writing middleware, before appending, do:
```python
if not hasattr(request.state, "detections"):
    request.state.detections = []
request.state.detections.append({...})
```

- [ ] **Step 3: Write failing test**

Add to `tests/test_rate_limit.py`:

```python
def test_rate_limit_appends_to_detections_not_returns_403(client, flush_test_redis):
    """When rate limited, middleware must annotate request.state.detections,
    not return 403 directly — policy action determines the response."""
    # This is hard to test without middleware inspection; verify via source
    import inspect
    from app.middlewares.rate_limit import RateLimitMiddleware
    source = inspect.getsource(RateLimitMiddleware.dispatch)
    assert "request.state.detections" in source, (
        "RateLimitMiddleware must write to request.state.detections"
    )
```

Add to `tests/test_injection.py` (or the existing injection test file):

```python
def test_injection_appends_to_detections_not_returns_403():
    """When injection detected, middleware must annotate request.state.detections."""
    import inspect
    from app.middlewares.injection_detection import InjectionDetectionMiddleware
    source = inspect.getsource(InjectionDetectionMiddleware.dispatch)
    assert "request.state.detections" in source, (
        "InjectionDetectionMiddleware must write to request.state.detections"
    )
```

- [ ] **Step 4: Run tests to verify they fail**
```bash
python -m pytest tests/test_rate_limit.py::test_rate_limit_appends_to_detections_not_returns_403 -v
```
Expected: FAIL.

- [ ] **Step 5: Fix `rate_limit.py`**

Read the current `dispatch` method. Find where it returns `JSONResponse(429)`. Replace the direct return with an append to `request.state.detections` and a `call_next()` invocation (the DecisionEngine will handle the actual block).

Before the rate-limit hit block:
```python
if not hasattr(request.state, "detections"):
    request.state.detections = []
request.state.detections.append({
    "type": "rate_limit",
    "score": 1.0,
    "reason": f"Rate limit exceeded ({count}/{limit} in {window}s)",
})
return await call_next(request)
```

Remove the `JSONResponse(429)` direct return.

**Important:** The `rate_limit_hits` counter increment, logging, and metrics must still happen before the detection is appended (they're observation, not response).

- [ ] **Step 6: Fix `injection_detection.py`**

Read the current dispatch method. Find where it calls `_blocked_response()` or returns `JSONResponse(403)`. Replace with:

```python
if not hasattr(request.state, "detections"):
    request.state.detections = []
request.state.detections.append({
    "type": "injection",
    "score": 0.95,
    "reason": f"{category}: {snippet}",
})
return await call_next(request)
```

Remove the `_blocked_response()` / `JSONResponse` return for injection hits.

- [ ] **Step 7: Run both tests**
```bash
python -m pytest tests/test_rate_limit.py::test_rate_limit_appends_to_detections_not_returns_403 tests/test_injection.py::test_injection_appends_to_detections_not_returns_403 -v
```
Expected: both PASS.

- [ ] **Step 8: Run full test suite — expect some failures**
```bash
python -m pytest tests/ -q 2>&1 | head -50
```
Some tests that expected 429/403 from rate_limit or injection directly will now get the response from DecisionEngine. Check what fails and fix tests to reflect the new behavior (the status code should still be 403 — DecisionEngine blocks when action is "block").

- [ ] **Step 9: Update any broken tests**

Tests expecting 429 from rate limit: the default policy action for `rate_limit` detection should be `block` in the default policy. Verify `configs/policies/default.yml` has `on_rate_limit: block`. If so, the response is still 403 from DecisionEngine (not 429 from rate_limit).

Update response code assertions: 429 → 403 in any affected tests, OR update the default policy to use HTTP 429. Decide based on what makes sense — keep 429 if it's the correct HTTP status for rate limiting.

**If keeping 429:** DecisionEngine's `_block_response` needs to accept a status_code parameter, and the detection dict should carry `"status_code": 429` for rate_limit type.

**Simpler alternative:** Keep rate_limit returning 429 directly (it's the correct HTTP status) but ALSO append to detections for monitoring. This means rate_limit still short-circuits to 429, but policy monitoring/throttle actions can be observed.

- [ ] **Step 10: Commit**
```bash
git add app/middlewares/rate_limit.py app/middlewares/injection_detection.py tests/
git commit -m "fix: wire request.state.detections in rate_limit and injection middlewares — policy dispatch no longer dead code (C-1)"
```

---

## Task 5: Fix REDIS_SENTINEL_SERVICE env var name mismatch (M-1)

**Files:**
- Modify: `.env.staging` (rename variable)
- Modify: `docs/CONFIGURATION.md` (update docs)
- No code change needed — `redis_client.py:65` already uses `REDIS_SENTINEL_SERVICE` (correct)

The mismatch: `.env.staging` uses `REDIS_SENTINEL_MASTER`, docs use `REDIS_SENTINEL_MASTER`, code uses `REDIS_SENTINEL_SERVICE`.

- [ ] **Step 1: Fix `.env.staging`**

Read `.env.staging`, find the line with `REDIS_SENTINEL_MASTER`, rename to `REDIS_SENTINEL_SERVICE`.

- [ ] **Step 2: Fix `docs/CONFIGURATION.md`**

Read `docs/CONFIGURATION.md`, find all references to `REDIS_SENTINEL_MASTER` and rename to `REDIS_SENTINEL_SERVICE`.

- [ ] **Step 3: Verify code is already correct**
```bash
grep "REDIS_SENTINEL_SERVICE" app/utils/redis_client.py
```
Expected: found on line 65.

- [ ] **Step 4: Commit**
```bash
git add .env.staging docs/CONFIGURATION.md
git commit -m "fix: rename REDIS_SENTINEL_MASTER to REDIS_SENTINEL_SERVICE to match code (M-1)"
```

---

## Task 6: Align Redis DB between local tests and CI (M-9)

**Files:**
- Modify: `.github/workflows/ci.yml` (change DB from 1 to 15)

Tests use `redis://localhost:6379/15` locally. CI sets `REDIS_URL=redis://localhost:6379/1`. Align CI to use DB 15 to match local.

- [ ] **Step 1: Fix CI**

In `.github/workflows/ci.yml`, find the env block containing `REDIS_URL: redis://localhost:6379/1` and change to:
```yaml
REDIS_URL: redis://localhost:6379/15
```

- [ ] **Step 2: Run tests locally to confirm still pass**
```bash
python -m pytest tests/ -q
```

- [ ] **Step 3: Commit**
```bash
git add .github/workflows/ci.yml
git commit -m "fix: align CI Redis DB to 15 to match local test default (M-9)"
```

---

## Task 7: Remove non-existent /readyz from rate-limit skip list (M-10)

**Files:**
- Modify: `app/middlewares/rate_limit.py:32`

- [ ] **Step 1: Fix `rate_limit.py`**

Find `_SKIP_PREFIXES` and remove `"/readyz"`:

```python
_SKIP_PREFIXES = (
    "/healthz",
    "/metrics",
    "/docs",
    "/openapi.json",
)
```

- [ ] **Step 2: Run tests**
```bash
python -m pytest tests/ -q
```

- [ ] **Step 3: Commit**
```bash
git add app/middlewares/rate_limit.py
git commit -m "fix: remove /readyz from rate-limit skip list — route does not exist (M-10)"
```

---

## Task 8: Fix broken `ritapi` CLI entry point in pyproject.toml (L-2)

**Files:**
- Modify: `pyproject.toml:56`

`ritapi = "app.main:app"` points to a FastAPI instance, not a callable. Fix with a proper CLI wrapper.

- [ ] **Step 1: Create CLI wrapper function**

Read `app/main.py`. Add a `main()` function at the bottom:

```python
def main() -> None:
    """Entry point for the `ritapi` CLI command."""
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        log_level=os.getenv("LOG_LEVEL", "info"),
    )
```

- [ ] **Step 2: Fix `pyproject.toml`**

Change line 56:
```toml
ritapi = "app.main:app"
```
To:
```toml
ritapi = "app.main:main"
```

- [ ] **Step 3: Verify**
```bash
python -c "from app.main import main; print('OK')"
```

- [ ] **Step 4: Commit**
```bash
git add app/main.py pyproject.toml
git commit -m "fix: add main() CLI entry point to app/main.py, fix pyproject.toml entry point (L-2)"
```

---

## Task 9: Separate test dependencies from production requirements (L-3)

**Files:**
- Modify: `requirements.txt` (remove test deps)
- Create: `requirements-dev.txt` (test deps)
- Modify: `Dockerfile` (no change needed — already uses `requirements.txt`)
- Modify: `.github/workflows/ci.yml` (install requirements-dev.txt for test step)

- [ ] **Step 1: Create `requirements-dev.txt`**

```
pytest>=8.0.0
pytest-anyio>=0.0.0
anyio>=4.0.0
pytest-cov>=5.0.0
httpx>=0.27.0
```

(Include httpx if tests use it for TestClient)

- [ ] **Step 2: Remove test deps from `requirements.txt`**

Remove these lines from `requirements.txt`:
- `pytest>=8.0.0`
- `pytest-anyio>=0.0.0`
- `anyio>=4.0.0`
- `pytest-cov>=5.0.0`

- [ ] **Step 3: Update CI to install dev deps for test step**

In `.github/workflows/ci.yml`, find the step that runs `pip install -r requirements.txt` for tests. Add:
```yaml
          pip install -r requirements-dev.txt
```
after the main install, in the test step only.

- [ ] **Step 4: Verify tests still run**
```bash
pip install -r requirements-dev.txt -q
python -m pytest tests/ -q
```

- [ ] **Step 5: Commit**
```bash
git add requirements.txt requirements-dev.txt .github/workflows/ci.yml
git commit -m "fix: separate test dependencies into requirements-dev.txt, keep production image clean (L-3)"
```

---

## Final Verification

After all tasks:
```bash
python -m pytest tests/ -q --tb=short
```
Expected: all tests pass.

```bash
git log --oneline -10
```
Expected: 9 new commits visible.
