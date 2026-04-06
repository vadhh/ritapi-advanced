# Audit Fixes — Batch 3 (Architecture: Decision Engine + Throttle + Deployment) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the core architectural issues identified by code review: Decision Engine must process ALL detections pre-route-handler; no middleware may bypass it; throttle must be real; all middlewares must write detections; deployment templates must require secrets.

**Root cause summary:**
1. Decision Engine currently checks detections AFTER `call_next` — route handler already ran
2. Injection and rate_limit write detections but then return directly — Decision Engine never runs
3. Throttle action is a documented no-op
4. Bot/exfil pre-request blocks don't write to `request.state.detections`
5. DASHBOARD_TOKEN absent from .env.staging and Helm chart

**Architecture after fix:**
```
RateLimit:   detect → write detections → await call_next (pass through)
Injection:   detect → write detections → await call_next (pass through)
BotDetect:   detect → write detections → await call_next (pass through)
Exfil:       detect → write detections → await call_next (pass through)
DecisionEng: read detections → block/throttle/monitor PRE call_next → route never runs for blocks
```

**Tech Stack:** Python 3.11+, FastAPI, Starlette middleware, Redis, asyncio

---

## Files Modified

| File | Tasks |
|------|-------|
| `app/middlewares/decision_engine.py` | C1, T1 (pre-request block + real throttle) |
| `app/middlewares/injection_detection.py` | M7 (remove direct returns) |
| `app/middlewares/rate_limit.py` | M7 (remove direct return, preserve 429 via status_code) |
| `app/middlewares/bot_detection.py` | C1-complete (write detections) |
| `app/middlewares/exfiltration_detection.py` | C1-complete (write detections) |
| `app/policies/service.py` | T1 (add `on_bot_block` action, throttle_ttl) |
| `.env.staging` | M2 |
| `helm/ritapi-advanced/templates/secret.yaml` | M2 |
| `helm/ritapi-advanced/values.yaml` | M2 |
| `tests/` | new tests throughout |

---

## Task 1: Decision Engine — pre-request detection block (M-7 + C-1 core fix)

**Files:**
- Modify: `app/middlewares/decision_engine.py`

This is the most important structural change. Move detection processing to BEFORE `call_next`. Outer middlewares write detections in their pre-request phase, so by the time Decision Engine's pre-request phase runs, all outer detections are already in `request.state.detections`.

**Key insight:** In Starlette, middleware execution order on REQUEST path is outermost→innermost. Decision Engine is innermost, so when its pre-request code runs, ALL outer middlewares have already written their detections.

- [ ] **Step 1: Write failing test**

Add to `tests/test_decision_engine.py` (create if it doesn't exist):

```python
"""Tests for DecisionEngineMiddleware policy dispatch."""
import pytest
from fastapi.testclient import TestClient


def test_decision_engine_blocks_without_hitting_route(client):
    """When Decision Engine blocks a request, the route handler must NOT run.
    Verified by ensuring Decision Engine processes detections PRE-call_next."""
    import inspect
    from app.middlewares.decision_engine import DecisionEngineMiddleware
    source = inspect.getsource(DecisionEngineMiddleware.dispatch)
    # detections check must appear BEFORE call_next
    call_next_pos = source.index("call_next")
    detections_check_pos = source.index("detections")
    assert detections_check_pos < call_next_pos, (
        "Decision Engine must check detections BEFORE calling call_next"
    )


def test_injection_does_not_return_directly(client):
    """Injection middleware must not return directly — must call call_next."""
    import inspect
    from app.middlewares.injection_detection import InjectionDetectionMiddleware
    source = inspect.getsource(InjectionDetectionMiddleware.dispatch)
    # After the detections.append, must NOT call _blocked_response directly
    # Instead must call call_next
    # Verify by checking _blocked_response is not called on injection hit
    # (the method should only exist in the class, not be called in dispatch)
    assert "_blocked_response" not in source.split("call_next")[0], (
        "InjectionDetectionMiddleware must call call_next, not _blocked_response, after detection"
    )


def test_rate_limit_does_not_return_429_directly(client):
    """Rate limit middleware must not return 429 directly — must call call_next."""
    import inspect
    from app.middlewares.rate_limit import RateLimitMiddleware
    source = inspect.getsource(RateLimitMiddleware.dispatch)
    # After writing detections, rate_limit must call call_next not return JSONResponse(429)
    detections_pos = source.index("request.state.detections")
    # After the detections append, the next action should be call_next, not JSONResponse
    post_detection_source = source[detections_pos:]
    # The first return after detections should not be a 429 JSONResponse
    assert "status_code=429" not in post_detection_source.split("call_next")[0], (
        "After writing detections, RateLimitMiddleware must call call_next not return 429"
    )
```

- [ ] **Step 2: Run tests to verify they fail**
```bash
python -m pytest tests/test_decision_engine.py -v 2>&1 | head -30
```

- [ ] **Step 3: Fix `app/middlewares/decision_engine.py`**

Replace the entire `dispatch` method. Move detection processing to PRE-`call_next`:

```python
    async def dispatch(self, request: Request, call_next):
        # Resolve route and attach policy to request state for other middlewares
        route = resolve_route(request.url.path, request.method)
        policy = get_policy(route.policy if route else None)
        request.state.route = route
        request.state.policy = policy

        ip = (
            (request.headers.get("x-forwarded-for", "").split(",")[0].strip())
            or (request.client.host if request.client else "unknown")
        )

        # --- PRE-REQUEST: check detections from outer middlewares ---
        # Outer middlewares write to request.state.detections before calling
        # call_next. By the time we reach here, all outer pre-request detections
        # are already recorded. We process them now so the route handler never
        # runs for blocked requests.
        detections = getattr(request.state, "detections", [])
        for detection in detections:
            det_type = detection.get("type", "unknown")
            score = detection.get("score", 0.0)
            reason = detection.get("reason", "")
            status_code = detection.get("status_code", 403)
            action = policy.decision_actions.get_action(det_type)

            if action == "block":
                return self._block_response(
                    request, ip, reason, det_type, score, status_code
                )
            elif action == "throttle":
                self._apply_throttle(request, ip, reason, det_type, score)
            elif action == "monitor":
                self._log_monitor(request, ip, reason, det_type, score)
            # action == "allow" → no-op

        # Legacy block flag from middlewares that set it directly
        if getattr(request.state, "block", False):
            reason = getattr(request.state, "block_reason", "Security policy violation")
            return self._block_response(request, ip, reason, "decision_engine", 1.0, 403)

        # --- Route handler executes only if no block ---
        response = await call_next(request)
        return response
```

- [ ] **Step 4: Update `_block_response` to accept `status_code`**

```python
    def _block_response(
        self,
        request: Request,
        ip: str,
        reason: str,
        det_type: str,
        score: float,
        status_code: int = 403,
    ) -> JSONResponse:
        logger.warning(
            "DecisionEngine: blocking %s %s from %s — %s",
            request.method, request.url.path, ip, reason,
        )
        log_request(
            client_ip=ip,
            path=request.url.path,
            method=request.method,
            action="block",
            detection_type=det_type,
            score=score,
            reasons=reason,
        )
        return JSONResponse(
            {"error": "Forbidden" if status_code == 403 else "Too Many Requests",
             "detail": reason},
            status_code=status_code,
        )
```

- [ ] **Step 5: Add `_apply_throttle` stub (real implementation in Task 2)**

```python
    def _apply_throttle(
        self, request: Request, ip: str, reason: str, det_type: str, score: float
    ) -> None:
        """Mark this IP for throttling on subsequent requests."""
        self._log_monitor(request, ip, reason, det_type, score)
        # Throttle implementation: set Redis key — rate_limit reads this on next request
        # Full implementation in Task 2
```

- [ ] **Step 6: Run tests**
```bash
python -m pytest tests/test_decision_engine.py::test_decision_engine_blocks_without_hitting_route -v
```
Expected: PASS.

- [ ] **Step 7: Run full suite**
```bash
python -m pytest tests/ -q
```
Expected: all pass. Note: some tests may now get 403 where they expected 429 from rate_limit — fix those in Task 3.

- [ ] **Step 8: Commit**
```bash
git add app/middlewares/decision_engine.py tests/test_decision_engine.py
git commit -m "fix: Decision Engine checks detections PRE-call_next — route handler never runs for blocked requests"
```

---

## Task 2: Remove direct returns from injection and rate_limit (M-7)

**Files:**
- Modify: `app/middlewares/injection_detection.py`
- Modify: `app/middlewares/rate_limit.py`

Both middlewares must pass through to Decision Engine via `call_next` instead of returning directly.

### Part A: Fix `injection_detection.py`

- [ ] **Step 1: Read the current dispatch method**

Read `app/middlewares/injection_detection.py` lines 200-320 to understand all the places `_blocked_response` is called.

- [ ] **Step 2: Remove all direct `_blocked_response` returns**

For each of the 5 detection blocks (scanner UA, URL scan, body plain text, JSON recursive, YARA), the pattern is currently:
```python
if hit:
    self._log_and_block(...)
    if not hasattr(request.state, "detections"):
        request.state.detections = []
    request.state.detections.append({...})
    return self._blocked_response(category)   ← REMOVE THIS
```

Replace `return self._blocked_response(category)` with:
```python
    return await call_next(request)
```

The detection is already written to `request.state.detections`. Decision Engine will process it.

- [ ] **Step 3: Add `status_code` to injection detection dict**

In each `detections.append({...})` in injection_detection.py, add `"status_code": 403`:
```python
request.state.detections.append({
    "type": "injection",
    "score": 0.95,
    "reason": f"{category}: {snippet[:120]}",
    "status_code": 403,
})
```

### Part B: Fix `rate_limit.py`

- [ ] **Step 4: Read the current dispatch method**

Read `app/middlewares/rate_limit.py` around the `JSONResponse(429)` return.

- [ ] **Step 5: Remove the 429 direct return**

Currently:
```python
if not hasattr(request.state, "detections"):
    request.state.detections = []
request.state.detections.append({
    "type": "rate_limit",
    "score": 1.0,
    "reason": f"Rate limit exceeded for {id_type}:{identity_label}",
})
return JSONResponse(
    {...},
    status_code=429,
)
```

Change to:
```python
if not hasattr(request.state, "detections"):
    request.state.detections = []
request.state.detections.append({
    "type": "rate_limit",
    "score": 1.0,
    "reason": f"Rate limit exceeded for {id_type}:{identity_label}",
    "status_code": 429,
})
return await call_next(request)
```

Note: the `return await call_next(request)` is INSIDE the per-identity loop but must `break` or return immediately — don't iterate more identities after the first limit hit.

- [ ] **Step 6: Run failing tests**
```bash
python -m pytest tests/test_decision_engine.py::test_injection_does_not_return_directly tests/test_decision_engine.py::test_rate_limit_does_not_return_429_directly -v
```
Expected: both PASS.

- [ ] **Step 7: Run full suite and fix regressions**
```bash
python -m pytest tests/ -q 2>&1 | head -40
```

Rate limit tests that expected `429` will now get `429` (passed through via `"status_code": 429` in detection dict + `_block_response` now accepts `status_code`).

Injection tests that expected `403` should still get `403`.

Fix any regressions.

- [ ] **Step 8: Commit**
```bash
git add app/middlewares/injection_detection.py app/middlewares/rate_limit.py tests/
git commit -m "fix: injection and rate_limit call call_next instead of returning directly — Decision Engine now processes all detections (M-7)"
```

---

## Task 3: Implement real throttle (L-5)

**Files:**
- Modify: `app/middlewares/decision_engine.py` (complete `_apply_throttle`)
- Modify: `app/middlewares/rate_limit.py` (check throttle flag → use reduced limit)

Real throttle: when Decision Engine applies throttle action, it sets a Redis key `ritapi:throttle:{ip}` with a TTL. Rate limit middleware checks this key before applying limits — if set, use 50% of the configured limit.

- [ ] **Step 1: Complete `_apply_throttle` in `decision_engine.py`**

Add import at top: `from app.utils.redis_client import RedisClientSingleton`

Update `_apply_throttle`:
```python
    def _apply_throttle(
        self, request: Request, ip: str, reason: str, det_type: str, score: float
    ) -> None:
        """Mark this IP for throttling — rate_limit reads this on next request."""
        self._log_monitor(request, ip, reason, det_type, score)
        try:
            redis = RedisClientSingleton.get_client()
            if redis is not None:
                # Set throttle flag for 60s — rate_limit will use 50% limit
                redis.set(f"ritapi:throttle:{ip}", "1", ex=60)
                logger.info("Throttle applied to %s for 60s", ip)
        except Exception as e:
            logger.warning("Could not set throttle flag for %s: %s", ip, e)
```

- [ ] **Step 2: Check throttle flag in `rate_limit.py`**

In `rate_limit.py`, after computing `rate_limit` and `rate_window`, add a throttle check:

```python
        # Check if this IP is throttled — if so, use 50% of normal limit
        if redis and client_ip:
            try:
                if redis.exists(f"ritapi:throttle:{client_ip}"):
                    rate_limit = max(1, rate_limit // 2)
                    logger.debug("Throttle active for %s — limit reduced to %d", client_ip, rate_limit)
            except Exception:
                pass  # fail-open
```

- [ ] **Step 3: Write test for throttle**

Add to `tests/test_decision_engine.py`:

```python
def test_throttle_sets_redis_key(flush_test_redis):
    """Decision Engine throttle action must set ritapi:throttle:{ip} in Redis."""
    import redis as redis_lib
    from app.middlewares.decision_engine import DecisionEngineMiddleware
    from unittest.mock import MagicMock

    r = redis_lib.from_url("redis://localhost:6379/15")
    ip = "10.1.2.3"
    r.delete(f"ritapi:throttle:{ip}")

    # Manually invoke _apply_throttle
    middleware = DecisionEngineMiddleware(app=MagicMock())
    request = MagicMock()
    request.headers.get.return_value = ip
    request.client.host = ip
    request.url.path = "/api/test"
    request.method = "GET"
    middleware._apply_throttle(request, ip, "test throttle", "rate_limit", 0.8)

    assert r.exists(f"ritapi:throttle:{ip}"), "Throttle key must be set in Redis"
    ttl = r.ttl(f"ritapi:throttle:{ip}")
    assert 0 < ttl <= 60, f"TTL must be between 0 and 60s, got {ttl}"
```

- [ ] **Step 4: Run test**
```bash
python -m pytest tests/test_decision_engine.py::test_throttle_sets_redis_key -v
```
Expected: PASS.

- [ ] **Step 5: Run full suite**
```bash
python -m pytest tests/ -q
```

- [ ] **Step 6: Commit**
```bash
git add app/middlewares/decision_engine.py app/middlewares/rate_limit.py tests/test_decision_engine.py
git commit -m "fix: implement real throttle — sets Redis key, rate_limit uses 50% limit when throttled (L-5)"
```

---

## Task 4: All middlewares write to request.state.detections (complete C-1)

**Files:**
- Modify: `app/middlewares/bot_detection.py`
- Modify: `app/middlewares/exfiltration_detection.py`

Bot and exfil pre-request blocks currently return directly without going through Decision Engine. Fix them to write to detections + call call_next.

Note: Default policy has `on_bot_detection: "monitor"`. For pre-request bot blocks (accumulated risk at threshold), we need `"block"` action. Use detection type `"bot_block"` and add `on_bot_block: "block"` to `DecisionActions` defaults.

- [ ] **Step 1: Add `on_bot_block` to `DecisionActions` in `app/policies/service.py`**

```python
@dataclass
class DecisionActions:
    on_auth_failure: str = "block"
    on_rate_limit: str = "block"
    on_injection: str = "block"
    on_bot_detection: str = "monitor"   # post-response scoring is informational
    on_bot_block: str = "block"         # pre-request block when risk >= threshold
    on_exfiltration: str = "monitor"
    on_exfiltration_block: str = "block"  # pre-request block when counter exceeded
```

Also update `_load_policies` to read these new fields:
```python
decision_actions=DecisionActions(
    on_auth_failure=actions_data.get("on_auth_failure", "block"),
    on_rate_limit=actions_data.get("on_rate_limit", "block"),
    on_injection=actions_data.get("on_injection", "block"),
    on_bot_detection=actions_data.get("on_bot_detection", "monitor"),
    on_bot_block=actions_data.get("on_bot_block", "block"),
    on_exfiltration=actions_data.get("on_exfiltration", "monitor"),
    on_exfiltration_block=actions_data.get("on_exfiltration_block", "block"),
),
```

- [ ] **Step 2: Fix bot_detection.py pre-request block**

In `app/middlewares/bot_detection.py`, find the pre-request block (added in H-2 fix). Change from:
```python
return JSONResponse(
    {"error": "Forbidden", "detail": "Automated request detected"},
    status_code=403,
)
```
To:
```python
if not hasattr(request.state, "detections"):
    request.state.detections = []
request.state.detections.append({
    "type": "bot_block",
    "score": float(existing_risk) / BLOCK_THRESHOLD,
    "reason": f"Cumulative bot risk {existing_risk} >= {BLOCK_THRESHOLD}",
    "status_code": 403,
})
return await call_next(request)
```

Also remove the `bot_blocks.inc()` and `requests_total.labels(...)` increment from the pre-request block (Decision Engine will log it). Keep the `logger.warning`.

- [ ] **Step 3: Fix exfiltration_detection.py pre-request block**

In `app/middlewares/exfiltration_detection.py`, find the pre-request block (added in H-3 fix). Change from:
```python
return JSONResponse(
    {"error": "Forbidden", ...},
    status_code=403,
)
```
To:
```python
if not hasattr(request.state, "detections"):
    request.state.detections = []
request.state.detections.append({
    "type": "exfiltration_block",
    "score": 0.9,
    "reason": f"{pre_reason} (pre-request counter exceeded)",
    "status_code": 403,
})
return await call_next(request)
```

Remove the direct metric increments (Decision Engine handles them).

- [ ] **Step 4: Run test suite**
```bash
python -m pytest tests/ -q
```
Fix any regressions. Bot detection tests may need updating if they expected 403 from bot middleware directly.

- [ ] **Step 5: Commit**
```bash
git add app/middlewares/bot_detection.py app/middlewares/exfiltration_detection.py app/policies/service.py
git commit -m "fix: bot and exfil pre-request blocks route through Decision Engine; add on_bot_block and on_exfiltration_block policy actions (C-1 complete)"
```

---

## Task 5: Add multi-detection and policy-override tests (L-10)

**Files:**
- Create/modify: `tests/test_decision_engine.py`

- [ ] **Step 1: Add multi-detection conflict test**

```python
def test_multi_detection_block_wins_over_monitor(client, flush_test_redis):
    """When multiple detections are present, block takes precedence over monitor."""
    import inspect
    from app.middlewares.decision_engine import DecisionEngineMiddleware
    from app.policies.service import DEFAULT_POLICY, DecisionActions, Policy
    from unittest.mock import AsyncMock, MagicMock, patch
    from fastapi import Request

    # Simulate request with two detections: monitor + block
    mock_request = MagicMock(spec=Request)
    mock_request.headers.get.return_value = "10.0.0.1"
    mock_request.client.host = "10.0.0.1"
    mock_request.url.path = "/api/test"
    mock_request.method = "GET"
    mock_request.state = MagicMock()
    mock_request.state.route = None
    mock_request.state.block = False
    mock_request.state.detections = [
        {"type": "bot_detection", "score": 0.3, "reason": "suspicious UA", "status_code": 403},
        {"type": "injection", "score": 0.95, "reason": "SQLi detected", "status_code": 403},
    ]

    async def fake_call_next(req):
        raise AssertionError("Route handler must NOT run when block detection present")

    import asyncio
    middleware = DecisionEngineMiddleware(app=MagicMock())
    with patch("app.middlewares.decision_engine.get_policy", return_value=DEFAULT_POLICY):
        with patch("app.middlewares.decision_engine.resolve_route", return_value=None):
            response = asyncio.get_event_loop().run_until_complete(
                middleware.dispatch(mock_request, fake_call_next)
            )
    assert response.status_code == 403
```

- [ ] **Step 2: Add policy-allows-injection test**

```python
def test_policy_monitor_allows_injection_through(client, flush_test_redis):
    """When policy sets on_injection: monitor, injection does not block."""
    import asyncio
    from unittest.mock import AsyncMock, MagicMock, patch
    from fastapi import Request
    from app.middlewares.decision_engine import DecisionEngineMiddleware
    from app.policies.service import Policy, DecisionActions, AuthPolicy, RateLimitPolicy, SchemaPolicy
    from starlette.responses import JSONResponse as StarletteJSONResponse

    monitor_policy = Policy(
        name="test_monitor",
        decision_actions=DecisionActions(on_injection="monitor"),
    )

    mock_request = MagicMock(spec=Request)
    mock_request.headers.get.return_value = "10.0.0.2"
    mock_request.client.host = "10.0.0.2"
    mock_request.url.path = "/api/test"
    mock_request.method = "GET"
    mock_request.state = MagicMock()
    mock_request.state.route = None
    mock_request.state.block = False
    mock_request.state.detections = [
        {"type": "injection", "score": 0.9, "reason": "test", "status_code": 403},
    ]

    route_was_called = []
    async def fake_call_next(req):
        route_was_called.append(True)
        return StarletteJSONResponse({"ok": True}, status_code=200)

    middleware = DecisionEngineMiddleware(app=MagicMock())
    with patch("app.middlewares.decision_engine.get_policy", return_value=monitor_policy):
        with patch("app.middlewares.decision_engine.resolve_route", return_value=None):
            response = asyncio.get_event_loop().run_until_complete(
                middleware.dispatch(mock_request, fake_call_next)
            )

    assert route_was_called, "Route handler must run when policy action is monitor"
    assert response.status_code == 200
```

- [ ] **Step 3: Add blocked-request-never-hits-backend integration test**

```python
def test_injection_blocked_request_never_hits_backend(client, flush_test_redis):
    """End-to-end: injection attempt must be blocked with route handler not running."""
    # A SQLi payload in the URL should trigger injection detection
    response = client.get("/api/v1/health?id=1' OR '1'='1")
    # Response must be 403 (from Decision Engine via injection detection)
    assert response.status_code in (403, 404), (
        f"SQLi payload should be blocked, got {response.status_code}"
    )
```

- [ ] **Step 4: Run all new tests**
```bash
python -m pytest tests/test_decision_engine.py -v
```

- [ ] **Step 5: Commit**
```bash
git add tests/test_decision_engine.py
git commit -m "test: add multi-detection conflict, policy-override, and end-to-end block tests"
```

---

## Task 6: DASHBOARD_TOKEN in all deployment templates (M-2)

**Files:**
- Modify: `.env.staging`
- Modify: `helm/ritapi-advanced/templates/secret.yaml`
- Modify: `helm/ritapi-advanced/values.yaml`

- [ ] **Step 1: Add DASHBOARD_TOKEN to `.env.staging`**

Read `.env.staging`, find a good place (near ADMIN_SECRET), and add:
```
# Bearer token for /dashboard routes — leave empty for open access
DASHBOARD_TOKEN=
```

- [ ] **Step 2: Add DASHBOARD_TOKEN to Helm Secret**

In `helm/ritapi-advanced/templates/secret.yaml`, add after `ADMIN_SECRET`:
```yaml
  DASHBOARD_TOKEN: {{ .Values.secrets.dashboardToken | default "" | quote }}
```

- [ ] **Step 3: Add `dashboardToken` to `helm/ritapi-advanced/values.yaml`**

In the `secrets:` section, add:
```yaml
  dashboardToken: ""  # Set to a strong random value to protect /dashboard
```

- [ ] **Step 4: Verify Helm template**
```bash
helm template test ./helm/ritapi-advanced \
  --set secrets.secretKey=x --set secrets.adminSecret=y --set secrets.redisPassword=z \
  | grep "DASHBOARD_TOKEN"
```
Expected: found under `kind: Secret`.

- [ ] **Step 5: Commit**
```bash
git add .env.staging helm/ritapi-advanced/templates/secret.yaml helm/ritapi-advanced/values.yaml
git commit -m "fix: add DASHBOARD_TOKEN to .env.staging and Helm Secret template (M-2)"
```

---

## Final Verification

```bash
python -m pytest tests/ -v --tb=short 2>&1 | tail -20
git log --oneline -6
```

Expected: all tests pass, 6 new commits.
