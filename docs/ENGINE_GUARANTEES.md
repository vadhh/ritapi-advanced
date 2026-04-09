# Engine Guarantees

These are architectural invariants enforced by RitAPI Advanced's middleware stack.
They are not aspirational — they are tested, verified, and must be preserved across
all future changes.

---

## G1 — All blocks go through DecisionEngine

Every enforcement decision (403, 429, 401) is issued by `DecisionEngineMiddleware`
(`app/middlewares/decision_engine.py`), the innermost middleware.

Upstream middlewares (RateLimit, InjectionDetection, BotDetection, Exfiltration,
HardGate) **do not return responses directly**. They append structured detection
objects to `request.state.detections` via `append_detection()` and call
`call_next()`. DecisionEngine is the sole authority that converts detections into
HTTP responses.

The only exception is `HardGateMiddleware` (Tier 1), which performs unconditional
pre-detection blocks (known-bad IPs, DDoS spikes, YARA matches) before the
detection stack runs. This is intentional and documented separately.

**Regression test:** `test_decision_engine_always_in_middleware_stack`

---

## G2 — Backend never executes on block

When any detection resolves to a `block` action under the active policy, the route
handler is **never called**. DecisionEngine returns the error response before
`call_next(request)` is reached.

This is enforced structurally: all detection processing happens in the pre-request
phase of `dispatch()`, prior to the `await call_next(request)` call. A static
source inspection test (`test_decision_engine_checks_detections_before_call_next`)
verifies this ordering at the code level.

**Regression tests:**
- `test_block_detection_prevents_route_handler`
- `test_decision_engine_checks_detections_before_call_next`

---

## G3 — Tenant ID is always verified before use

`tenant_id` on `request.state` is set exclusively by `AuthMiddleware` after a
credential (JWT or API key) has been cryptographically verified. Unauthenticated
requests carry `tenant_id = None`.

No middleware or route handler may trust a `tenant_id` value that arrived in a
request header directly. All policy lookups, Redis key namespacing, and rate limit
counters use the verified value from `request.state.tenant_id`.

Unverified requests are identified in SIEM events as `tenant_status = "unauthenticated"`.

---

## G4 — No detection middleware may directly return 403 or 429

Detection middlewares (`RateLimitMiddleware`, `InjectionDetectionMiddleware`,
`BotDetectionMiddleware`, `ExfiltrationDetectionMiddleware`) must not return
`JSONResponse` with status 403 or 429 themselves. They write to
`request.state.detections` and yield to the next middleware via `call_next()`.

This guarantee exists so that:
- All enforcement decisions are policy-driven and tenant-scoped.
- Every block is logged through a single code path (`_block_response`) with
  consistent SIEM fields.
- Policy overrides (e.g. `on_injection: monitor`) are respected — a middleware
  that hard-codes a 403 would bypass the policy layer entirely.

**Regression tests:**
- `test_injection_calls_call_next_not_blocked_response`
- `test_rate_limit_calls_call_next_not_jsonresponse_429`

---

## Invariant summary

| # | Guarantee | Enforced by | Tested |
|---|-----------|-------------|--------|
| G1 | All blocks go through DecisionEngine | Middleware architecture | Yes |
| G2 | Backend never executes on block | Pre-request detection processing | Yes |
| G3 | Tenant ID is always verified | AuthMiddleware / state isolation | Yes |
| G4 | No middleware returns 403/429 directly | Detection-only contract | Yes |

---

## Violation protocol

If a future change must break one of these guarantees, the following steps are
required before merging:

1. Document the exception explicitly in this file under a new section.
2. Update or add regression tests to cover the new behaviour.
3. Get sign-off from a second reviewer who has read this document.

Breaking a guarantee silently is a critical defect.
