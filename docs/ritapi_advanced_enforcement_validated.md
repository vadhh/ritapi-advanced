# RitAPI Advanced — Enforcement Checkpoint (2026-04-02)

This note records confirmed enforcement behaviors as of the current codebase.
Do not break these invariants without explicit review.

---

## 1. Exfiltration pre-request blocks before backend

**Confirmed.** `ExfiltrationDetectionMiddleware.dispatch()` reads Redis counters for
`bulk_access` and `sequential_crawl` **before** calling `call_next()`:

```
exfiltration_detection.py:99-125
```

If either counter exceeds its threshold, an `exfiltration_block` detection is appended
and the request is forwarded to `call_next()` — which reaches `DecisionEngineMiddleware`
(innermost), which issues the 403 **before** the route handler ever executes.

The backend sees nothing.

---

## 2. Injection / SQLi blocks before backend

**Confirmed.** `InjectionDetectionMiddleware.dispatch()` scans in pre-request order:

1. Scanner User-Agent (`injection_detection.py:223`)
2. URL / query string (`injection_detection.py:239`)
3. Request body — plain text, JSON recursive, YARA (`injection_detection.py:255-328`)

On any hit, an `injection` detection (score 0.95, status 403) is appended and
`call_next()` is returned immediately. `DecisionEngineMiddleware` processes the
detection and returns 403 before the route handler runs.

The backend sees nothing.

---

## 3. Bot block blocks before backend

**Confirmed.** `BotDetectionMiddleware.dispatch()` checks the **cumulative risk score**
stored in Redis **before** forwarding the request:

```
bot_detection.py:224-244
```

If `existing_risk >= BLOCK_THRESHOLD (70)`, a `bot_block` detection is appended and
`call_next()` is returned immediately — same path as above through `DecisionEngine`.

New risk accumulation (post-response) only writes to the risk key; it cannot unblock
a request already in-flight.

---

## 4. Throttle is real

**Confirmed.** Two-part mechanism:

- **DecisionEngine** sets `ritapi:{tenant_id}:throttle:{ip}` (60 s TTL) in Redis when
  action == `"throttle"` (`decision_engine.py:136-148`).
- **RateLimitMiddleware** reads that key on the **next** request and halves `rate_limit`
  for that IP (`rate_limit.py:86-88`).

Effect: throttled IPs hit their rate limit at half the normal quota on all subsequent
requests within the 60-second window.

---

## 5. Post-response detections are observation only

**Confirmed.** The following heuristics run **after** `call_next()` and are therefore
post-response observations, not pre-backend blocks:

| Middleware | Heuristic | Action |
|---|---|---|
| `ExfiltrationDetectionMiddleware` | `LARGE_RESPONSE` (> 1 MB) | monitor |
| `ExfiltrationDetectionMiddleware` | `HIGH_VOLUME` (> 10 MB/IP/5 min) | monitor |
| `BotDetectionMiddleware` | all 13 rules (need response status) | accumulate risk |

`BULK_ACCESS` and `SEQUENTIAL_CRAWL` are **blocked pre-request** on repeat requests
(counter already exceeded); the **first** request that pushes them over threshold
returns a response before the block fires — that first response is served.

---

## 6. Detections accumulate without overwrite

**Confirmed.** All middleware uses `append_detection()` from `detection_schema.py`,
which appends to `request.state.detections` (a list). No middleware clears or
overwrites a prior detection. `DecisionEngineMiddleware` reads the full list:

```
decision_engine.py:59-64
```

Multiple simultaneous detections (e.g., rate-limit + injection) are all evaluated.
The first `block` action encountered wins and short-circuits the loop.

---

## 7. DecisionEngine is the last gate before route handler

**Confirmed.** `main.py:32` registers `DecisionEngineMiddleware` first, making it
the **innermost** middleware — the last to run pre-request, first to run post-response.

Full execution order (request direction):
```
RequestID → TenantContext → HardGate → RateLimit → Auth → Schema
  → Bot → Injection → Exfil → DecisionEngine → route handler
```

`DecisionEngine` processes all accumulated detections and returns 403 before yielding
to the route handler (`decision_engine.py:92-94`). No other middleware can block after
`DecisionEngine` has decided to pass — the route handler executes unconditionally from
that point.

---

## Source files audited

| File | Last verified |
|---|---|
| `app/main.py` | 2026-04-02 |
| `app/middlewares/decision_engine.py` | 2026-04-02 |
| `app/middlewares/exfiltration_detection.py` | 2026-04-02 |
| `app/middlewares/injection_detection.py` | 2026-04-02 |
| `app/middlewares/bot_detection.py` | 2026-04-02 |
| `app/middlewares/rate_limit.py` | 2026-04-02 |
