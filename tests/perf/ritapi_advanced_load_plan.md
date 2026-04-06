# RitAPI Advanced — Load Test Plan

**Version:** 1.0  
**Date:** 2026-04-02  
**Stage:** 4 — Testing / QA  
**Tool:** [Locust](https://locust.io) (`pip install locust`)  
**Runner scripts:** `tests/perf/locustfile_*.py`

---

## Prerequisites

```bash
# Install Locust (not in requirements.txt — perf-only dependency)
pip install locust

# Start the service under test
cp .env.example .env          # set SECRET_KEY, ADMIN_SECRET, REDIS_URL
docker compose -f docker/redis-standalone.yml up -d
uvicorn app.main:app --host 0.0.0.0 --port 8001 --workers 2

# Obtain a VIEWER JWT for clean-traffic scenarios
curl -s -X POST http://localhost:8001/admin/token \
  -H "X-Admin-Secret: $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"subject":"perf-runner","role":"VIEWER","tenant_id":"perf-tenant"}' \
  | python3 -m json.tool
# Copy access_token → PERF_JWT env var
export PERF_JWT="<token>"
```

---

## Scenarios

### S1 — Clean Traffic (Baseline)

**Goal:** Establish baseline latency and throughput for authenticated GET requests that pass all middleware with no detections.

**Config:**

| Parameter | Value |
|-----------|-------|
| Users | 50 concurrent |
| Spawn rate | 5/s |
| Duration | 5 min |
| Target path | `GET /healthz` (no auth), `GET /api/v1/status` (JWT auth) |
| Auth | `Authorization: Bearer $PERF_JWT` |
| User-Agent | `perf-runner/1.0` |
| Tenant | `X-Target-ID: perf-tenant` |

**Expected outcomes:**

- `GET /healthz` → 100 % `200`, p95 < 5 ms
- Authenticated route → 100 % `200` or `404` (route may not exist; never `429`/`403`)
- No `auth_failure` detections in logs
- Redis rate counters increment on every request, no pipeline errors

**Pass criteria:**

- p95 latency ≤ 50 ms
- Error rate (non-2xx/4xx-expected) = 0 %
- `ritapi_requests_total{action="block"}` counter unchanged from baseline

---

### S2 — Bot Traffic (Behavioral Detection)

**Goal:** Confirm bot detection fires and blocks before reaching the route handler under sustained automated-looking traffic.

**Config:**

| Parameter | Value |
|-----------|-------|
| Users | 20 concurrent |
| Spawn rate | 20/s (instant burst) |
| Duration | 3 min |
| Target paths | Rotating: `/api/v1/a`, `/api/v1/b`, … `/api/v1/o` (15+ distinct endpoints) |
| Auth | No auth header |
| User-Agent | `python-requests/2.31.0` (matches `_SUSPICIOUS_UA_TOKENS`) |
| Request rate | 60 req/s per simulated IP |

**Triggered rules:**

| Rule | Threshold | Expected signal |
|------|-----------|-----------------|
| `NO_USER_AGENT` / `SUSPICIOUS_USER_AGENT` | n/a — score 50–60 | fired on every request |
| `RAPID_FIRE` | 50 req / 10 s | fires after ~8 s per IP |
| `BURST_TRAFFIC` | 100 req / 60 s | fires after ~1.5 s per IP at 60 rps |
| `ENDPOINT_SCANNING` | 15 distinct paths / 5 min | fires when >15 paths visited |

**Expected outcomes:**

- `ritapi_bot_signals_total` increments for `RAPID_FIRE`, `BURST_TRAFFIC`, `ENDPOINT_SCANNING`
- `ritapi_bot_blocks_total` increments (cumulative score ≥ 70 threshold)
- Blocked responses are `403` with `{"detail": …}` JSON body
- Decision-engine SIEM log emits `"action":"block","trigger_type":"bot_block"` events
- No crash or panic in uvicorn process

**Pass criteria:**

- ≥ 95 % of requests after warm-up (first 30 s) return `403`
- `ritapi_bot_blocks_total` > 0 within 60 s of test start
- Server p95 latency for `403` responses ≤ 80 ms (detection overhead within budget)
- Locust reports 0 connection errors (only HTTP-level 4xx)

---

### S3 — Injection Block (WAF Regex)

**Goal:** Confirm injection detection catches and blocks SQLi/XSS payloads at full request rate without latency blowup from regex scanning.

**Config:**

| Parameter | Value |
|-----------|-------|
| Users | 30 concurrent |
| Spawn rate | 10/s |
| Duration | 3 min |
| Target path | `POST /api/v1/search` |
| Auth | `Authorization: Bearer $PERF_JWT` |
| Payload rotation | 4 payloads (see below), cycled round-robin |
| Content-Type | `application/json` |

**Payloads (round-robin):**

```json
// Payload 1 — SQLi
{"q": "' OR '1'='1"}

// Payload 2 — XSS
{"q": "<script>alert(1)</script>"}

// Payload 3 — CMDi
{"q": "; ls -la /etc/passwd"}

// Payload 4 — clean (to measure mixed-traffic ratio)
{"q": "normal search term"}
```

**Expected outcomes:**

- Payloads 1–3 → `403`, body: `{"detail":"Request blocked: injection detected"}`
- Payload 4 → `200` or `404` (passes WAF)
- `ritapi_injection_blocks_total` increments for `sqli`, `xss`, `cmdi` categories
- SIEM log: `"action":"block","trigger_type":"injection"`
- No false positive on clean payload

**Pass criteria:**

- 100 % block rate on payloads 1–3 (zero bypass)
- 0 % block rate on payload 4
- Injection-block p95 latency ≤ 30 ms (regex scan is CPU-only, no Redis)
- `ritapi_injection_blocks_total` matches count of payloads 1–3 sent (±1 for race)

---

### S4 — Throttle (Rate Limit)

**Goal:** Confirm rate limiting kicks in at the configured threshold and degrades gracefully (429, not crash) under sustained high-rate traffic from a single IP.

**Config:**

| Parameter | Value |
|-----------|-------|
| Users | 5 (simulate single IP via shared X-Forwarded-For) |
| Spawn rate | 5/s |
| Duration | 4 min |
| Target path | `GET /api/v1/resource` |
| Auth | `Authorization: Bearer $PERF_JWT` |
| Rate | 150 req/s (exceeds default `RATE_LIMIT_REQUESTS=100`) |
| Tenant | `X-Target-ID: throttle-tenant` |

**Expected outcomes:**

- First `RATE_LIMIT_REQUESTS` (100) requests in the window → `200`/`404`
- Subsequent requests → `429` with detection type `rate_limit`
- SIEM log: `"action":"throttle","trigger_type":"rate_limit"`
- After window expires (60 s default), counter resets → `200` resumes
- `ritapi_rate_limit_hits_total{identity_type="ip"}` increments

**Pass criteria:**

- At least one `429` within the first 60 s window
- `429` rate stabilises above 50 % once window fills
- No `5xx` responses (Redis pipeline errors must not surface as 500)
- Redis pipeline call latency stable (monitor via `MONITOR` or `INFO stats`)
- SIEM log line count ≈ number of `429` responses (1 event per throttle decision)

---

## Metrics to Capture

### HTTP-level (Locust report)

| Metric | How to read |
|--------|-------------|
| Response status distribution | Locust HTML report → `Failures` tab + custom `ResponseStatsListener` |
| Average latency | Locust `stats.csv` → `Average Response Time (ms)` column |
| p95 latency | Locust `stats.csv` → `95%ile Response Time` column |
| Error rate | `(non-2xx count − expected-block count) / total * 100` |
| Requests/s throughput | Locust `stats.csv` → `Requests/s` column |

### Prometheus (scrape `/metrics` before and after each scenario)

```bash
# Snapshot before
curl -s http://localhost:8001/metrics > perf_before_s1.txt

# Run scenario
locust -f tests/perf/locustfile_s1_clean.py --headless -u 50 -r 5 -t 5m \
  --host http://localhost:8001 --csv=results/s1

# Snapshot after
curl -s http://localhost:8001/metrics > perf_after_s1.txt

# Diff counters
diff perf_before_s1.txt perf_after_s1.txt | grep '^>' | grep 'ritapi_'
```

**Key counters to diff per scenario:**

| Scenario | Counter(s) to watch |
|----------|---------------------|
| S1 clean | `ritapi_requests_total{action="allow"}` |
| S2 bot | `ritapi_bot_signals_total`, `ritapi_bot_blocks_total` |
| S3 injection | `ritapi_injection_blocks_total{category=…}` |
| S4 throttle | `ritapi_rate_limit_hits_total{identity_type="ip"}` |
| All | `ritapi_redis_connected` (must stay `1`), `ritapi_threat_score` histogram |

### Redis stability check

```bash
# Before run
redis-cli INFO stats | grep -E 'total_commands|rejected_connections|instantaneous_ops'

# During run (watch every 5 s)
watch -n 5 'redis-cli INFO stats | grep -E "total_commands|rejected|instantaneous"'

# After run
redis-cli INFO memory | grep used_memory_human
```

**Pass criteria:** `rejected_connections` = 0 throughout; `used_memory_human` growth < 20 MB above idle baseline.

### Log coherence check

```bash
# Tail SIEM events during run
tail -f /var/log/ritapi_advanced.jsonl | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
        missing = [f for f in ['request_id','tenant_id','action','trigger_type','source_ip','severity'] if f not in e]
        if missing:
            print('MISSING FIELDS:', missing, line.strip())
    except Exception as ex:
        print('PARSE ERROR:', ex, repr(line[:120]))
"
```

**Pass criteria:** Zero `MISSING FIELDS` or `PARSE ERROR` lines during the entire run.

---

## Running All Scenarios

```bash
mkdir -p results/

# S1 — Clean traffic
locust -f tests/perf/locustfile_s1_clean.py --headless \
  -u 50 -r 5 -t 5m --host http://localhost:8001 \
  --csv=results/s1 --html=results/s1_report.html

# S2 — Bot traffic
locust -f tests/perf/locustfile_s2_bot.py --headless \
  -u 20 -r 20 -t 3m --host http://localhost:8001 \
  --csv=results/s2 --html=results/s2_report.html

# S3 — Injection block
locust -f tests/perf/locustfile_s3_injection.py --headless \
  -u 30 -r 10 -t 3m --host http://localhost:8001 \
  --csv=results/s3 --html=results/s3_report.html

# S4 — Throttle
locust -f tests/perf/locustfile_s4_throttle.py --headless \
  -u 5 -r 5 -t 4m --host http://localhost:8001 \
  --csv=results/s4 --html=results/s4_report.html
```

---

## Pass / Fail Summary Table

| Scenario | Pass when… | Fail when… |
|----------|-----------|-----------|
| S1 Clean | p95 ≤ 50 ms; 0 unexpected blocks | Any `403`/`429` on clean requests |
| S2 Bot | ≥ 95 % `403` after warm-up; `bot_blocks_total` > 0 | Bot traffic reaches route handler |
| S3 Injection | 100 % block on attack payloads; 0 % on clean | Any attack payload returns `2xx`/`404` |
| S4 Throttle | `429` within 60 s window; 0 `5xx` | 5xx from Redis error; no 429 ever |
| All | `redis_connected=1`; 0 parse errors in SIEM log | `redis_connected=0`; malformed log lines |

---

## Notes

- **Locust worker mode:** For higher concurrency (>200 users), run one master and N workers:
  ```bash
  locust -f tests/perf/locustfile_s1_clean.py --master &
  locust -f tests/perf/locustfile_s1_clean.py --worker --master-host=127.0.0.1
  ```
- **Redis flush between scenarios:** `redis-cli FLUSHDB` clears counters so scenarios don't bleed into each other. Run only against a dev Redis instance.
- **BOT_DETECTION_BYPASS_IPS:** Ensure `127.0.0.1` and the Locust runner IP are NOT in this env var for S2 to work.
- **Rate limit reset:** If re-running S4, flush Redis or wait for the window (60 s) to expire before starting.
- **YARA rules:** If `YARA_RULES_DIR` is set, S3 payloads may also trigger YARA blocks — both are expected and correct. SIEM `trigger_type` will be `yara` instead of `injection`.
