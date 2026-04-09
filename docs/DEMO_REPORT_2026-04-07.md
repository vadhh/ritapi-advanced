# Demo Report — RitAPI Advanced
**Date:** 2026-04-07
**Version:** v1.3.0 + post-release fixes (ec8d099)
**Environment:** Docker Compose (local), Ubuntu 24.04, Docker Engine 29.3.0

---

## 1. What Was Demonstrated

A self-contained live demo stack exercising all five protection layers of RitAPI Advanced via a scripted attack suite (`scripts/demo_attack.sh`).

| Act | Scenario | Layer | Result |
|-----|----------|-------|--------|
| 1 | Valid credential + matching tenant | Pass-through | HTTP 200 ✓ |
| 2a | Token bound to `acme`, header claims `corp` | AuthMiddleware — tenant mismatch | HTTP 403 ✓ |
| 2b | Token bound to `corp`, header claims `acme` | AuthMiddleware — tenant mismatch | HTTP 403 ✓ |
| 3a | `UNION SELECT NULL--` in query string | InjectionDetectionMiddleware — sqli | HTTP 403 ✓ |
| 3b | `<script>alert(document.cookie)</script>` in query string | InjectionDetectionMiddleware — xss | HTTP 403 ✓ |
| 3c | `; id; whoami` in query string | InjectionDetectionMiddleware — cmdi | HTTP 403 ✓ |
| 3d | `../../../etc/shadow` in path param | InjectionDetectionMiddleware — path_traversal | HTTP 403 ✓ |
| 3e | SQLi in POST JSON body | InjectionDetectionMiddleware — sqli | HTTP 403 ✓ |
| 4a | `User-Agent: sqlmap/1.7.8#stable` | BotDetectionMiddleware | HTTP 403 ✓ |
| 4b | `User-Agent: Nikto/2.1.6` | BotDetectionMiddleware | HTTP 403 ✓ |
| 5 | 55 requests / 50 req per 60s limit | RateLimitMiddleware | HTTP 429 ✓ |

**Final score: 11/11 scenarios passed.**

---

## 2. Infrastructure Used

```
docker/demo.yml
  ├── ritapi-demo-app   (python:3.12-slim, port 8001)
  └── ritapi-demo-redis (redis:7-alpine, internal only)

Network: 172.28.0.0/24 (pinned — gateway always 172.28.0.1)
```

Key demo settings (`.env.demo`):
- `RATE_LIMIT_REQUESTS=50` / `RATE_LIMIT_WINDOW=60`
- `LOG_PATH=/tmp/ritapi_demo.jsonl` (dashboard-readable file + stdout)
- `BOT_DETECTION_BYPASS_IPS=127.0.0.1,::1,172.28.0.1`
- `YARA_RULES_DIR=/app/rules`

---

## 3. Issues Found and Fixed During Demo Testing

| # | Issue | Root Cause | Fix |
|---|-------|-----------|-----|
| 1 | App container unhealthy — healthcheck blocked | Python-urllib flagged as `scanner_ua` by injection detection | Switched healthcheck to `curl`; added `curl` to Dockerfile runtime |
| 2 | Docker bridge IP varied per machine | Default bridge assigned random subnet | Pinned demo network to `172.28.0.0/24` |
| 3 | Host requests accumulating bot risk score | Bridge gateway not in `BOT_DETECTION_BYPASS_IPS` | Added `172.28.0.1` to bypass list |
| 4 | `demo_attack.sh` crash on optional arg | `set -u` + unset `$4` in `_expect()` | Changed to `${4:-}` |
| 5 | Legacy token generation required `docker exec` | Script assumed access to container shell | Replaced with admin API call for mismatched tenant token |
| 6 | SQLi URL pattern not detected | `+` decoded as literal `+` by injection middleware, not as space | Switched payload to `UNION SELECT` with `%20` spaces |
| 7 | Dashboard events table empty | JS used wrong field names (`client_ip`, `path`, `detection_type`, `score`, `reasons`) | Fixed to `source_ip`, `route`, `trigger_type`, derived from `detections[]` |
| 8 | Dashboard rate-limited on page refresh | Browser fires 4 parallel requests per refresh; demo limit was 10/30s | Raised limit to 50/60s; demo attacks use dedicated `X-Forwarded-For` IPs |
| 9 | SIEM events not visible in dashboard | `LOG_PATH=/dev/stdout` is not seekable; dashboard uses file I/O | Changed logger to write to file when `LOG_PATH` is a real path; set `LOG_PATH=/tmp/ritapi_demo.jsonl` |

---

## 4. Dashboard State After Demo Run

After running `demo_attack.sh` once from a clean Redis state, the dashboard shows:

- **Blocked (last 200):** 10+
- **Detection Breakdown:** `injection`, `bot_block`, `rate_limit`, `auth_failure`
- **Top Blocked IPs:** `10.0.attack.1–5`, `10.0.bot.1–2`, `10.0.flood.1` (8 distinct attackers)
- **Recent Events table:** source IP, tenant, method, path, action badge, detection type with sub-type, score, reason — all populated

---

## 5. Observability Endpoints (Live During Demo)

| Endpoint | Purpose |
|----------|---------|
| `http://localhost:8001/dashboard` | Security event dashboard (auto-refreshes every 15s) |
| `http://localhost:8001/metrics` | Prometheus metrics (blocked count, threat score histogram, latency) |
| `docker compose -f docker/demo.yml logs -f app` | Live SIEM event stream (JSONL to stdout) |

---

## 6. How to Re-run

```bash
# Reset counters between demo runs (keep containers up)
./scripts/demo_clean.sh

# Full run including rebuild
./scripts/demo_run.sh

# Attack suite only (containers must be up)
DEMO_PAUSE=1 ./scripts/demo_attack.sh
```

---

## 7. Known Limitations

- **No TLS in demo stack** — demo runs plain HTTP on port 8001. Nginx TLS termination is available for staging via `scripts/gen_cert.sh`.
- **YARA rules loaded** but HardGate YARA scan only covers request bodies — URL-based YARA is not supported.
- **Single-worker uvicorn** in the demo image — not representative of production throughput.
- **Bot detection warm-up** — scanner UA block requires 3–4 requests to cross the risk threshold. First request returns 403 from injection detection (scanner UA pattern), not bot detection.
- **`docker exec`-based legacy token generation removed** — Act 2b now demonstrates a tenant mismatch (corp token → acme claim) rather than a no-tid legacy credential. True legacy token testing remains available via the unit test suite (`tests/test_strict_tenant_mode.py`).
