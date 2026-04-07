# RitAPI Advanced — Live Demo

A self-contained demo stack that exercises every protection layer:
tenant isolation, injection WAF, bot detection, and rate limiting.

## Prerequisites

- Docker + Docker Compose v2
- `curl`, `python3` (for the attack script)
- Ports `8001` and `6379` free on localhost

## Quick Start

```bash
# 1. Launch the stack (builds image on first run)
./scripts/demo_run.sh

# 2. In a second terminal — watch SIEM events stream live
docker compose -f docker/demo.yml logs -f app
```

`demo_run.sh` will wait for the app to become healthy, then automatically
run the attack suite.

---

## Running Attacks Manually

Once the stack is up you can re-run attacks at any time without restarting:

```bash
./scripts/demo_attack.sh
```

Reset all counters between runs (rate limit, bot risk, exfil):

```bash
./scripts/demo_clean.sh
```

Full teardown:

```bash
./scripts/demo_clean.sh --down
```

---

## What Each Act Demonstrates

| Act | Scenario | Layer triggered | Expected response |
|-----|----------|-----------------|-------------------|
| 1 | Valid token + matching tenant | — (pass-through) | `200 {"backend": "executed"}` |
| 2a | Token bound to `acme`, header claims `corp` | `AuthMiddleware` | `403 Forbidden` |
| 2b | Legacy token with no tenant claim | `AuthMiddleware` | `403 Forbidden` |
| 3a | `' OR '1'='1` in query string | `InjectionDetectionMiddleware` | `403 Forbidden` |
| 3b | `<script>alert(1)</script>` in query string | `InjectionDetectionMiddleware` | `403 Forbidden` |
| 3c | `; cat /etc/passwd` in query string | `InjectionDetectionMiddleware` | `403 Forbidden` |
| 4 | `User-Agent: sqlmap/1.7.8` | `BotDetectionMiddleware` | `403 Forbidden` |
| 5 | 12 rapid requests (limit: 10 / 30 s) | `RateLimitMiddleware` | `429 Too Many Requests` |

---

## Live Observability

| URL | What it shows |
|-----|---------------|
| `http://localhost:8001/dashboard` | Real-time security event dashboard |
| `http://localhost:8001/metrics` | Prometheus metrics (blocked requests, threat scores, latency) |
| `docker compose -f docker/demo.yml logs -f app` | SIEM event stream (JSONL) |

---

## Demo Credentials

All credentials in `.env.demo` are safe to commit and intended only for this demo.
**Do not use them in production.**

| Secret | Value |
|--------|-------|
| `SECRET_KEY` | `demo-secret-ritapi-2024-not-for-production-only` |
| `ADMIN_SECRET` | `demo-admin-ritapi-2024` |
| Rate limit | 10 requests / 30 s (intentionally low) |

Tokens for `acme` and `default` tenants are issued automatically by
`demo_attack.sh` via `POST /admin/token` at the start of each run.

---

## Troubleshooting

**Stack won't start / app container exits immediately**
```bash
docker compose -f docker/demo.yml logs app
```

**`demo_attack.sh` reports "Token issuance failed"**
The app container is not ready yet. Wait for the health check to pass:
```bash
docker compose -f docker/demo.yml ps
```

**Bot detection not blocking in Act 4**
Bot detection accumulates a risk score over multiple requests. The script
fires 3 warm-up requests before the final check. If the container was just
started, Redis may still be cold — run `demo_clean.sh` and try again.

**Port 8001 already in use**
```bash
# Find and stop whatever is using it
lsof -i :8001
```
Or override the port by editing `docker/demo.yml` (`ports: - "8002:8001"`)
and setting `RITAPI_BASE_URL=http://localhost:8002` before running the scripts.
