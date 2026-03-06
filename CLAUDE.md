# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

RitAPI Advanced is a standalone FastAPI service providing layer-7 API protection: WAF (regex + YARA), rate limiting, bot detection, injection detection, exfiltration detection, JWT/API-key auth, RBAC, Prometheus metrics, and a live security dashboard.

**Current stage: Stage 4 (Testing / QA), ~40% through.**

## Stage Model

| Stage | Name | Status |
|-------|------|--------|
| 0 | Concept / Requirements | ✅ |
| 1 | Design | ✅ |
| 2 | Development (Local) | ✅ |
| 3 | Integration | ✅ |
| 4 | Testing / QA | 🔶 ~40% |
| 5 | Staging | ✗ |
| 6 | Build & Packaging | ✗ |
| 7 | Code Signing & Security Audit | ✗ |
| 8 | Distribution / Release | ✗ |
| 9 | Client Installation & Validation | ✗ |
| 10 | Production & Maintenance | ✗ |

See `TODO.md` for the full task breakdown per stage.

## Setup & Run

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # configure SECRET_KEY, REDIS_URL, etc.

# Start Redis (standalone dev)
docker compose -f docker/redis-standalone.yml up -d

uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
```

Run tests:
```bash
pytest tests/ -v
```

TLS certificates (required before starting Nginx):
```bash
sudo ./scripts/gen_cert.sh              # self-signed (dev)
sudo ./scripts/gen_cert.sh your.domain  # Let's Encrypt (prod)
```

Redis HA (Sentinel):
```bash
./scripts/redis_sentinel_setup.sh start
# Then set REDIS_SENTINEL_HOSTS=127.0.0.1:26379,... in .env
```

## Architecture

### Middleware Stack (`app/main.py`)

Request execution order (last `add_middleware()` runs first):
```
RateLimitMiddleware → AuthMiddleware → BotDetectionMiddleware
  → InjectionDetectionMiddleware → ExfiltrationDetectionMiddleware
  → DecisionEngineMiddleware → route handler
```

- **RateLimitMiddleware** — per-IP and per-API-key Redis counters; 429 on breach. Skips `/healthz`, `/metrics`, `/docs`, `/openapi`.
- **AuthMiddleware** — enforces JWT Bearer or X-API-Key on all routes. Bypass: `/healthz`, `/metrics`, `/dashboard*`, `/admin*`. Attaches claims to `request.state.claims`.
- **BotDetectionMiddleware** — 13 rules (rapid-fire, burst, endpoint scanning, suspicious/missing UA, error rates, HTTP method anomalies). Runs post-`call_next()` to see response status. Bypass IPs via `BOT_DETECTION_BYPASS_IPS`.
- **InjectionDetectionMiddleware** — 96 regex patterns (19 XSS + 23 SQLi + 15 CMDi + 15 path traversal + 4 LDAP + 16 scanner-UA). Recursive JSON scan. URL-decode normalisation. YARA scan after regex. 2 MB body cap.
- **ExfiltrationDetectionMiddleware** — 4 response-side heuristics: LARGE_RESPONSE (>1 MB → monitor), HIGH_VOLUME (>10 MB/IP/5min → monitor), BULK_ACCESS (>50 hits/path/IP/min → block), SEQUENTIAL_CRAWL (>30 distinct endpoints/IP/5min → block).
- **DecisionEngineMiddleware** — innermost gate; checks `request.state.block` set by any upstream middleware and returns 403 if set.

### Auth (`app/auth/`)
- `jwt_handler.py` — `create_access_token(subject, role)` / `verify_token()` / `require_jwt`. Bearer header only.
- `api_key_handler.py` — `issue_api_key(subject, role, ttl_seconds)` / `validate_api_key()` / `revoke_api_key()` / `rotate_api_key()`. SHA-256 hash stored in Redis (`ritapi:apikey:{hash}`).

### RBAC (`app/rbac/rbac_service.py`)
`SUPER_ADMIN=5 > ADMIN=4 > OPERATOR=3 > AUDITOR=2 > VIEWER=1`. Use `require_role(UserRole.ADMIN)` as a FastAPI `Depends`.

### Redis (`app/utils/redis_client.py`)
Singleton with:
- Reconnect cooldown (`REDIS_RECONNECT_COOLDOWN`, default 5s) — no thundering herd
- Per-op retry: `ExponentialBackoff(cap=1s)` × 3 on `ConnectionError`/`TimeoutError`
- `mark_failed()` — called by middleware error handlers to reset the singleton
- Sentinel HA when `REDIS_SENTINEL_HOSTS` is set

### Admin API (`app/web/admin.py`)
Bootstrap: pass `X-Admin-Secret` header (= `ADMIN_SECRET` env var) or a SUPER_ADMIN JWT.
- `POST /admin/token` — issue JWT
- `POST /admin/apikey` — issue API key (optional `ttl_days`)
- `POST /admin/apikey/rotate` — atomic key rotation
- `DELETE /admin/apikey` — revoke

### Utilities
- `app/utils/yara_scanner.py` — singleton, `YARA_RULES_DIR` env var, 2 MB scan cap, no-op when yara-python absent
- `app/utils/logging.py` — JSONL to `LOG_PATH`; fields: `timestamp`, `client_ip`, `path`, `method`, `action`, `detection_type`, `score`, `reasons`
- `app/utils/metrics.py` — 7 counters, 2 histograms, 2 gauges; exposed at `GET /metrics`

## Environment Variables

| Variable | Purpose | Default |
|---|---|---|
| `SECRET_KEY` | JWT signing key | *(required)* |
| `JWT_ALGORITHM` | e.g. `HS256` | `HS256` |
| `JWT_EXPIRE_MINUTES` | Token TTL | `60` |
| `ADMIN_SECRET` | Bootstrap admin credential | *(required)* |
| `REDIS_URL` | Standalone Redis | `redis://localhost:6379/1` |
| `REDIS_SENTINEL_HOSTS` | Sentinel HA (overrides `REDIS_URL`) | *(unset)* |
| `REDIS_SENTINEL_SERVICE` | Sentinel master name | `mymaster` |
| `REDIS_RECONNECT_COOLDOWN` | Seconds between reconnect attempts | `5` |
| `RATE_LIMIT_REQUESTS` | Requests per window | `100` |
| `RATE_LIMIT_WINDOW` | Window in seconds | `60` |
| `LOG_PATH` | JSONL log output path | `/var/log/ritapi_advanced.jsonl` |
| `YARA_RULES_DIR` | Directory of `.yar` rule files | *(unset = YARA disabled)* |
| `BOT_DETECTION_BYPASS_IPS` | Comma-separated IPs exempt from bot scoring | `127.0.0.1,::1` |
| `DASHBOARD_TOKEN` | Bearer token for `/dashboard*` (unset = open) | *(unset)* |
