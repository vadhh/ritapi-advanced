# RitAPI Advanced — Operator & User Manual

**Version 1.2.x**

---

## Contents

1. [Introduction](#1-introduction)
2. [Install](#2-install)
   - 2.1 [One-liner (recommended)](#21-one-liner-recommended)
   - 2.2 [Manual Docker Compose](#22-manual-docker-compose)
   - 2.3 [Helm (Kubernetes)](#23-helm-kubernetes)
   - 2.4 [Python package (embed)](#24-python-package-embed)
   - 2.5 [Bare metal](#25-bare-metal)
3. [Architecture](#3-architecture)
4. [Authentication](#4-authentication)
   - 4.1 [Admin bootstrap](#41-admin-bootstrap)
   - 4.2 [JWT tokens](#42-jwt-tokens)
   - 4.3 [API keys](#43-api-keys)
   - 4.4 [RBAC roles](#44-rbac-roles)
5. [Protection layers](#5-protection-layers)
   - 5.1 [Rate limiting](#51-rate-limiting)
   - 5.2 [Bot detection](#52-bot-detection)
   - 5.3 [Injection detection (WAF)](#53-injection-detection-waf)
   - 5.4 [Exfiltration detection](#54-exfiltration-detection)
   - 5.5 [Decision engine & policy](#55-decision-engine--policy)
6. [Policy YAML](#6-policy-yaml)
7. [Configuration reference](#7-configuration-reference)
8. [Admin API](#8-admin-api)
9. [Dashboard](#9-dashboard)
10. [Metrics & monitoring](#10-metrics--monitoring)
11. [Upgrade](#11-upgrade)
12. [Uninstall](#12-uninstall)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. Introduction

RitAPI Advanced is a drop-in layer-7 API protection service built on FastAPI. It sits in front of your existing API and enforces security policies without requiring changes to your application code.

```
Your client  →  RitAPI Advanced (:8001)  →  Your API
```

Traffic is inspected at multiple layers in sequence:

| Layer | What it does |
|---|---|
| Rate limiting | Counts requests per IP and per API key; returns 429 when exceeded |
| Authentication | Validates JWT Bearer or `X-API-Key`; attaches claims to the request |
| Bot detection | 13 behavioural rules; accumulates risk score per IP |
| Injection / WAF | 96 regex patterns + YARA rules; detects XSS, SQLi, CMDi, path traversal, LDAP |
| Exfiltration | Response-side heuristics: bulk access, sequential crawl, large response, high volume |
| Decision engine | Reads all detections; applies per-route policy (block / throttle / monitor / allow) |

If a request is blocked, your backend never executes. If it is monitored, the request passes but is logged. Throttled requests count against a tighter rate limit sub-bucket.

---

## 2. Install

### 2.1 One-liner (recommended)

```bash
curl -sSL https://raw.githubusercontent.com/vadhh/ritapi-advanced/main/bootstrap.sh | bash
```

This single command:

1. Checks Docker and Docker Compose are installed
2. Downloads `docker-compose.yml` from the release
3. Generates cryptographically random secrets (`SECRET_KEY`, `ADMIN_SECRET`, `REDIS_PASSWORD`)
4. Writes a `.env` file (mode `600`)
5. Pulls the pre-built image from GHCR
6. Starts the service and waits for a healthy state
7. Prints first-steps instructions including how to get your admin token

**Prefer to inspect the script before running it:**

```bash
curl -sSL https://raw.githubusercontent.com/vadhh/ritapi-advanced/main/bootstrap.sh -o bootstrap.sh
less bootstrap.sh
bash bootstrap.sh
```

**Flags:**

| Flag | Effect |
|---|---|
| `--auto` | Non-interactive — all secrets generated, no prompts |
| `--version v1.2.1` | Pin a specific release tag |
| `--upgrade` | Pull latest image and restart the app container |
| `--uninstall` | Stop and remove all containers and volumes |

Examples:

```bash
# Automated deployment (no stdin required)
curl -sSL .../bootstrap.sh | bash -s -- --auto

# Pin version v1.2.1
curl -sSL .../bootstrap.sh | bash -s -- --version v1.2.1

# Upgrade existing install
bash bootstrap.sh --upgrade

# Remove everything
bash bootstrap.sh --uninstall
```

### 2.2 Manual Docker Compose

```bash
# 1. Get the compose file
curl -sSL https://raw.githubusercontent.com/vadhh/ritapi-advanced/main/docker-compose.yml -o docker-compose.yml

# 2. Create .env
cat > .env <<EOF
SECRET_KEY=$(openssl rand -hex 32)
ADMIN_SECRET=$(openssl rand -hex 32)
REDIS_PASSWORD=$(openssl rand -hex 16)
DASHBOARD_TOKEN=
PORT=8001
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=60
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60
EOF
chmod 600 .env

# 3. Start
docker compose up -d

# 4. Check health
curl http://localhost:8001/healthz
```

### 2.3 Helm (Kubernetes)

```bash
helm repo add ritapi https://vadhh.github.io/ritapi-advanced/charts
helm repo update

helm install ritapi ritapi/ritapi-advanced \
  --set secrets.secretKey=$(openssl rand -hex 32) \
  --set secrets.adminSecret=$(openssl rand -hex 32) \
  --set secrets.redisPassword=$(openssl rand -hex 16) \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=ritapi.example.com
```

For a full values reference see [INSTALL.md](INSTALL.md#option-c--kubernetes-helm).

### 2.4 Python package (embed)

Install into an existing FastAPI application:

```bash
pip install ritapi-advanced
```

```python
from fastapi import FastAPI
from app.middlewares.decision_engine import DecisionEngineMiddleware
from app.middlewares.injection_detection import InjectionDetectionMiddleware
from app.middlewares.rate_limit import RateLimitMiddleware

app = FastAPI()

# Innermost first
app.add_middleware(DecisionEngineMiddleware)
app.add_middleware(InjectionDetectionMiddleware)
app.add_middleware(RateLimitMiddleware)
```

Add all six middleware classes in the correct order for full protection (see [Architecture](#3-architecture)).

### 2.5 Bare metal

See [INSTALL.md](INSTALL.md#option-a--bare-metal) for the full bare-metal procedure including systemd unit file, TLS generation, and Redis Sentinel HA setup.

---

## 3. Architecture

### Request flow

```
Request arrives
      │
      ▼
RateLimitMiddleware       ← outermost — runs pre-request
      │
      ▼
AuthMiddleware            ← validates JWT or API key
      │
      ▼
BotDetectionMiddleware    ← accumulates risk score from behavioural signals
      │
      ▼
InjectionDetectionMiddleware  ← WAF: regex + YARA scan of URL, headers, body
      │
      ▼
ExfiltrationDetectionMiddleware  ← response-side heuristics (runs after call_next)
      │
      ▼
DecisionEngineMiddleware  ← innermost gate: reads all detections, applies policy
      │
      ▼
Route handler (your API)
```

**Key design property:** Detection middlewares write to `request.state.detections`. The Decision Engine reads this list and decides the final action (block / throttle / monitor / allow) according to the per-route policy YAML. No detection middleware returns a 403 directly — all blocking goes through the Decision Engine.

### Bypass paths

Some paths skip authentication and selected middlewares to remain publicly accessible:

| Path | Skips auth | Skips rate limit |
|---|---|---|
| `/healthz` | yes | yes |
| `/metrics` | yes | yes |
| `/docs`, `/openapi.json` | yes | yes |
| `/dashboard*` | yes | no |
| `/admin*` | yes (uses X-Admin-Secret or JWT) | no |

### Redis key layout

| Pattern | Purpose | TTL |
|---|---|---|
| `ratelimit:ip:<ip>` | Per-IP request counter | `RATE_LIMIT_WINDOW` s |
| `ratelimit:key:<hash>` | Per-API-key counter | `RATE_LIMIT_WINDOW` s |
| `bot:<ip>:score` | Bot risk accumulator | 300 s |
| `bot:<ip>:<rule>` | Per-rule counters | varies |
| `exfil:<ip>:vol` | Bytes transferred per IP | 3600 s |
| `exfil:<ip>:bulk` | Bulk access hit counter | 300 s |
| `ritapi:apikey:<sha256>` | API key store | key TTL |

---

## 4. Authentication

### 4.1 Admin bootstrap

The first credential into the system is the `ADMIN_SECRET` environment variable. It is a shared secret used only to obtain the initial SUPER_ADMIN JWT.

```bash
source .env
curl -s -X POST http://localhost:8001/admin/token \
  -H "X-Admin-Secret: $ADMIN_SECRET" | jq .
```

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

Store this token securely — it has SUPER_ADMIN privileges. Rotate `ADMIN_SECRET` after issuing the first production key if your threat model requires it.

### 4.2 JWT tokens

JWTs are issued via `POST /admin/token` and carry a `role` claim. The AuthMiddleware validates the signature and expiry on every request.

**Request header:**

```
Authorization: Bearer <token>
```

**Token lifetime:** Controlled by `JWT_EXPIRE_MINUTES` (default 60). Tokens are not revocable — expiry is the only mechanism. Set a short TTL for high-privilege roles.

**Issue a token for a specific role:**

```bash
# Not directly exposed via admin API — use admin/apikey for long-lived credentials.
# The /admin/token endpoint issues SUPER_ADMIN tokens only.
```

### 4.3 API keys

API keys are long-lived opaque credentials stored as SHA-256 hashes in Redis.

**Issue a key:**

```bash
curl -s -X POST http://localhost:8001/admin/apikey \
  -H "X-Admin-Secret: $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"subject": "my-service", "role": "OPERATOR", "ttl_days": 90}' | jq .
```

```json
{
  "api_key": "rta_live_a1b2c3d4...",
  "subject": "my-service",
  "role": "OPERATOR",
  "expires_at": "2026-06-29T12:00:00Z"
}
```

The key is shown once. Store it immediately.

**Use a key:**

```
X-API-Key: rta_live_a1b2c3d4...
```

**Rotate a key atomically:**

```bash
curl -s -X POST http://localhost:8001/admin/apikey/rotate \
  -H "X-Admin-Secret: $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"api_key": "rta_live_old..."}' | jq .
```

The old key is revoked and a new key is issued in a single atomic operation. There is no window where neither key is valid.

**Revoke a key:**

```bash
curl -s -X DELETE http://localhost:8001/admin/apikey \
  -H "X-Admin-Secret: $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"api_key": "rta_live_a1b2c3d4..."}' | jq .
```

### 4.4 RBAC roles

| Role | Level | Typical use |
|---|---|---|
| `SUPER_ADMIN` | 5 | Bootstrap only; issue via `/admin/token` |
| `ADMIN` | 4 | Manage keys and policies |
| `OPERATOR` | 3 | Read metrics, view dashboard, rotate own keys |
| `AUDITOR` | 2 | Read-only access to logs and metrics |
| `VIEWER` | 1 | Minimal access; call protected API routes |

Role checks are hierarchical: a role with level N can access any endpoint requiring level ≤ N.

---

## 5. Protection layers

### 5.1 Rate limiting

Per-IP and per-API-key counters in Redis using atomic INCR + EXPIRE NX (pipeline).

| Behaviour | Details |
|---|---|
| Default limit | 100 requests per 60-second window |
| On breach | HTTP 429, `Retry-After` header set to seconds until window reset |
| Throttle action | Per-route policy can halve the effective limit for a detection type |
| Exempt paths | `/healthz`, `/metrics`, `/docs`, `/openapi.json` |

Tune with `RATE_LIMIT_REQUESTS` and `RATE_LIMIT_WINDOW`.

### 5.2 Bot detection

13 rules that accumulate a risk score per IP. When the cumulative score reaches the block threshold, the request is blocked.

| Rule | Score contribution | Trigger condition |
|---|---|---|
| `RAPID_FIRE` | 40 | >50 requests/minute |
| `BURST_TRAFFIC` | 30 | >20 requests in 5 seconds |
| `NO_USER_AGENT` | 60 | Missing `User-Agent` header |
| `SUSPICIOUS_USER_AGENT` | 60 | Known scanner UA (sqlmap, nikto, zgrab, masscan…) |
| `ENDPOINT_SCANNING` | 50 | >10 distinct 404s in 60 seconds |
| `ERROR_RATE_ANOMALY` | 35 | >30% 4xx/5xx over last 100 requests |
| `UNUSUAL_HTTP_METHOD` | 25 | TRACE, CONNECT, or other uncommon verbs |
| `LARGE_PAYLOAD` | 20 | `Content-Length` > 10 KB |
| *(additional rules)* | varies | See `app/middlewares/bot_detection.py` |

**Block threshold:** Score ≥ 70 → HTTP 403

**Risk decay:** Scores expire after 300 seconds of inactivity per IP.

**Bypass IPs:** Set `BOT_DETECTION_BYPASS_IPS` to exempt monitoring agents, health-checkers, and known-good internal services:

```
BOT_DETECTION_BYPASS_IPS=127.0.0.1,::1,10.0.1.50
```

### 5.3 Injection detection (WAF)

96 regex patterns applied to the full request (URL path, query string, headers, and body) plus YARA rules on the raw body.

**Pattern categories:**

| Category | Patterns | Examples |
|---|---|---|
| XSS | 19 | `<script>`, `onerror=`, `javascript:` |
| SQLi | 23 | `UNION SELECT`, `OR 1=1`, `information_schema` |
| CMDi | 15 | `;ls`, `$(cmd)`, pipe chaining |
| Path traversal | 15 | `../../../etc/passwd`, URL-encoded variants |
| LDAP injection | 4 | `*)(&`, `)(cn=*` |
| Scanner UA | 16 | sqlmap, nikto, curl with known attacker patterns |

**Body handling:**

- Maximum body size scanned: 2 MB (larger bodies skip YARA but regex still runs on the first 2 MB)
- JSON bodies are recursively traversed — each field value is scanned independently
- URL-encoded inputs are decoded before scanning to catch double-encoded attacks

**YARA rules:**

YARA provides a second layer on top of regex. Rules live in `YARA_RULES_DIR` (default `/app/rules`). Bundled rule files cover SQLi, XSS, shell injection, and credential stuffing patterns. Add your own `.yar` files to the same directory and restart the service.

**On a detection:** The middleware writes to `request.state.detections` with the matched rule name. The Decision Engine reads this and applies the per-route policy.

### 5.4 Exfiltration detection

Four response-side heuristics that monitor outbound data patterns:

| Heuristic | Threshold | Default action |
|---|---|---|
| `LARGE_RESPONSE` | Response body > 1 MB | monitor |
| `HIGH_VOLUME` | > 10 MB transferred per IP per 5 minutes | monitor |
| `BULK_ACCESS` | > 50 hits to the same path per IP per minute | block |
| `SEQUENTIAL_CRAWL` | > 30 distinct endpoints per IP per 5 minutes | block |

The exfiltration middleware runs **after** `call_next()` — it sees the response. Detection is written to `request.state.detections` for future requests from the same IP. The Decision Engine applies the block/monitor action on the **current** request if it was already flagged in a prior request.

### 5.5 Decision engine & policy

The Decision Engine is the innermost middleware. It runs before the route handler and reads all detections accumulated by upstream middlewares.

For each detection in `request.state.detections`, it looks up the per-route policy (see [Section 6](#6-policy-yaml)) and resolves one of four actions:

| Action | Effect |
|---|---|
| `block` | Return HTTP 403 immediately; backend does not execute |
| `throttle` | Apply a tighter rate limit sub-bucket; pass if not exhausted |
| `monitor` | Log the detection and pass; no user-visible impact |
| `allow` | Explicit allow; overrides lower-priority detections |

The highest-priority action wins. `block` > `throttle` > `monitor` > `allow`.

---

## 6. Policy YAML

Policies live in `POLICIES_DIR` (default `/app/configs/policies/`). One YAML file per route or route group.

**Example: `policies/api_v1_data.yml`**

```yaml
route: /api/v1/data
methods: [GET, POST]

rules:
  SQLI:
    action: block
  XSS:
    action: block
  CMDI:
    action: block
  PATH_TRAVERSAL:
    action: block
  BULK_ACCESS:
    action: block
  SEQUENTIAL_CRAWL:
    action: block
  LARGE_RESPONSE:
    action: monitor
  RAPID_FIRE:
    action: throttle
  BURST_TRAFFIC:
    action: throttle
  NO_USER_AGENT:
    action: monitor
```

**Default policy (when no file matches):**

```yaml
SQLI:        block
XSS:         block
CMDI:        block
PATH_TRAVERSAL: block
BULK_ACCESS: block
SEQUENTIAL_CRAWL: block
LARGE_RESPONSE: monitor
HIGH_VOLUME: monitor
RAPID_FIRE:  throttle
```

Policy files are loaded at startup. To apply changes, restart the service.

**Routing config** (`/app/configs/routing.yml`) maps incoming paths to upstream backends. The format is:

```yaml
routes:
  - path: /api/v1/
    upstream: http://your-api:8080
    strip_prefix: false
  - path: /api/v2/
    upstream: http://your-api-v2:8080
```

---

## 7. Configuration reference

All settings are environment variables. Set them in `.env` (generated by `bootstrap.sh`) or pass them directly to Docker.

### Core secrets

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | **required** | JWT HMAC signing key — 32+ bytes of entropy |
| `ADMIN_SECRET` | **required** | Bootstrap credential for `/admin/*` endpoints |

Generate a value: `openssl rand -hex 32`

### JWT

| Variable | Default | Description |
|---|---|---|
| `JWT_ALGORITHM` | `HS256` | Signing algorithm |
| `JWT_EXPIRE_MINUTES` | `60` | Access token lifetime in minutes |

### Redis

| Variable | Default | Description |
|---|---|---|
| `REDIS_URL` | `redis://localhost:6379/1` | Standalone Redis URL |
| `REDIS_PASSWORD` | `""` | Redis AUTH password |
| `REDIS_SENTINEL_HOSTS` | `""` | Comma-separated Sentinel addresses for HA mode |
| `REDIS_SENTINEL_SERVICE` | `mymaster` | Sentinel master name |
| `REDIS_RECONNECT_COOLDOWN` | `5` | Seconds between reconnect attempts |

For HA with Sentinel, set `REDIS_SENTINEL_HOSTS=sentinel1:26379,sentinel2:26379` and the client switches to Sentinel mode automatically.

### Rate limiting

| Variable | Default | Description |
|---|---|---|
| `RATE_LIMIT_REQUESTS` | `100` | Max requests per window |
| `RATE_LIMIT_WINDOW` | `60` | Window size in seconds |

### Bot detection

| Variable | Default | Description |
|---|---|---|
| `BOT_DETECTION_BYPASS_IPS` | `127.0.0.1,::1` | Comma-separated IPs exempt from bot scoring |

### Logging & YARA

| Variable | Default | Description |
|---|---|---|
| `LOG_PATH` | `/var/log/ritapi/ritapi_advanced.jsonl` | JSONL structured log output path |
| `YARA_RULES_DIR` | `/app/rules` | Directory of `.yar` rule files |

### Networking

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8001` | Host port to expose (Docker only) |
| `DASHBOARD_TOKEN` | `""` | Bearer token to protect `/dashboard` (empty = open) |

---

## 8. Admin API

All admin endpoints require either `X-Admin-Secret: $ADMIN_SECRET` or a `SUPER_ADMIN` JWT in the `Authorization: Bearer` header.

### POST /admin/token

Issue a SUPER_ADMIN JWT.

```bash
curl -s -X POST http://localhost:8001/admin/token \
  -H "X-Admin-Secret: $ADMIN_SECRET"
```

### POST /admin/apikey

Issue an API key.

```bash
curl -s -X POST http://localhost:8001/admin/apikey \
  -H "X-Admin-Secret: $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "my-service",
    "role": "OPERATOR",
    "ttl_days": 90
  }'
```

`ttl_days` is optional. Omit for a non-expiring key.

### POST /admin/apikey/rotate

Atomically revoke the old key and issue a new one.

```bash
curl -s -X POST http://localhost:8001/admin/apikey/rotate \
  -H "X-Admin-Secret: $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"api_key": "rta_live_old..."}'
```

### DELETE /admin/apikey

Revoke a key immediately.

```bash
curl -s -X DELETE http://localhost:8001/admin/apikey \
  -H "X-Admin-Secret: $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"api_key": "rta_live_..."}'
```

---

## 9. Dashboard

The live security dashboard is at `GET /dashboard`.

It displays:

- Recent blocked/monitored requests (rolling 5-minute window)
- Per-detection-type counts
- Top blocked IPs
- Rate limit hit rate
- Bot detection trigger counts
- Redis connection status

**Access control:**

If `DASHBOARD_TOKEN` is set in `.env`, the dashboard requires:

```
Authorization: Bearer <dashboard_token>
```

If `DASHBOARD_TOKEN` is empty (default), the dashboard is open to anyone who can reach the service. Restrict it at the network or Nginx layer in production.

---

## 10. Metrics & monitoring

Prometheus metrics are exported at `GET /metrics` (plain text, no auth).

### Available metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `ritapi_requests_total` | counter | `action`, `detection_type` | All processed requests |
| `ritapi_injections_total` | counter | `detection_type` | WAF detections |
| `ritapi_bot_blocks_total` | counter | `rule` | Bot detection blocks |
| `ritapi_exfil_blocks_total` | counter | `heuristic` | Exfiltration blocks |
| `ritapi_auth_failures_total` | counter | `reason` | Auth rejections |
| `ritapi_rate_limit_hits_total` | counter | `limit_type` | Rate limit 429s |
| `ritapi_threat_score` | histogram | — | Risk score distribution |
| `ritapi_response_size_bytes` | histogram | — | Outbound response sizes |
| `ritapi_redis_connected` | gauge | — | Redis connection state (0 or 1) |
| `ritapi_active_api_keys` | gauge | — | Count of non-expired API keys |

### Grafana

Import the bundled dashboard from `docker/grafana/dashboard.json` into Grafana. The dashboard includes panels for all counters above plus alert thresholds.

### Prometheus scrape config

```yaml
# prometheus.yml
scrape_configs:
  - job_name: ritapi
    static_configs:
      - targets: ['ritapi-host:8001']
    metrics_path: /metrics
    scrape_interval: 15s
```

### Recommended alerts

| Alert | Condition | Severity |
|---|---|---|
| High block rate | `rate(ritapi_injections_total[5m]) > 10` | warning |
| Redis down | `ritapi_redis_connected == 0` | critical |
| Auth failure spike | `rate(ritapi_auth_failures_total[5m]) > 5` | warning |
| Rate limit saturation | `rate(ritapi_rate_limit_hits_total[5m]) > 20` | info |

### Structured logs

Each request produces one JSONL log line in `LOG_PATH`:

```json
{
  "timestamp": "2026-03-31T10:00:00.123456Z",
  "client_ip": "1.2.3.4",
  "path": "/api/v1/data",
  "method": "POST",
  "action": "block",
  "detection_type": "SQLI",
  "score": 100,
  "reasons": ["sql_union_select", "stacked_queries"]
}
```

`action` is one of: `allow`, `block`, `monitor`, `throttle`.

---

## 11. Upgrade

### Using the installer

```bash
bash bootstrap.sh --upgrade
```

This pulls the latest image and restarts only the app container (Redis is untouched, data is preserved).

### Manual

```bash
docker compose pull app
docker compose up -d --no-deps app
```

### Kubernetes

```bash
helm upgrade ritapi ritapi/ritapi-advanced \
  -f my-values.yaml \
  --wait --timeout 120s
```

### After upgrade

Verify the service is healthy:

```bash
curl http://localhost:8001/healthz
```

Expected response:

```json
{"status": "ok", "redis": "connected"}
```

If Redis appears as `"degraded"`, the service is still operational — it falls back to in-memory counters. Check `docker compose logs redis` for the root cause.

---

## 12. Uninstall

```bash
bash bootstrap.sh --uninstall
```

This runs `docker compose down -v --remove-orphans`, removing all containers and volumes (including Redis data and app logs).

The `.env` and `docker-compose.yml` files are left on disk. Remove them manually if no longer needed:

```bash
rm .env docker-compose.yml
```

---

## 13. Troubleshooting

### Service is unhealthy after start

```bash
docker compose logs app        # application logs
docker compose logs redis      # Redis logs
docker compose ps              # container states
```

Common causes:

| Symptom | Likely cause | Fix |
|---|---|---|
| `SECRET_KEY not set` | `.env` missing or not loaded | Check `.env` exists; re-run `bootstrap.sh` |
| `Redis connection refused` | Redis container not ready | Wait 10 s and retry; check `docker compose ps redis` |
| Port 8001 already in use | Another process on that port | Set a different `PORT` in `.env` |
| YARA rules fail to compile | Invalid `.yar` file added | Check service logs for the filename; fix or remove the rule |

### 429 responses unexpectedly

The rate limit applies per IP. If your client is behind NAT, all clients share one IP bucket.

Options:
- Increase `RATE_LIMIT_REQUESTS` in `.env` and restart
- Issue API keys so per-key limits apply instead of per-IP

### 403 on legitimate requests

Check the structured log at `LOG_PATH` for the `detection_type` and `reasons` fields.

```bash
tail -f /var/log/ritapi/ritapi_advanced.jsonl | python3 -m json.tool
```

If it is a false positive from the WAF:
- For YARA false positives: edit the relevant `.yar` rule to narrow the pattern and restart
- For regex false positives: the patterns are compiled into `app/middlewares/injection_detection.py` — open a support issue

If it is a bot detection false positive (monitoring agents, health checkers):

```bash
# In .env:
BOT_DETECTION_BYPASS_IPS=127.0.0.1,::1,<monitoring-agent-ip>
```

Restart the service after editing `.env`.

### Redis connection drops periodically

The Redis client has built-in reconnect logic with a 5-second cooldown (`REDIS_RECONNECT_COOLDOWN`). During a disconnect, rate-limit and bot-score state is temporarily unavailable but the service remains up.

For high-availability deployments, configure Redis Sentinel:

```
REDIS_SENTINEL_HOSTS=sentinel1:26379,sentinel2:26379,sentinel3:26379
REDIS_SENTINEL_SERVICE=mymaster
```

### Dashboard shows no data

The dashboard reads from Redis. If Redis is unavailable, the dashboard shows zeros.

If Redis is healthy but the dashboard still shows no data:
- Generate some traffic through the proxy (`curl http://localhost:8001/healthz` a few times)
- Verify the `LOG_PATH` file is growing: `wc -l /var/log/ritapi/ritapi_advanced.jsonl`

### View API documentation

Swagger UI is at `GET /docs` (no auth required). This shows all endpoint schemas, request/response formats, and lets you try requests interactively.

---

## Further reading

| Document | Purpose |
|---|---|
| [INSTALL.md](INSTALL.md) | Detailed install options (bare metal, Kubernetes, CI pipelines) |
| [CONFIGURATION.md](CONFIGURATION.md) | Complete environment variable reference |
| [RUNBOOK.md](RUNBOOK.md) | On-call procedures and incident response |
| [PENTEST.md](PENTEST.md) | Penetration testing guide and known limitations |
| [SLO.md](SLO.md) | Service level objectives |
