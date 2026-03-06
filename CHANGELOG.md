# Changelog

All notable changes to RitAPI Advanced are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-03-06

Initial production-ready release.

### Added

**Core middleware stack** (outermost → innermost):
- `RateLimitMiddleware` — per-IP and per-API-key sliding-window rate limiting backed by Redis; configurable via `RATE_LIMIT_REQUESTS` / `RATE_LIMIT_WINDOW`
- `AuthMiddleware` — JWT Bearer and `X-API-Key` enforcement on all routes except bypass prefixes (`/healthz`, `/metrics`, `/dashboard*`, `/admin*`)
- `BotDetectionMiddleware` — 13-rule cumulative risk engine (RAPID_FIRE, BURST_TRAFFIC, ENDPOINT_SCANNING, SUSPICIOUS_USER_AGENT, LARGE_PAYLOAD, EXCESSIVE_POST, REPEATED_404/401/403, HIGH_ERROR_RATE, CONSECUTIVE_ERRORS, NO_USER_AGENT, SUSPICIOUS_METHOD); configurable bypass IPs
- `InjectionDetectionMiddleware` — regex detection for XSS, SQLi, CMDi, path traversal, LDAP injection, scanner User-Agents; YARA scanning of request bodies and headers; double-URL-decode and HTML-entity normalisation
- `ExfiltrationDetectionMiddleware` — post-response heuristics: large response (>1 MB), high outbound volume (>10 MB / 5 min), bulk endpoint access (>50 hits / 60 s), sequential crawl (>30 distinct endpoints / 5 min)
- `DecisionEngineMiddleware` — final 403 enforcement based on `request.state.block`

**Auth**
- JWT issuance and verification (`python-jose`, HS256); configurable expiry
- API key lifecycle: issue, validate (SHA-256 hash in Redis), revoke, rotate with optional TTL
- RBAC: five-level IntEnum (`VIEWER=1` → `SUPER_ADMIN=5`), enforced via `require_role()` FastAPI dependency

**Admin API** (`/admin/*`)
- Bootstrap via `X-Admin-Secret` header (no chicken-and-egg)
- `POST /admin/token`, `POST /admin/apikey`, `POST /admin/apikey/rotate`, `DELETE /admin/apikey`

**YARA scanner**
- Singleton with module-scoped reset; compiles all `.yar`/`.yara` files from `YARA_RULES_DIR`
- 20 rules across 4 files: `sqli.yar` (6), `xss.yar` (8), `shell_injection.yar` (10), `credential_stuffing.yar` (3)

**Observability**
- Prometheus metrics: 7 counters + 2 histograms + 2 gauges (requests, blocks, bot signals, exfil alerts, auth failures, rate limit hits, threat score, response size, active keys/IPs)
- Structured JSONL logging: every request logged with `timestamp`, `client_ip`, `path`, `method`, `action`, `detection_type`, `score`, `reasons`
- Dashboard: Jinja2-rendered HTML at `/dashboard` with live stats; JSON stats at `/dashboard/stats`
- Grafana dashboard JSON (`docker/grafana/dashboard.json`)

**Infrastructure**
- Redis singleton with exponential-backoff retry, 5-second reconnect cooldown, `mark_failed()` propagation across middlewares
- Redis Sentinel HA support (`REDIS_SENTINEL_HOSTS` env var): 1 primary + 2 replicas + 3 sentinels
- `Dockerfile`: multi-stage build (builder + runtime), non-root `ritapi` user
- `docker/app.yml`: full-stack Compose (app + Redis + Nginx) with internal network isolation
- `nginx.conf`: TLS termination, HTTP→HTTPS redirect, `/metrics` restricted to 127.0.0.1
- `scripts/gen_cert.sh`: self-signed cert (dev) or certbot (production)
- `scripts/smoke_test.sh`: 15-check post-deploy validation, CI-gate ready

**Testing**
- 162 tests, 100% pass rate across 11 test modules
- `test_bot_detection.py` — all 13 rules unit-tested + middleware integration
- `test_exfiltration.py` — BULK_ACCESS, SEQUENTIAL_CRAWL, Redis helper unit tests
- `test_yara.py` — 20 YARA rule match tests (SQLi, XSS, shell injection, credential stuffing)
- `test_rbac.py`, `test_edge_cases.py`, `test_redis_failover.py`
- `locustfile.py`: load test (LegitimateUser 70% / AttackerUser 20% / CrawlerBot 10%)

**Build & Packaging**
- `pyproject.toml`: PEP 517 build, ruff lint config, coverage thresholds (70% minimum)
- `requirements.lock`: fully pinned transitive dependencies via `pip-compile`
- `.github/workflows/ci.yml`: lint → test (Python 3.11 + 3.12 matrix) → build multi-arch image → cosign signing → push to registry

---

## [Unreleased]

_Nothing yet._
