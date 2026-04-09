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

## [1.1.0] — 2026-03-18

Policy-driven routing and enforcement release.

### Added

**Policy-driven architecture**
- `configs/routing.yml` — YAML-based multi-route definitions with path prefix, HTTP methods, upstream backends, and policy assignment
- `configs/policies/{auth,payment,admin}.yml` — per-route policy files defining auth requirements, rate limits, schema enforcement, and decision actions
- `app/routing/service.py` — route resolver with longest-prefix-first matching, lazy loading, and hot-reload support
- `app/policies/service.py` — policy loader with typed dataclasses (`AuthPolicy`, `RateLimitPolicy`, `SchemaPolicy`, `DecisionActions`)

**Per-route enforcement**
- `SchemaEnforcementMiddleware` — validates request bodies against named Pydantic schemas based on route policy; dynamically resolves schema classes
- `PaymentPayload` schema — strict validation for payment endpoints (amount, currency, recipient)
- `AuthMiddleware` now reads `policy.auth.jwt` / `policy.auth.api_key` to enable/disable auth methods per route
- `RateLimitMiddleware` now reads `policy.rate_limit.requests` / `window_seconds` for per-route rate limits
- `DecisionEngineMiddleware` rewritten to resolve route → load policy → process detections with 4 action types

**Decision actions**
- `allow` — pass through silently
- `monitor` — pass through with structured logging
- `throttle` — pass through with rate reduction marker
- `block` — return 403 Forbidden

**Production safety**
- `scripts/backup.sh` — pg_dump + /etc/ritapi config + log archival + 30-backup retention with metadata
- `scripts/restore.sh` — database restore + config restore + service lifecycle management
- `DEPLOYMENT_STATES.md` — 5-state lifecycle (INSTALL → SETUP → MONITOR → ENFORCE → ROLLBACK) with entry/exit criteria
- `GO_LIVE_CHECKLIST.md` — 47 items across infrastructure, product, and security sections with sign-off table
- `minifw-ai.service` — systemd unit with full sandboxing (NoNewPrivileges, ProtectSystem=strict, ProtectHome, PrivateTmp)

**Infrastructure**
- HSTS header enabled in `nginx.conf`
- `PyYAML>=6.0.0` added to dependencies
- Routing/policy env vars (`ROUTING_CONFIG_PATH`, `POLICIES_DIR`) added to env template, Dockerfile, Docker Compose, and Helm chart
- `.deb` packaging updated: conffiles include routing/policy configs, postinst deploys configs to `/etc/ritapi-advanced/`
- CI pipeline validates YAML configs before test run
- Helm chart bumped to 1.1.0 with routing/policy ConfigMap entries

### Changed
- `DecisionEngineMiddleware` — rewritten from simple block-flag gate to full route-aware policy engine
- `AuthMiddleware` — now policy-configurable (previously global enforcement)
- `RateLimitMiddleware` — now reads per-route limits from policy (previously single global limit)
- `DEBIAN/control` — added `postgresql` to Recommends
- `DEBIAN/postinst` — installs routing.yml and policy files to `/etc/ritapi-advanced/`
- `DEBIAN/prerm` — stops MiniFW-AI service on removal
- `DEBIAN/postrm` — cleans up policy configs and backups on purge

## [1.4.0] — 2026-04-08

Engine hardening release. No architecture changes. No UI changes.

### Fixed

**M-7 — DecisionEngine routing (critical)**
- All middlewares now append detections via `append_detection()` instead of returning `JSONResponse` directly
- `HardGateMiddleware` fully rewritten: all 5 check methods call `append_detection()` then `call_next()`
- `InjectionDetectionMiddleware`: removed dead `_blocked_response()` static method and unused import
- `DecisionEngineMiddleware` is now the sole authority for all 403/429 responses

**M-7 — Policy mapping gap (critical)**
- `DecisionActions` was missing `on_blocked_ip`, `on_blocked_asn`, `on_yara`, `on_ddos_spike`, `on_invalid_api_key` — all 5 HardGate types fell through to `"monitor"` (silent pass-through)
- Added all 5 fields defaulting to `"block"`; added to `_parse_policy_data()` for YAML override support

**Real throttle**
- `_apply_throttle()` was a no-op flag; rewritten as Redis pipeline counter
- `count > THROTTLE_MAX_HITS` returns 429; below threshold passes through; Redis unavailable fails-open
- Constants: `THROTTLE_MAX_HITS` (default 5), `THROTTLE_WINDOW` (default 60 s), both env-configurable

**Redis safety**
- `rate_limit.py`: removed `setex` double-write; `redis.set(nx=True, ex=ttl)` is now the single atomic op
- `exfiltration_detection._incr`: replaced two-step INCR + conditional EXPIRE with pipeline (INCR + EXPIRE NX)
- `exfiltration_detection._incrby`: removed try/except fallback that executed the pipeline twice on error

**Tenant logging**
- `security_event_logger`: `tenant_id` is now `str | None`; `None` when no verified tenant
- `siem_export`: `build_siem_event()` now includes `tenant_status` field (`"authenticated"` / `"unauthenticated"`)
- Eliminates the `"default"` ambiguity in SIEM output

### Added

**Cache invalidation**
- `_route_cache` and `_tenant_policy_cache` now store `(value, timestamp)` tuples
- `CACHE_TTL_SECONDS` env var (default 60 s) controls TTL; expired entries evicted on access

**`POST /admin/reload`**
- Force-reloads `routing.yml` and all policy YAML files, clears both caches
- Requires SUPER_ADMIN or valid `X-Admin-Secret`
- Returns `{"reloaded": true, "routes": N, "policies": N}`

**Startup validation**
- App refuses to start if `DASHBOARD_TOKEN` is not set (`RuntimeError`)
- App refuses to start if `ADMIN_SECRET` is not set (`RuntimeError`)

### Tests

- 335 tests total, 335 passed, 0 failed
- 7 new test files: `test_m7_hardgate_integration.py` (12), `test_m7_decision_engine_routing.py` (6), `test_throttle_real.py` (4), `test_redis_bugs.py` (8), `test_tenant_status.py` (7), `test_cache_invalidation.py` (9), `test_admin_dashboard_security.py` (15)
- 6 existing test files updated to reflect new enforcement model

## [Unreleased]

_Nothing yet._
