# TODO.md — RitAPI Advanced

Last updated: 2026-03-07 (Stage 9)

## Stage Model

| Stage | Name | Status |
|-------|------|--------|
| 0 | Concept / Requirements | ✅ Complete |
| 1 | Design | ✅ Complete |
| 2 | Development (Local) | ✅ Complete |
| 3 | Integration | ✅ Complete |
| 4 | Testing / QA | ✅ Complete |
| 5 | Staging | ✅ Complete |
| 6 | Build & Packaging | ✅ Complete |
| 7 | Code Signing & Security Audit | ✅ Complete |
| 8 | Distribution / Release | ✅ Complete |
| 9 | Client Installation & Validation | ✅ Complete |
| 10 | Production & Maintenance | ✗ Not started |

**Current position: Stage 10 (Production & Maintenance) — Stages 0–9 complete**

---

## Stage 0 — Concept / Requirements ✅

- [x] PRD defined: 10 protection features (rate limit, WAF, bot detection, exfiltration, JWT, API key, RBAC, YARA, Prometheus, dashboard)
- [x] Archive audit completed across `ritapi-advanced`, `ritapi-v-sentinel`, `_archive/ritapi_v`, `minifw-ai-standalone`
- [x] Regressions identified and tracked

---

## Stage 1 — Design ✅

- [x] Middleware stack order defined (RateLimit → Auth → Bot → WAF → Exfil → DecisionEngine)
- [x] Redis key schema designed (rate, bot, exfil, apikey namespaces)
- [x] Auth model: JWT (Bearer) + API key (SHA-256/Redis), RBAC IntEnum hierarchy
- [x] JSONL log schema defined
- [x] Prometheus metric taxonomy defined
- [x] `CLAUDE.md` documents architecture

---

## Stage 2 — Development (Local) ✅

All modules implemented and running on `localhost:8001`.

**Foundation**
- [x] `app/utils/redis_client.py` — singleton with reconnect cooldown, per-op retry (ExponentialBackoff), Sentinel HA support, `mark_failed()` propagation
- [x] `app/utils/logging.py` — JSONL structured logger, auto-creates dirs, stderr fallback
- [x] `app/utils/metrics.py` — 7 counters, 2 histograms, 2 gauges; `GET /metrics`
- [x] `app/utils/yara_scanner.py` — scanner singleton, 2 MB cap, graceful no-op

**Auth & RBAC**
- [x] `app/auth/jwt_handler.py` — `create_access_token` / `verify_token` / `require_jwt`
- [x] `app/auth/api_key_handler.py` — issue (with TTL) / validate / revoke / rotate; SHA-256 Redis storage
- [x] `app/rbac/rbac_service.py` — 5-level IntEnum, `require_role()` factory

**Middleware stack**
- [x] `app/middlewares/rate_limit.py` — per-IP + per-API-key, 429, Prometheus
- [x] `app/middlewares/auth.py` — JWT/API-key enforcement, bypass list, `request.state.claims`
- [x] `app/middlewares/bot_detection.py` — 13 rules, risk accumulator, bypass IPs
- [x] `app/middlewares/injection_detection.py` — 96 regex patterns (XSS/SQLi/CMDi/traversal/LDAP/scanner-UA), YARA hook
- [x] `app/middlewares/exfiltration_detection.py` — 4 heuristics (large response, high volume, bulk access, sequential crawl)
- [x] `app/middlewares/decision_engine.py` — unified block gate (innermost)

**Routes & UI**
- [x] `app/web/admin.py` — `POST /admin/token`, `POST /admin/apikey`, `POST /admin/apikey/rotate`, `DELETE /admin/apikey`
- [x] `app/web/dashboard.py` — live UI + `/events` / `/stats` / `/status` APIs, auth guard
- [x] `app/schemas/payload_schema.py` — `BasePayload`, NFC normalisation, Content-Type dep

**YARA rules**
- [x] `rules/sqli.yar` — 6 rules (UNION SELECT, stacked, boolean blind, time-based, error-based, info_schema)
- [x] `rules/xss.yar` — 5 rules (script tags, event handlers, javascript: protocol, polyglots, dangerous tags)
- [x] `rules/shell_injection.yar` — 5 rules (chaining, file read, remote exec, env vars, reverse shells)
- [x] `rules/credential_stuffing.yar` — 4 rules (bulk creds, tool signatures, JSON array auth, common passwords)

**Infrastructure**
- [x] `nginx.conf` — HTTPS, TLSv1.2/1.3, hardened ciphers, X-Forwarded-For, limit_req_zone, /metrics restricted
- [x] `scripts/gen_cert.sh` — self-signed (dev) + Let's Encrypt/Certbot (production)
- [x] `docker/redis-standalone.yml` — single Redis for dev
- [x] `docker/redis-sentinel.yml` + `docker/sentinel.conf` — 1 primary + 2 replicas + 3 sentinels, quorum=2
- [x] `scripts/redis_sentinel_setup.sh` — start/stop/status

---

## Stage 3 — Integration ✅

- [x] All middlewares wired in `app/main.py` in correct execution order
- [x] Auth middleware integrated with RBAC (claims on `request.state`)
- [x] `mark_failed()` propagated from all middleware Redis error handlers
- [x] Prometheus metrics wired into all middlewares
- [x] Admin router integrated with RBAC and auth bypass
- [x] Dashboard router integrated with optional auth guard
- [x] `/metrics` endpoint refreshes gauges from Redis on each scrape

---

## Stage 4 — Testing / QA ✅

**162/162 tests passing** (`python -m pytest tests/ -q`)

- [x] `test_health.py` — bypass endpoints
- [x] `test_auth.py` — 401 enforcement, JWT, API key lifecycle
- [x] `test_waf.py` — XSS, SQLi, CMDi, path traversal, scanner UA, nested JSON, clean passthrough
- [x] `test_rate_limit.py` — 429 triggering, API key rate limit, response format
- [x] `test_admin.py` — token issuance, API key CRUD, rotation, RBAC enforcement
- [x] `test_bot_detection.py` — all 13 rules unit tested + middleware integration tests
- [x] `test_exfiltration.py` — BULK_ACCESS, SEQUENTIAL_CRAWL, Redis helpers unit tested
- [x] `test_yara.py` — SQLi, XSS, shell injection, credential stuffing rule verification (20 rules)
- [x] `test_rbac.py` — role hierarchy enforcement, VIEWER blocked from ADMIN routes
- [x] `test_edge_cases.py` — oversized body (413), malformed JSON, non-UTF-8, long URLs, unicode bypass
- [x] `test_redis_failover.py` — fail-open behaviour, reconnect cooldown, JWT works without Redis
- [x] `locustfile.py` — load/stress test (LegitimateUser 70%, AttackerUser 20%, CrawlerBot 10%)
- [x] `pytest.ini` — `testpaths = tests`, coverage flags documented
- [x] `requirements.txt` — `pytest-cov>=5.0.0` added

---

## Stage 5 — Staging ✅

- [x] **`Dockerfile`** — multi-stage build (builder + runtime), non-root user `ritapi`, yara-python compiled against `libyara-dev`
- [x] **`docker/app.yml`** — full-stack Compose: `app` + `redis` + `nginx`; internal/external network split; named volumes for logs, Redis data, certs
- [x] **`.env.staging`** — staging template with documented secret placeholders (`SECRET_KEY`, `ADMIN_SECRET`, `REDIS_PASSWORD`); all env vars explained
- [x] **`scripts/smoke_test.sh`** — validates bypass endpoints, dashboard, auth enforcement, WAF blocking, rate limiter; exits non-zero on failure (CI-gate ready)
- [x] **`docker/grafana/dashboard.json`** — Grafana dashboard: request rate, bot/injection/exfil/auth counters by label, threat score heatmap, response size percentiles

---

## Stage 6 — Build & Packaging ✅

- [x] **`Dockerfile`** — multi-stage build (builder + runtime), non-root `ritapi` user, no dev tools in runtime layer *(done in Stage 5)*
- [x] **`.github/workflows/ci.yml`** — lint (ruff + bandit) → test matrix (Python 3.11 + 3.12, Redis service) → build multi-arch image (amd64 + arm64) → cosign sign → push to GHCR
- [x] **`pyproject.toml`** — PEP 517 build, version `1.0.0`, ruff lint config, coverage threshold (`fail_under = 70`)
- [x] **`CHANGELOG.md`** — Keep-a-Changelog format, full 1.0.0 release notes
- [x] **`requirements.lock`** — fully pinned transitive dependencies via `pip-compile --strip-extras`

---

## Stage 7 — Code Signing & Security Audit ✅

- [x] **SAST** — bandit (0 medium/high findings) + semgrep OWASP top-ten (9 false positives suppressed with `# nosemgrep`); both run in CI lint job
- [x] **Dependency audit** — `pip-audit` in CI; 1 finding: `ecdsa` CVE-2024-23342 (accepted risk — ECDSA code path unused, HS256 only); `--ignore-vuln` added with justification
- [x] **SBOM** — `cyclonedx-py` generates `sbom.json` in CI test job; uploaded as 90-day artifact
- [x] **Secret scanning** — `gitleaks-action@v2` in CI lint job; `.gitleaks.toml` allowlist for test fixtures and placeholder strings
- [x] **Penetration test** — `PENTEST.md`: 20 attack vectors tested, 3 findings (F-01 CVE accepted, F-02 fullwidth Unicode open, F-03 HPP low-priority open); auth and Redis key design reviewed
- [x] **WAF bypass review** — fullwidth Unicode (F-02) and HPP (F-03) documented; NFKC normalisation recommended
- [x] **Code review sign-off** — JWT (HS256 + exp enforcement), API key (SHA-256 hash, 256-bit entropy), RBAC (no escalation path), Redis keys (no namespace collisions)

---

## Stage 8 — Distribution / Release ✅

- [x] **Release notes / CHANGELOG.md** — Keep-a-Changelog format, full 1.0.0 release notes *(done Stage 6)*
- [x] **Container registry push** — CI `build` job pushes multi-arch signed image to GHCR *(done Stage 6)*
- [x] **Helm chart** — `helm/ritapi-advanced/` with full template suite: Deployment, Service, Ingress, HPA, bundled Redis, ConfigMap, Secret, ServiceAccount; `values.yaml` covers all tunables; `_helpers.tpl` provides `redisUrl` helper for bundled vs. external Redis
- [x] **Git tag v1.0.0** — semantic version tag; CI triggers GHCR release on push

---

## Stage 9 — Client Installation & Validation ✅

- [x] **`INSTALL.md`** — step-by-step guide for bare-metal (systemd), Docker Compose, and Kubernetes (Helm); includes first-login instructions and upgrade procedures for all three deployment targets
- [x] **`scripts/validate_install.sh`** — 7-section post-install validator: connectivity, auth enforcement, WAF injection blocking (XSS/SQLi/traversal/scanner-UA), rate limiting, Prometheus metrics, admin bootstrap, TLS; exits non-zero on failure; supports `--url`, `--admin-secret`, `--skip-tls` flags
- [x] **`CONFIGURATION.md`** — complete reference for all environment variables with types, defaults, and examples; Redis key layout; bot detection rule score table; Prometheus metric catalogue; security hardening checklist
- [x] **Upgrade guide** — rolling restart for Docker Compose, `helm upgrade` + rollback for Kubernetes, safe Redis key flush procedure; in `INSTALL.md`

---

## Stage 10 — Production & Maintenance ✗

- [ ] **Grafana alert rules** — alert on: auth failure spike, rate limit hit rate > 10%, bot block surge, Redis down
- [ ] **Runbook** — on-call procedures for Redis failover, cert renewal, YARA rule update, rate limit tuning
- [ ] **Log rotation** — configure `logrotate` for `LOG_PATH` JSONL file
- [ ] **SLOs defined** — uptime target, p99 latency budget, false-positive rate threshold for WAF
- [ ] **YARA rule update process** — documented workflow for adding/testing/deploying new `.yar` files without downtime
- [ ] **API key rotation policy** — documented schedule (e.g., 90-day TTL default, automated reminder)

---

## Feature Readiness Reference (Stage 2–3 perspective)

| Feature | Completeness | Notes |
|---------|-------------|-------|
| Auth — JWT | 97% | Globally enforced, admin issuance, `require_jwt` dep |
| Auth — API Key | 97% | TTL, rotation, revocation, globally enforced |
| RBAC | 85% | 5-level IntEnum, `require_role()`. No business routes to protect yet |
| API Rate Limiting | 90% | Per-IP + per-API-key, 429, Prometheus |
| Injection Detection — regex | 90% | 96 patterns, recursive JSON scan, YARA hook |
| Injection Detection — YARA | 75% | 20 rules across 4 files |
| Bot Detection | 90% | 13 rules, risk accumulator, bypass IPs |
| Data Exfiltration Detection | 80% | 4 heuristics, Redis-backed, Prometheus |
| Payload Validation | 80% | Pydantic, NFC, Content-Type dep, 2 MB cap |
| Observability — JSONL | 90% | All fields, auto-creates dirs, stderr fallback |
| Observability — Prometheus | 90% | 7 counters, 2 histograms, 2 gauges |
| Dashboard | 90% | Live UI, auto-refresh, auth guard. Missing: pagination |
| Admin API | 95% | Token + API key CRUD, RBAC-enforced |
| Enforcement shell | 95% | Full middleware stack + Nginx config |
| Redis resilience | 95% | Cooldown, retry backoff, mark_failed(), Sentinel HA |
| TLS provisioning | 95% | gen_cert.sh (self-signed + Certbot) |
| Test coverage | 40% | 36 tests (auth, WAF, rate limit, admin). Bot/exfil/YARA/load missing |
