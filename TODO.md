# TODO.md — Codebase Audit Findings

Audit performed: 2026-03-30

---

## Critical

- [x] **C-1** — Policy dispatch is dead code: no middleware populates `request.state.detections`, so `DecisionEngineMiddleware` policy dispatch (on_rate_limit, on_bot_detection, etc.) never runs — all detections block unconditionally ignoring YAML policy settings. (`app/main.py:24-33`, `app/middlewares/decision_engine.py:58-73`)

- [x] **C-2** — Raw API key embedded in Redis keyspace: full plaintext API key used in key names (`ritapi:rate:apikey:<key>:<path>`), violating the hash-only storage design. (`app/middlewares/rate_limit.py:74`)

- [x] **C-3** — `SECRET_KEY=change-me` committed to git: `.env` is tracked by git and contains the default secret key — anyone who clones the repo can forge JWTs for any role including `SUPER_ADMIN`. (`.env:1`, `.gitignore`)

- [x] **C-4** — Redis password leaked via Kubernetes ConfigMap: assembled `REDIS_URL` containing Redis password placed in ConfigMap instead of Secret, readable by any pod in the namespace. (`helm/ritapi-advanced/templates/configmap.yaml:18`)

---

## High

- [x] **H-1** — Timing oracle on `ADMIN_SECRET` and `DASHBOARD_TOKEN`: uses `==` instead of `hmac.compare_digest()`, vulnerable to timing side-channel attacks. (`app/web/admin.py:39`, `app/web/dashboard.py:43`)

- [x] **H-2** — Bot detection blocks *after* route handler executes: `call_next()` is called first, then block decision is made — backend has already processed the request before the 403 is returned. (`app/middlewares/bot_detection.py:213-257`)

- [x] **H-3** — Exfiltration detection same post-execution block issue: data is already queried before the 403 fires. (`app/middlewares/exfiltration_detection.py:84-185`)

- [x] **H-4** — `_incrby` TTL race condition: "first write" detection using `val == amount` is incorrect for concurrent requests with variable byte amounts. (`app/middlewares/exfiltration_detection.py:57-60`)

- [x] **H-5** — 5 Prometheus alert rules reference non-existent metrics: `ritapi_redis_connected`, `ritapi_injections_total`, `ritapi_exfil_blocks_total`, `ritapi_request_duration_seconds_bucket`, and `ritapi_active_api_keys` are never registered — those alerts silently never fire. (`docker/prometheus/alerts.yaml`)

- [x] **H-6** — Undocumented CVE suppression in CI: `CVE-2026-30922` suppressed in `pip-audit` with no entry in `docs/PENTEST.md`; future-dated CVE ID may be fabricated or a placeholder. (`.github/workflows/ci.yml:64`)

---

## Medium

- [x] **M-1** — Env var name mismatch: docs and `.env.staging` use `REDIS_SENTINEL_MASTER` but code reads `REDIS_SENTINEL_SERVICE` — Sentinel deployments silently fall back to `mymaster`. (`app/utils/redis_client.py:64`, `.env.staging:37`)

- [x] **M-2** — `DASHBOARD_TOKEN` absent from all deployment templates: missing from `.env.example`, `.env.staging`, and Helm ConfigMap — dashboard deploys with no auth by default. (`.env.example`, `helm/ritapi-advanced/templates/configmap.yaml`)

- [ ] **M-3** — `ADMIN_SECRET` missing from `.env.example`: operators following the example file will deploy with admin bootstrap auth silently disabled. (`.env.example`)

- [ ] **M-4** — `_tail_jsonl` silently returns fewer than N events for long log lines: 300-byte-per-line estimate causes silent truncation with no indication. (`app/web/dashboard.py:66-67`)

- [ ] **M-5** — Test fixture scope mismatch: `flush_test_redis` is function-scoped but depends on session-scoped `redis` fixture — failover tests that call `mark_failed()` can dirty subsequent tests. (`tests/conftest.py:50-57`)

- [ ] **M-6** — Double body read relies on Starlette internal caching: `SchemaEnforcementMiddleware` and `InjectionDetectionMiddleware` both read the request body — fragile coupling to Starlette's `_body` caching behavior. (`app/middlewares/schema_enforcement.py:66`, `app/middlewares/injection_detection.py:234`)

- [x] **M-7** — Injection blocks bypass `DecisionEngineMiddleware` entirely: injection middleware returns directly without calling `call_next`, so `request.state.policy` and `request.state.route` are never set for blocked requests. (`app/middlewares/injection_detection.py:221-280`)

- [ ] **M-8** — Per-process singletons unreliable with multiple workers: YARA scanner, Redis client, and policy/route caches are per-process — hot-reload via SIGHUP or `reload_policies()` only affects one worker under `uvicorn --workers 2`. (`app/utils/yara_scanner.py:183`, `Dockerfile:72`)

- [x] **M-9** — Redis DB mismatch between local and CI: tests use DB 15 locally but DB 1 in CI — `flushdb()` in CI could destroy unrelated data if DB 1 has pre-existing state. (`tests/conftest.py:15`, `.github/workflows/ci.yml:113`)

- [x] **M-10** — `/readyz` in rate-limit skip list but route does not exist: load balancers probing `/readyz` receive a 401 (not in auth bypass list) or 404. (`app/middlewares/rate_limit.py:32`)

---

## Low

- [ ] **L-1** — Developer username and filesystem path committed in `.env`: `LOG_PATH=/home/stardhoom/...` exposes developer info. (`.env:10`)

- [x] **L-2** — Broken `ritapi` CLI entry point in `pyproject.toml`: points to `app.main:app` (a FastAPI instance), not a callable — `ritapi` command does not work. (`pyproject.toml:56`)

- [x] **L-3** — Test dependencies bundled in production image: `pytest`, `pytest-anyio`, `anyio`, `pytest-cov` are in `requirements.txt` and installed into the Docker image. (`requirements.txt:13-16`)

- [ ] **L-4** — `XSS_Dangerous_Tags` YARA rule too broad: `2 of them` condition matches normal HTML containing e.g. `<details>` and `<svg>` — high false-positive risk for CMS or rich-text payloads. (`rules/xss.yar:92`)

- [x] **L-5** — `throttle` action in policy is a documented no-op: `on_rate_limit: throttle` in `auth.yml` has the same effect as `allow`. (`configs/policies/auth.yml:18`, `app/middlewares/decision_engine.py:69-72`)

- [ ] **L-6** — `autouse` Redis flush skips entire test suite if Redis is unavailable: pure unit tests (WAF regex, JWT, RBAC) cannot run without Redis due to the autouse dependency chain. (`tests/conftest.py:50-57`)

- [ ] **L-7** — `_tail_jsonl` truncation not surfaced to caller: no error or metadata returned when fewer than N lines are available. (`app/web/dashboard.py:66`)

- [ ] **L-8** — Potential counter state leak in parametrized bot detection tests: within-test accumulation of Redis counters could cause false `RAPID_FIRE` hits at scale. (`tests/test_bot_detection.py:76-80`)

- [x] **L-9** — Typo in Helm `values.yaml` image repository: `ritapi-advance` should be `ritapi-advanced` — default Helm install pulls from a non-existent image. (`helm/ritapi-advanced/values.yaml:7`)

- [x] **L-10** — Missing test coverage: no tests for `DecisionEngineMiddleware` policy dispatch, `SchemaEnforcementMiddleware`, API key rotation atomicity, or dashboard with `DASHBOARD_TOKEN` set. (`tests/`)
