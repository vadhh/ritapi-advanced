# RitAPI Advanced — Tenant Flow (Current / As-Is)
**Date:** 2026-04-07

---

## End-to-end request path (tenant perspective)

```
Client → RequestIDMiddleware
       → TenantContextMiddleware          ← sets claimed_tenant_id
       → HardGateMiddleware
       → RateLimitMiddleware              ← reads tenant_id for Redis keys
       → AuthMiddleware                   ← reads credential_tenant_id, validates
       → SchemaEnforcementMiddleware
       → BotDetectionMiddleware           ← reads tenant_id for Redis keys
       → InjectionDetectionMiddleware
       → ExfiltrationDetectionMiddleware  ← reads tenant_id for Redis keys
       → DecisionEngineMiddleware         ← reads tenant_id for policy lookup + throttle keys
       → route handler
```

---

## Where is `claimed_tenant_id` set?

**File:** `app/middlewares/tenant_context.py` — `TenantContextMiddleware.dispatch()`

```
X-Target-ID header → strip → regex validate ([a-zA-Z0-9_-]{1,64})
  match  → request.state.tenant_id = raw value
  no match / absent → request.state.tenant_id = "default"
```

This is the **only** place `request.state.tenant_id` is written. All downstream code reads it; none overwrite it.

---

## Where is `credential_tenant_id` read?

**File:** `app/middlewares/auth.py` — `AuthMiddleware.dispatch()`, lines 126–127

```python
claimed_tenant    = getattr(request.state, "tenant_id", "default")
credential_tenant = claims.get("tid") or claims.get("tenant_id")
```

- **JWT tokens** embed the tenant as `"tid"` (set by `create_access_token()` in `app/auth/jwt_handler.py:52`).
- **API keys** embed it as `"tenant_id"` in the Redis metadata JSON (set by `issue_api_key()` in `app/auth/api_key_handler.py:77`).
- If neither field is present the credential is considered **unbound** (legacy).

---

## Where is `request.state.tenant_id` finalized?

`TenantContextMiddleware` sets it unconditionally on every request. No other middleware modifies it. It is final from that point forward.

DecisionEngine reads it defensively:
```python
raw_tid = getattr(request.state, "tenant_id", None)
tenant_id = raw_tid if isinstance(raw_tid, str) and raw_tid else "default"
```
This guard exists because DecisionEngine may theoretically run before TenantContext in edge-case test setups; in production the middleware order guarantees TenantContext runs first.

---

## Which paths still accept legacy / no-tenant credentials?

### Condition for legacy pass-through
`TENANT_STRICT_MODE` env var is not set (or set to anything other than `1`, `true`, `yes`).  
Default: **OFF** → legacy pass-through is active.

### Paths where tenant is NOT validated at all

| Path prefix | Reason |
|-------------|--------|
| `/healthz` | `_BYPASS_EXACT` — AuthMiddleware skips entirely |
| `/metrics` | `_BYPASS_EXACT` — AuthMiddleware skips entirely |
| `/dashboard*` | `_BYPASS_PREFIXES` — AuthMiddleware skips entirely |
| `/admin*` | `_BYPASS_PREFIXES` — AuthMiddleware skips entirely; admin routes use their own RBAC + `ADMIN_SECRET` header |

### Paths where tenant IS validated (when credential carries a tenant claim)

All other routes — AuthMiddleware runs and:
1. If `credential_tenant` is set and `≠ claimed_tenant` → `auth_failure` detection (403 via DecisionEngine).
2. If `credential_tenant` is absent **and** `TENANT_STRICT_MODE=false` → passes through with no tenant binding.
3. If `credential_tenant` is absent **and** `TENANT_STRICT_MODE=true` → `auth_failure` detection (403).

---

## Redis key namespace

All tenant-aware middlewares use `tenant_scoped_key()` (`app/utils/tenant_key.py`):

```
ritapi:{tenant_id}:{category}:{subject}
```

| Middleware | Category | Subject |
|-----------|----------|---------|
| RateLimitMiddleware | `rate:ip` | `{ip}:{path_slug}` |
| RateLimitMiddleware | `rate:apikey` | `{key_hash}:{path_slug}` |
| RateLimitMiddleware (reads) | `throttle` | `{ip}` |
| DecisionEngineMiddleware | `throttle` | `{ip}` |
| BotDetectionMiddleware | `bot:*` | varies by rule |
| ExfiltrationDetectionMiddleware | `exfil:*` | varies by heuristic |

---

## Open questions / gaps

1. **`/admin*` bypass** — admin credential issuance (`POST /admin/apikey`) creates keys with a `tenant_id` field, but the admin endpoint itself is exempt from AuthMiddleware's tenant check. A compromised `ADMIN_SECRET` can issue keys for any tenant.
2. **Strict mode is off by default** — operators must explicitly set `TENANT_STRICT_MODE=true` to enforce tenant binding. There is no warning logged when a legacy (unbound) credential passes through.
3. **No runtime audit** — there is no metric or log field that distinguishes "unbound credential passed" from "bound credential passed". Forensics cannot distinguish legacy tokens from properly issued ones post-hoc.
