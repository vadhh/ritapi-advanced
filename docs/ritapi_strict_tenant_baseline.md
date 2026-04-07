# RitAPI Advanced — Strict Tenant Baseline
**Date:** 2026-04-07  
**Purpose:** Lock the enforcement baseline so today's tenant-isolation work does not silently break it.

---

## Confirmed enforcement paths (as of 2026-04-07)

| Path | Status | Evidence |
|------|--------|---------|
| Bot detection (13 rules) | ✅ Validated | `BotDetectionMiddleware` → `append_detection` → DecisionEngine |
| Injection detection (96 patterns + YARA) | ✅ Validated | `InjectionDetectionMiddleware` → `append_detection` |
| Exfiltration detection (4 heuristics) | ✅ Validated | `ExfiltrationDetectionMiddleware` → `append_detection` |
| Rate limiting (per-IP, per-key) | ✅ Validated | `RateLimitMiddleware` → tenant-scoped Redis keys |
| DecisionEngine as last policy gate | ✅ Validated | innermost middleware; reads detections + legacy block flag |
| SIEM logging (`SecurityEventLogger`) | ✅ Active | called from `DecisionEngineMiddleware._block_response` etc. |
| Tenant spoofing via `X-Target-ID` | ✅ Partially patched | `TenantContextMiddleware` sanitises header (regex); `AuthMiddleware` validates credential_tenant vs claimed_tenant |

---

## Tenant isolation state at baseline

- `TenantContextMiddleware` sets `request.state.tenant_id` from `X-Target-ID` (sanitised).
- `AuthMiddleware` checks `credential_tenant != claimed_tenant` → `auth_failure` detection.
- `TENANT_STRICT_MODE=false` by default — legacy credentials without a `tid`/`tenant_id` claim **pass through**.
- Tests for strict-mode behavior exist in `tests/test_strict_tenant_mode.py` (4 tests, all unit-level).

## Known gaps at baseline

1. **Legacy credentials bypass tenant check** — when `TENANT_STRICT_MODE` is off (default), tokens with no `tid` claim are allowed through regardless of the claimed tenant in `X-Target-ID`.
2. **No integration test** exercises the full middleware stack with a mismatched tenant; current tests verify logic in isolation only.
3. **Admin routes bypass AuthMiddleware** — `/admin*` routes are in `_BYPASS_PREFIXES`; tenant binding is not enforced there.

---

## Non-goals for today

- Do not change HardGateMiddleware behavior.
- Do not change injection/exfiltration/bot detection patterns.
- Do not change DecisionEngine action resolution.

Any work today that alters the above bullet points must be flagged before merging.
