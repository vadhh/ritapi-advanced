"""
Authentication Middleware.

Enforces JWT (Authorization: Bearer) or API key (X-API-Key) based on the
per-route policy loaded by the DecisionEngine. When no policy is set or the
route is bypassed, auth is skipped.

Policy-driven behavior:
  - policy.auth.jwt = true  → accept JWT Bearer tokens
  - policy.auth.api_key = true → accept X-API-Key headers
  - Both false → auth is skipped for this route

Bypass paths (no auth regardless of policy):
  /healthz        — liveness probe
  /metrics        — Prometheus scrape
  /dashboard*     — dashboard UI (add auth guard separately if needed)

Tenant verification (always enforced on non-bypass routes):
  Every valid credential MUST carry a tenant claim ("tid" for JWT,
  "tenant_id" for API key metadata).  The embedded value is compared
  against request.state.claimed_tenant_id set by TenantContextMiddleware.
  On success:
    request.state.tenant_id      = credential_tenant  (verified)
    request.state.tenant_verified = True
  On failure (missing claim or mismatch) an auth_failure detection is
  appended and the request is forwarded to DecisionEngineMiddleware for
  the 403 response.
"""
import logging
import time

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.auth.api_key_handler import validate_api_key
from app.auth.jwt_handler import get_token_from_request, verify_token
from app.middlewares.detection_schema import append_detection
from app.utils.metrics import auth_failures
from app.utils.perf import add_redis_ms, get_perf

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Bypass configuration
# ---------------------------------------------------------------------------

_BYPASS_EXACT: frozenset[str] = frozenset({"/healthz", "/metrics"})
# /admin routes perform their own auth (RBAC + ADMIN_SECRET header).
# /dashboard is open by design (add dashboard auth guard separately if needed).
_BYPASS_PREFIXES: tuple[str, ...] = ("/dashboard", "/admin")


def _is_bypassed(path: str) -> bool:
    return path in _BYPASS_EXACT or any(path.startswith(p) for p in _BYPASS_PREFIXES)


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if _is_bypassed(path):
            return await call_next(request)

        # Read policy from request state (set by DecisionEngine, which runs innermost
        # but add_middleware order means it's added first — so it actually dispatches
        # after this middleware). If policy is not yet available, fall back to
        # requiring both JWT and API key (safe default).
        policy = getattr(request.state, "policy", None)

        # Determine which auth methods this route accepts
        accept_jwt = True
        accept_api_key = True
        if policy is not None:
            accept_jwt = policy.auth.jwt
            accept_api_key = policy.auth.api_key

        # If the policy disables both auth methods, skip auth entirely
        if not accept_jwt and not accept_api_key:
            return await call_next(request)

        ip = (
            (request.headers.get("x-forwarded-for", "").split(",")[0].strip())
            or (request.client.host if request.client else "unknown")
        )

        claims = None
        auth_method = "missing"
        _t_auth = time.monotonic()

        # 1. Try JWT Bearer
        if accept_jwt:
            token = get_token_from_request(request)
            if token:
                auth_method = "jwt"
                claims = verify_token(token)
                if claims is None:
                    logger.debug("Auth: invalid/expired JWT from %s on %s", ip, path)

        # 2. Fall back to API key
        if claims is None and accept_api_key:
            raw_key = request.headers.get("x-api-key", "").strip()
            if raw_key:
                auth_method = "api_key"
                _t_redis = time.monotonic()
                claims = validate_api_key(raw_key)
                add_redis_ms(request, (time.monotonic() - _t_redis) * 1000)
                if claims is None:
                    # nosemgrep: python-logger-credential-disclosure — logs IP/path, not the key
                    logger.debug("Auth: invalid API key from %s on %s", ip, path)

        # 3. Reject if no valid credential — write detection and route through DecisionEngine
        if claims is None:
            get_perf(request)["auth_ms"] = round((time.monotonic() - _t_auth) * 1000, 3)
            logger.warning(
                "Auth: rejected %s %s from %s (method=%s)", request.method, path, ip, auth_method
            )
            auth_failures.labels(method=auth_method).inc()
            append_detection(
                request,
                detection_type="auth_failure",
                score=1.0,
                reason=f"No valid credential (attempted: {auth_method})",
                status_code=401,
                source="auth",
                metadata={"auth_method": auth_method, "path": path},
            )
            return await call_next(request)

        # 4. Tenant verification gate — always enforced.
        # TenantContextMiddleware wrote the client's claimed tenant to
        # request.state.claimed_tenant_id.  The credential must carry a
        # matching tenant claim; credentials without any tenant claim are
        # rejected unconditionally (no legacy pass-through).
        claimed_tenant = getattr(request.state, "claimed_tenant_id", "default")
        credential_tenant = claims.get("tid") or claims.get("tenant_id")

        if not credential_tenant:
            get_perf(request)["auth_ms"] = round((time.monotonic() - _t_auth) * 1000, 3)
            logger.warning(  # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
                "Auth: rejecting unbound token from %s on %s — no tenant claim in payload",
                ip, path,
            )
            auth_failures.labels(method="tenant_unbound").inc()
            append_detection(
                request,
                detection_type="auth_failure",
                score=1.0,
                reason="Credential carries no tenant claim (unbound credential rejected)",
                status_code=403,
                source="auth",
                metadata={"auth_method": auth_method, "path": path},
            )
            return await call_next(request)

        if credential_tenant != claimed_tenant:
            get_perf(request)["auth_ms"] = round((time.monotonic() - _t_auth) * 1000, 3)
            logger.warning(
                "Auth: tenant mismatch from %s — credential_tenant=%r claimed=%r",
                ip, credential_tenant, claimed_tenant,
            )
            auth_failures.labels(method="tenant_mismatch").inc()
            append_detection(
                request,
                detection_type="auth_failure",
                score=1.0,
                reason=(
                    f"Tenant mismatch: credential is bound to {credential_tenant!r} "
                    f"but request claims {claimed_tenant!r}"
                ),
                status_code=403,
                source="auth",
                metadata={
                    "credential_tenant": credential_tenant,
                    "claimed_tenant": claimed_tenant,
                    "auth_method": auth_method,
                },
            )
            return await call_next(request)

        # Verified: bind the confirmed tenant and attach claims for RBAC and route handlers
        get_perf(request)["auth_ms"] = round((time.monotonic() - _t_auth) * 1000, 3)
        request.state.tenant_id = credential_tenant
        request.state.tenant_verified = True
        request.state.claims = claims
        return await call_next(request)
