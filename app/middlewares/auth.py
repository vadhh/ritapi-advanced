"""
Authentication Middleware.

Enforces JWT (Authorization: Bearer) or API key (X-API-Key) on every request
except the bypass list. On success, attaches claims to request.state.claims so
that downstream RBAC dependencies can read them without re-validating.

Bypass paths (no auth required):
  /healthz        — liveness probe
  /metrics        — Prometheus scrape (network-level access control recommended)
  /dashboard*     — dashboard UI (add auth guard separately if needed)
"""
import logging

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.auth.api_key_handler import validate_api_key
from app.auth.jwt_handler import get_token_from_request, verify_token
from app.utils.logging import log_request
from app.utils.metrics import auth_failures

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

        ip = (
            (request.headers.get("x-forwarded-for", "").split(",")[0].strip())
            or (request.client.host if request.client else "unknown")
        )

        claims = None
        auth_method = "missing"

        # 1. Try JWT Bearer
        token = get_token_from_request(request)
        if token:
            auth_method = "jwt"
            claims = verify_token(token)
            if claims is None:
                logger.debug("Auth: invalid/expired JWT from %s on %s", ip, path)

        # 2. Fall back to API key
        if claims is None:
            raw_key = request.headers.get("x-api-key", "").strip()
            if raw_key:
                auth_method = "api_key"
                claims = validate_api_key(raw_key)
                if claims is None:
                    logger.debug("Auth: invalid API key from %s on %s", ip, path)

        # 3. Reject if no valid credential
        if claims is None:
            logger.warning("Auth: rejected %s %s from %s (method=%s)", request.method, path, ip, auth_method)
            auth_failures.labels(method=auth_method).inc()
            log_request(
                client_ip=ip,
                path=path,
                method=request.method,
                action="block",
                detection_type="auth_failure",
                score=1.0,
                reasons=f"No valid credential (attempted: {auth_method})",
            )
            return JSONResponse(
                {
                    "error": "Unauthorized",
                    "detail": "Provide a valid Bearer token (Authorization: Bearer <jwt>) or API key (X-API-Key: <key>)",
                },
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Attach claims for RBAC and route handlers
        request.state.claims = claims
        return await call_next(request)
