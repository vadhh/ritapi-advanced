"""
RBAC — 5-level role enforcement for API endpoints.

Ported from:
  ritapi-v-sentinel/projects/minifw_ai_service/app/services/rbac_service.py
Removed from source:
  - SQLAlchemy Session / User model dependency
  - SectorType (network-firewall concept, not applicable here)
  - AuditService (no DB in this service)
  - can_modify_user (user management not a RitAPI Advanced concern)

Usage
-----
Protect a route by role:

    from app.rbac.rbac_service import require_role, UserRole

    @app.get("/admin/data")
    def admin_route(claims: dict = Depends(require_role(UserRole.ADMIN))):
        ...

`claims` is the decoded JWT payload or API key metadata dict —
both contain a "role" string key (set by jwt_handler / api_key_handler).

Role hierarchy (higher value = more permissive):
    SUPER_ADMIN = 5
    ADMIN       = 4
    OPERATOR    = 3
    AUDITOR     = 2
    VIEWER      = 1
"""
from collections.abc import Callable
from enum import IntEnum

from fastapi import HTTPException, status


class UserRole(IntEnum):
    VIEWER      = 1
    AUDITOR     = 2
    OPERATOR    = 3
    ADMIN       = 4
    SUPER_ADMIN = 5

    @classmethod
    def from_string(cls, value: str) -> "UserRole":
        try:
            return cls[value.upper()]
        except KeyError as err:
            raise ValueError(f"Unknown role: {value!r}") from err


# ---------------------------------------------------------------------------
# Auth resolution — accepts JWT or API key, returns claims dict
# ---------------------------------------------------------------------------

def _get_claims_from_jwt_or_key(
    jwt_claims: dict | None = None,
    key_meta: dict | None = None,
) -> dict:
    """Return the first available claims dict from either auth path."""
    return jwt_claims or key_meta or {}


async def resolve_claims(request) -> dict:
    """
    Attempt JWT auth first, then API key auth.
    Raises 401 if neither is present/valid.
    """
    from app.auth.api_key_handler import validate_api_key
    from app.auth.jwt_handler import get_token_from_request, verify_token

    # Try JWT
    token = get_token_from_request(request)
    if token:
        payload = verify_token(token)
        if payload:
            return payload

    # Try API key
    raw_key = request.headers.get("x-api-key", "").strip()
    if raw_key:
        meta = validate_api_key(raw_key)
        if meta:
            return meta

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required (Bearer token or X-API-Key)",
        headers={"WWW-Authenticate": "Bearer"},
    )


# ---------------------------------------------------------------------------
# Role enforcement dependency factory
# ---------------------------------------------------------------------------

def require_role(min_role: UserRole) -> Callable:
    """
    Returns a FastAPI dependency that enforces a minimum role level.

    The dependency resolves the caller's identity via JWT or API key,
    parses the "role" claim, and raises 403 if insufficient.

    Example:
        @app.delete("/resource")
        def delete(claims = Depends(require_role(UserRole.ADMIN))):
            ...
    """
    async def dependency(request) -> dict:
        claims = await resolve_claims(request)

        role_str = claims.get("role", "")
        if not role_str:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Token does not contain a role claim.",
            )

        try:
            caller_role = UserRole.from_string(role_str)
        except ValueError as err:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Unrecognised role: {role_str!r}",
            ) from err

        if caller_role < min_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Insufficient permissions. "
                    f"Required: {min_role.name} (level {min_role}), "
                    f"your role: {caller_role.name} (level {caller_role})."
                ),
            )

        return claims

    return dependency


# ---------------------------------------------------------------------------
# Convenience shortcuts
# ---------------------------------------------------------------------------

require_viewer      = require_role(UserRole.VIEWER)
require_auditor     = require_role(UserRole.AUDITOR)
require_operator    = require_role(UserRole.OPERATOR)
require_admin       = require_role(UserRole.ADMIN)
require_super_admin = require_role(UserRole.SUPER_ADMIN)
