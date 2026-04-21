"""
Admin API — token and API key management.

Bootstrap auth: pass ADMIN_SECRET from env in the X-Admin-Secret header.
Once you have a SUPER_ADMIN JWT you can use that instead of the secret.

Endpoints
---------
POST /admin/token       Issue a JWT (admin secret or SUPER_ADMIN token required)
POST /admin/apikey      Issue an API key (ADMIN+ or admin secret)
POST /admin/apikey/rotate  Rotate an existing key (ADMIN+ or admin secret)
DELETE /admin/apikey    Revoke an API key (ADMIN+ or admin secret)
POST /admin/reload      Reload routing + policy YAML files (SUPER_ADMIN or admin secret)
"""
import hmac
import logging
import os

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.auth.api_key_handler import issue_api_key, revoke_api_key, rotate_api_key
from app.auth.jwt_handler import create_access_token
from app.utils.ip_blocklist import block_ip, get_blocked_ips, unblock_ip
from app.utils.jwt_denylist import add_to_denylist
from app.policies.service import get_all_policies, reload_policies
from app.rbac.rbac_service import UserRole, require_role
from app.routing.service import get_all_routes, reload_routes
from app.utils.logging import log_admin_event

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["Admin"])

_ADMIN_SECRET: str = os.getenv("ADMIN_SECRET", "")


# ---------------------------------------------------------------------------
# Bootstrap auth helper
# ---------------------------------------------------------------------------

def _is_admin_secret(x_admin_secret: str = Header(default="")) -> bool:
    """Returns True if the request provides the correct ADMIN_SECRET header."""
    if not _ADMIN_SECRET:
        return False
    return hmac.compare_digest(x_admin_secret, _ADMIN_SECRET)


async def _require_admin_access(
    request: Request,
    has_secret: bool = Depends(_is_admin_secret),
) -> dict:
    """
    Allows access if:
      - X-Admin-Secret matches ADMIN_SECRET, OR
      - The caller has ADMIN or higher role (from JWT / API key resolved by AuthMiddleware)
    Returns the claims dict on success.
    """
    if has_secret:
        return {"subject": "__admin_secret__", "role": "SUPER_ADMIN"}

    # Fall through to RBAC check
    try:
        return await require_role(UserRole.ADMIN)(request)
    except HTTPException as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Provide a valid X-Admin-Secret header or an ADMIN+ JWT / API key.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from err


async def _require_super_admin_access(
    request: Request,
    has_secret: bool = Depends(_is_admin_secret),
) -> dict:
    """Like _require_admin_access but requires SUPER_ADMIN for role-sensitive operations."""
    if has_secret:
        return {"subject": "__admin_secret__", "role": "SUPER_ADMIN"}
    try:
        return await require_role(UserRole.SUPER_ADMIN)(request)
    except HTTPException as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Provide a valid X-Admin-Secret header or a SUPER_ADMIN JWT / API key.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from err


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class TokenRequest(BaseModel):
    subject: str = Field(
        ..., min_length=1, max_length=128, description="Identity (username, service name)"
    )
    role: str = Field(..., description="VIEWER | AUDITOR | OPERATOR | ADMIN | SUPER_ADMIN")
    tenant_id: str = Field(
        default="default",
        min_length=1,
        max_length=64,
        pattern=r'^[a-zA-Z0-9_-]+$',
        description="Tenant this token is bound to. Defaults to 'default'.",
    )


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    subject: str
    role: str


class ApiKeyRequest(BaseModel):
    subject: str = Field(..., min_length=1, max_length=128)
    role: str = Field(..., description="VIEWER | AUDITOR | OPERATOR | ADMIN | SUPER_ADMIN")
    ttl_days: int | None = Field(
        None, ge=1, le=3650, description="Key TTL in days. Omit for no expiry."
    )
    tenant_id: str = Field(
        default="default",
        min_length=1,
        max_length=64,
        pattern=r'^[a-zA-Z0-9_-]+$',
        description="Tenant this key is bound to. Defaults to 'default'.",
    )


class ApiKeyResponse(BaseModel):
    api_key: str
    subject: str
    role: str
    expires_in_seconds: int | None
    warning: str = "Store this key securely. It will not be shown again."


class ApiKeyRotateRequest(BaseModel):
    old_api_key: str = Field(..., min_length=1)
    ttl_days: int | None = Field(None, ge=1, le=3650)


class ApiKeyRevokeRequest(BaseModel):
    api_key: str = Field(..., min_length=1)


class RevokeTokenRequest(BaseModel):
    token: str = Field(..., description="The JWT to revoke")


class BlockIPRequest(BaseModel):
    ip: str = Field(..., description="IP address to block or unblock")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/token", response_model=TokenResponse, summary="Issue a JWT")
async def issue_token(
    request: Request,
    body: TokenRequest,
    caller: dict = Depends(_require_super_admin_access),
):
    """
    Issue a signed JWT for the given subject and role.
    Requires SUPER_ADMIN privileges or a valid ADMIN_SECRET header.
    """
    try:
        role = UserRole.from_string(body.role)
    except ValueError as err:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Invalid role {body.role!r}. "
                "Valid: VIEWER, AUDITOR, OPERATOR, ADMIN, SUPER_ADMIN"
            ),
        ) from err

    from app.auth.jwt_handler import EXPIRE_MINUTES
    token = create_access_token(subject=body.subject, role=role.name, tenant_id=body.tenant_id)
    log_admin_event(
        action="token_issued",
        subject=body.subject,
        role=role.name,
        issuer=caller.get("subject", "unknown"),
        tenant_id=body.tenant_id,
        request_id=getattr(request.state, "request_id", None),
    )
    return TokenResponse(
        access_token=token,
        expires_in=EXPIRE_MINUTES * 60,
        subject=body.subject,
        role=role.name,
    )


@router.post("/token/revoke", summary="Revoke a JWT before it expires")
async def revoke_token(
    body: RevokeTokenRequest,
    request: Request,
    caller: dict = Depends(_require_admin_access),
):
    """
    Revoke a JWT by its jti claim.

    Decodes without re-validating the signature — revocation is an admin action.
    Stores jti in Redis denylist with TTL = remaining token lifetime.
    Returns 400 if the token cannot be decoded or has no jti claim.
    """
    import math
    import time as _time
    from jose import JWTError
    from jose import jwt as jose_jwt
    from app.auth.jwt_handler import SECRET_KEY, ALGORITHM

    try:
        payload = jose_jwt.decode(
            body.token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"verify_exp": False},
        )
    except JWTError as exc:
        raise HTTPException(status_code=400, detail=f"Cannot decode token: {exc}")

    jti = payload.get("jti")
    if not jti:
        raise HTTPException(status_code=400, detail="Token has no jti claim — cannot revoke")

    exp = payload.get("exp", 0)
    remaining = max(1, math.ceil(exp - _time.time()))
    add_to_denylist(jti, ttl=remaining)

    log_admin_event(
        action="jwt_revoked",
        subject=payload.get("sub", "unknown"),
        issuer="admin_revoke",
        metadata={"jti": jti, "ttl": remaining},
    )
    return {"revoked": True, "jti": jti, "ttl_seconds": remaining}


@router.post("/ip/block", summary="Add an IP to the permanent blocklist")
async def add_ip_block(
    body: BlockIPRequest,
    request: Request,
    caller: dict = Depends(_require_admin_access),
):
    """Permanently block an IP via the Redis blocklist. Takes effect immediately."""
    block_ip(body.ip)
    log_admin_event(
        action="ip_blocked",
        subject=caller.get("subject", "unknown"),
        issuer=caller.get("subject", "unknown"),
        request_id=getattr(request.state, "request_id", None),
        metadata={"ip": body.ip},
    )
    return {"blocked": True, "ip": body.ip}


@router.delete("/ip/block", summary="Remove an IP from the permanent blocklist")
async def remove_ip_block(
    body: BlockIPRequest,
    request: Request,
    caller: dict = Depends(_require_admin_access),
):
    """Unblock a previously blocked IP. Takes effect immediately."""
    removed = unblock_ip(body.ip)
    log_admin_event(
        action="ip_unblocked",
        subject=caller.get("subject", "unknown"),
        issuer=caller.get("subject", "unknown"),
        request_id=getattr(request.state, "request_id", None),
        metadata={"ip": body.ip, "was_present": removed},
    )
    return {"unblocked": True, "ip": body.ip, "was_present": removed}


@router.get("/ip/block", summary="List all permanently blocked IPs")
async def list_ip_blocks(
    request: Request,
    caller: dict = Depends(_require_admin_access),
):
    """Return the full Redis permanent IP blocklist."""
    ips = get_blocked_ips()
    return {"blocked_ips": sorted(ips), "count": len(ips)}


@router.post("/apikey", response_model=ApiKeyResponse, summary="Issue an API key")
async def issue_key(
    request: Request,
    body: ApiKeyRequest,
    caller: dict = Depends(_require_admin_access),
):
    """
    Issue an API key for the given subject and role.
    Requires ADMIN+ or a valid ADMIN_SECRET header.
    """
    try:
        role = UserRole.from_string(body.role)
    except ValueError as err:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid role {body.role!r}.",
        ) from err

    ttl_seconds = body.ttl_days * 86400 if body.ttl_days else None
    try:
        raw_key = issue_api_key(
            body.subject, role.name, tenant_id=body.tenant_id, ttl_seconds=ttl_seconds
        )
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e)
        ) from e

    log_admin_event(
        action="apikey_issued",
        subject=body.subject,
        role=role.name,
        issuer=caller.get("subject", "unknown"),
        tenant_id=body.tenant_id,
        request_id=getattr(request.state, "request_id", None),
        metadata={"ttl_days": body.ttl_days},
    )
    return ApiKeyResponse(
        api_key=raw_key,
        subject=body.subject,
        role=role.name,
        expires_in_seconds=ttl_seconds,
    )


@router.post("/apikey/rotate", response_model=ApiKeyResponse, summary="Rotate an API key")
async def rotate_key(
    request: Request,
    body: ApiKeyRotateRequest,
    caller: dict = Depends(_require_admin_access),
):
    """
    Revoke an existing key and issue a replacement with the same subject and role.
    Requires ADMIN+ or a valid ADMIN_SECRET header.
    """
    ttl_seconds = body.ttl_days * 86400 if body.ttl_days else None
    new_key = rotate_api_key(body.old_api_key, ttl_seconds=ttl_seconds)
    if new_key is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found or Redis unavailable.",
        )

    # Fetch metadata from the new key to return subject/role
    from app.auth.api_key_handler import validate_api_key
    meta = validate_api_key(new_key) or {}
    log_admin_event(
        action="apikey_rotated",
        subject=meta.get("subject", "unknown"),
        issuer=caller.get("subject", "unknown"),
        tenant_id=meta.get("tenant_id", "default"),
        request_id=getattr(request.state, "request_id", None),
    )
    return ApiKeyResponse(
        api_key=new_key,
        subject=meta.get("subject", ""),
        role=meta.get("role", ""),
        expires_in_seconds=ttl_seconds,
    )


@router.delete("/apikey", summary="Revoke an API key")
async def revoke_key(
    request: Request,
    body: ApiKeyRevokeRequest,
    caller: dict = Depends(_require_admin_access),
):
    """
    Permanently revoke an API key.
    Requires ADMIN+ or a valid ADMIN_SECRET header.
    """
    deleted = revoke_api_key(body.api_key)
    log_admin_event(
        action="apikey_revoked",
        subject=caller.get("subject", "unknown"),
        issuer=caller.get("subject", "unknown"),
        request_id=getattr(request.state, "request_id", None),
    )
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found (already revoked or never existed).",
        )
    return {"revoked": True}


@router.post("/reload", summary="Reload routing and policy config")
async def reload_config(
    request: Request,
    caller: dict = Depends(_require_super_admin_access),
):
    """
    Force-reload routing.yml and all policy YAML files on this worker, then
    broadcast a reload signal to all other workers via Redis pub/sub.
    Requires SUPER_ADMIN or a valid ADMIN_SECRET header.
    """
    reload_routes()
    reload_policies()
    routes = get_all_routes()
    policies = get_all_policies()

    from app.utils.reload_broadcaster import broadcast_reload
    workers_notified = broadcast_reload()

    log_admin_event(
        action="config_reloaded",
        subject=caller.get("subject", "unknown"),
        issuer=caller.get("subject", "unknown"),
        request_id=getattr(request.state, "request_id", None),
        metadata={"routes": len(routes), "policies": len(policies), "workers_notified": workers_notified},
    )
    return {
        "reloaded": True,
        "routes": len(routes),
        "policies": len(policies),
        "workers_notified": workers_notified,
    }
