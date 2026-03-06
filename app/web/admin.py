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
"""
import logging
import os

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.auth.api_key_handler import issue_api_key, revoke_api_key, rotate_api_key
from app.auth.jwt_handler import create_access_token
from app.rbac.rbac_service import UserRole, require_role

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
    return x_admin_secret == _ADMIN_SECRET


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


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/token", response_model=TokenResponse, summary="Issue a JWT")
async def issue_token(
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
    token = create_access_token(subject=body.subject, role=role.name)
    logger.info(  # nosemgrep: python-logger-credential-disclosure
        "Token issued: subject=%s role=%s by=%s",
        body.subject, role.name, caller.get("subject"),
    )
    return TokenResponse(
        access_token=token,
        expires_in=EXPIRE_MINUTES * 60,
        subject=body.subject,
        role=role.name,
    )


@router.post("/apikey", response_model=ApiKeyResponse, summary="Issue an API key")
async def issue_key(
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
        raw_key = issue_api_key(body.subject, role.name, ttl_seconds=ttl_seconds)
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e)
        ) from e

    logger.info(  # nosemgrep: python-logger-credential-disclosure
        "API key issued: subject=%s role=%s ttl_days=%s by=%s",
        body.subject, role.name, body.ttl_days, caller.get("subject"),
    )
    return ApiKeyResponse(
        api_key=raw_key,
        subject=body.subject,
        role=role.name,
        expires_in_seconds=ttl_seconds,
    )


@router.post("/apikey/rotate", response_model=ApiKeyResponse, summary="Rotate an API key")
async def rotate_key(
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
    logger.info("API key rotated by=%s", caller.get("subject"))  # nosemgrep: python-logger-credential-disclosure
    return ApiKeyResponse(
        api_key=new_key,
        subject=meta.get("subject", ""),
        role=meta.get("role", ""),
        expires_in_seconds=ttl_seconds,
    )


@router.delete("/apikey", summary="Revoke an API key")
async def revoke_key(
    body: ApiKeyRevokeRequest,
    caller: dict = Depends(_require_admin_access),
):
    """
    Permanently revoke an API key.
    Requires ADMIN+ or a valid ADMIN_SECRET header.
    """
    deleted = revoke_api_key(body.api_key)
    logger.info("API key revoke by=%s result=%s", caller.get("subject"), deleted)  # nosemgrep: python-logger-credential-disclosure
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found (already revoked or never existed).",
        )
    return {"revoked": True}
