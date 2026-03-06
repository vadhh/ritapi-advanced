"""
JWT authentication handler.

Issues and verifies JWT tokens for API consumers.
Role is embedded in the token as the "role" claim and read by RBAC.

Source ported from:
  ritapi-v-sentinel/projects/minifw_ai_service/app/services/auth/token_service.py
Changes:
  - Cookie-based auth replaced with Authorization: Bearer header
  - Decoupled from MiniFW User model — operates on plain dicts
  - Reads config from env (SECRET_KEY, JWT_ALGORITHM, JWT_EXPIRE_MINUTES)
"""
import logging
import os
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, Request, status
from jose import JWTError, jwt

logger = logging.getLogger(__name__)

SECRET_KEY: str = os.getenv("SECRET_KEY", "")
ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is not set.")


def create_access_token(subject: str, role: str, extra: dict | None = None) -> str:
    """
    Issue a signed JWT.

    Args:
        subject: Identity string (username, client ID, etc.)
        role:    One of SUPER_ADMIN | ADMIN | OPERATOR | AUDITOR | VIEWER
        extra:   Optional additional claims merged into the payload.

    Returns:
        Encoded JWT string.
    """
    expire = datetime.now(UTC) + timedelta(minutes=EXPIRE_MINUTES)
    payload = {"sub": subject, "role": role, "exp": expire}
    if extra:
        payload.update(extra)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> dict | None:
    """
    Decode and validate a JWT.

    Returns the payload dict on success, or None if the token is invalid/expired.
    """
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as e:
        logger.debug("JWT verification failed: %s", e)
        return None


def get_token_from_request(request: Request) -> str | None:
    """Extract Bearer token from Authorization header."""
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def require_jwt(request: Request) -> dict:
    """
    FastAPI dependency — resolves the current token payload or raises 401.

    Usage:
        @app.get("/protected")
        def route(claims: dict = Depends(require_jwt)):
            ...
    """
    token = get_token_from_request(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization: Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload
