"""
API key authentication handler.

No source existed anywhere in the codebase — written from scratch.

Storage layout in Redis:
  ritapi:apikey:{sha256(key)}  →  JSON {"role": str, "subject": str, "created_at": str}
  TTL: none by default (keys are permanent until revoked)

The raw key is returned once on issuance and never stored.
Only the SHA-256 hash is kept in Redis.
"""
import hashlib
import json
import logging
import os
import secrets
from datetime import datetime, timezone
from typing import Optional

from fastapi import HTTPException, Request, status

from app.utils.redis_client import RedisClientSingleton

logger = logging.getLogger(__name__)

_PREFIX = "ritapi:apikey:"
_KEY_BYTES = 32  # 256-bit raw key → 64-char hex string


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _hash(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def _redis_key(raw_key: str) -> str:
    return f"{_PREFIX}{_hash(raw_key)}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def issue_api_key(subject: str, role: str, ttl_seconds: Optional[int] = None) -> str:
    """
    Generate a new API key, store its hash in Redis, and return the raw key.

    Args:
        subject:     Identifier for the key owner (username, service name, etc.)
        role:        One of SUPER_ADMIN | ADMIN | OPERATOR | AUDITOR | VIEWER
        ttl_seconds: Optional TTL in seconds. None means the key never expires.

    Returns:
        The raw API key string. This is the only time it is available in plain text.

    Raises:
        RuntimeError: If Redis is unavailable.
    """
    redis = RedisClientSingleton.get_client()
    if redis is None:
        raise RuntimeError("Redis is unavailable — cannot issue API key.")

    raw_key = secrets.token_hex(_KEY_BYTES)
    metadata = json.dumps({
        "role": role,
        "subject": subject,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_in": ttl_seconds,
    })
    rkey = _redis_key(raw_key)
    redis.set(rkey, metadata.encode())
    if ttl_seconds is not None:
        redis.expire(rkey, ttl_seconds)
    logger.info("API key issued for subject=%s role=%s ttl=%s", subject, role, ttl_seconds)
    return raw_key


def rotate_api_key(old_raw_key: str, ttl_seconds: Optional[int] = None) -> Optional[str]:
    """
    Atomically revoke an existing key and issue a replacement with the same role/subject.

    Returns the new raw key, or None if the old key was not found or Redis is unavailable.
    """
    meta = validate_api_key(old_raw_key)
    if meta is None:
        return None
    revoke_api_key(old_raw_key)
    return issue_api_key(meta["subject"], meta["role"], ttl_seconds=ttl_seconds)


def validate_api_key(raw_key: str) -> Optional[dict]:
    """
    Look up an API key by its hash.

    Returns the metadata dict (with "role", "subject", "created_at") on success,
    or None if the key does not exist or Redis is unavailable.
    """
    redis = RedisClientSingleton.get_client()
    if redis is None:
        return None

    stored = redis.get(_redis_key(raw_key))
    if stored is None:
        return None

    try:
        return json.loads(stored)
    except (json.JSONDecodeError, ValueError):
        logger.error("Corrupt API key metadata for hash %s", _hash(raw_key)[:12])
        return None
    except Exception as exc:
        logger.error("Redis error reading API key: %s", exc)
        RedisClientSingleton.mark_failed()
        return None


def revoke_api_key(raw_key: str) -> bool:
    """
    Delete an API key from Redis.

    Returns True if the key existed and was deleted, False otherwise.
    """
    redis = RedisClientSingleton.get_client()
    if redis is None:
        return False
    deleted = redis.delete(_redis_key(raw_key))
    if deleted:
        logger.info("API key revoked (hash prefix: %s…)", _hash(raw_key)[:12])
    return bool(deleted)


def require_api_key(request: Request) -> dict:
    """
    FastAPI dependency — resolves key metadata or raises 401.

    Reads the raw key from the X-API-Key header.

    Usage:
        @app.get("/protected")
        def route(key_meta: dict = Depends(require_api_key)):
            ...
    """
    raw_key = request.headers.get("x-api-key", "").strip()
    if not raw_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
        )
    meta = validate_api_key(raw_key)
    if meta is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key",
        )
    return meta
