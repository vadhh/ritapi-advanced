"""Redis-backed JWT revocation denylist.

Each revoked token's jti (JWT ID) is stored as a Redis key with TTL equal
to the token's remaining lifetime. Fail-open: if Redis is unavailable,
is_revoked() returns False so traffic is not blocked.

Key format: ritapi:jwt:revoked:<jti>
"""
import logging

from app.utils.redis_client import RedisClientSingleton

logger = logging.getLogger(__name__)

_KEY_PREFIX = "ritapi:jwt:revoked:"


def _key(jti: str) -> str:
    return f"{_KEY_PREFIX}{jti}"


def add_to_denylist(jti: str, ttl: int) -> None:
    """Mark a JWT as revoked for `ttl` seconds.

    Silently no-ops if Redis is unavailable.
    """
    redis = RedisClientSingleton.get_client()
    if redis is None:
        logger.warning("JWT denylist: Redis unavailable — revocation of jti=%s not persisted", jti)
        return
    try:
        redis.setex(_key(jti), ttl, "1")
    except Exception as exc:
        logger.error("JWT denylist: failed to add jti=%s: %s", jti, exc)
        RedisClientSingleton.mark_failed()


def is_revoked(jti: str) -> bool:
    """Return True if the jti is in the denylist.

    Fails open (returns False) if Redis is unavailable.
    """
    redis = RedisClientSingleton.get_client()
    if redis is None:
        return False
    try:
        return redis.exists(_key(jti)) == 1
    except Exception as exc:
        logger.error("JWT denylist: failed to check jti=%s: %s", jti, exc)
        RedisClientSingleton.mark_failed()
        return False
