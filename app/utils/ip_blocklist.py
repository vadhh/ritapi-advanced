"""Redis-backed per-IP permanent blocklist.

IPs are stored in a Redis set. Entries persist until explicitly removed via
unblock_ip(). Fail-open: is_blocked() returns False when Redis is unavailable.

Key: ritapi:ip:blocked  (Redis set)
"""
import logging

from app.utils.redis_client import RedisClientSingleton

logger = logging.getLogger(__name__)

_SET_KEY = "ritapi:ip:blocked"


def block_ip(ip: str) -> None:
    """Add `ip` to the permanent blocklist. No-ops if Redis is unavailable."""
    redis = RedisClientSingleton.get_client()
    if redis is None:
        logger.warning("IP blocklist: Redis unavailable — block of %s not persisted", ip)
        return
    try:
        redis.sadd(_SET_KEY, ip)
    except Exception as exc:
        logger.error("IP blocklist: failed to block %s: %s", ip, exc)
        RedisClientSingleton.mark_failed()


def unblock_ip(ip: str) -> bool:
    """Remove `ip` from the blocklist. Returns True if it was present."""
    redis = RedisClientSingleton.get_client()
    if redis is None:
        logger.warning("IP blocklist: Redis unavailable — unblock of %s not persisted", ip)
        return False
    try:
        return redis.srem(_SET_KEY, ip) == 1
    except Exception as exc:
        logger.error("IP blocklist: failed to unblock %s: %s", ip, exc)
        RedisClientSingleton.mark_failed()
        return False


def is_blocked(ip: str) -> bool:
    """Return True if `ip` is in the blocklist. Fails open when Redis unavailable."""
    redis = RedisClientSingleton.get_client()
    if redis is None:
        return False
    try:
        return bool(redis.sismember(_SET_KEY, ip))
    except Exception as exc:
        logger.error("IP blocklist: failed to check %s: %s", ip, exc)
        RedisClientSingleton.mark_failed()
        return False


def get_blocked_ips() -> list[str]:
    """Return all currently blocked IPs. Returns [] when Redis unavailable."""
    redis = RedisClientSingleton.get_client()
    if redis is None:
        return []
    try:
        return [ip.decode() if isinstance(ip, bytes) else ip for ip in redis.smembers(_SET_KEY)]
    except Exception as exc:
        logger.error("IP blocklist: failed to list blocked IPs: %s", exc)
        RedisClientSingleton.mark_failed()
        return []
