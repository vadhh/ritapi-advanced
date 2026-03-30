"""
Redis client singleton with:
  - Reconnect cooldown: won't hammer Redis on every request after a failure
  - Per-operation retry with exponential backoff (via redis-py Retry)
  - Redis Sentinel support for HA deployments
  - mark_failed(): lets middlewares signal that a live client just errored,
    so the next request attempts reconnection without a thundering herd

Env vars
--------
Standalone (default):
  REDIS_URL               redis://localhost:6379/1

Sentinel (HA):
  REDIS_SENTINEL_HOSTS    host1:26379,host2:26379,host3:26379
  REDIS_SENTINEL_SERVICE  master service name (default: "mymaster")
  REDIS_SENTINEL_PASSWORD password for sentinel auth (optional)
  REDIS_SENTINEL_DB       DB number (default: 1)

Tuning:
  REDIS_CONNECT_TIMEOUT   socket connect timeout in seconds (default: 2)
  REDIS_SOCKET_TIMEOUT    socket read/write timeout in seconds (default: 2)
  REDIS_RECONNECT_COOLDOWN seconds to wait between reconnect attempts (default: 5)
"""
import logging
import os
import time

import redis
from app.utils.metrics import redis_connected
from redis.backoff import ExponentialBackoff
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError
from redis.retry import Retry

logger = logging.getLogger(__name__)

_CONNECT_TIMEOUT  = float(os.getenv("REDIS_CONNECT_TIMEOUT", "2"))
_SOCKET_TIMEOUT   = float(os.getenv("REDIS_SOCKET_TIMEOUT",  "2"))
_COOLDOWN_SECONDS = float(os.getenv("REDIS_RECONNECT_COOLDOWN", "5"))

# Per-operation retry: 3 attempts, exponential backoff capped at 1s
_RETRY = Retry(ExponentialBackoff(cap=1.0, base=0.1), retries=3)
_RETRY_ERRORS = [RedisConnectionError, RedisTimeoutError]


def _build_standalone_client() -> redis.Redis:
    url = os.getenv("REDIS_URL", "redis://localhost:6379/1")
    client = redis.from_url(
        url,
        decode_responses=False,
        retry=_RETRY,
        retry_on_error=_RETRY_ERRORS,
        socket_connect_timeout=_CONNECT_TIMEOUT,
        socket_timeout=_SOCKET_TIMEOUT,
    )
    # Mask password in log
    safe_url = url.split("@")[-1] if "@" in url else url
    logger.info("Redis (standalone) connected: %s", safe_url)
    return client


def _build_sentinel_client() -> redis.Redis:
    hosts_raw = os.getenv("REDIS_SENTINEL_HOSTS", "")
    service   = os.getenv("REDIS_SENTINEL_SERVICE", "mymaster")
    password  = os.getenv("REDIS_SENTINEL_PASSWORD") or None
    db        = int(os.getenv("REDIS_SENTINEL_DB", "1"))

    hosts = []
    for entry in hosts_raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if ":" in entry:
            host, port_str = entry.rsplit(":", 1)
            hosts.append((host.strip(), int(port_str)))
        else:
            hosts.append((entry, 26379))

    from redis.sentinel import Sentinel
    sentinel = Sentinel(
        hosts,
        socket_timeout=_SOCKET_TIMEOUT,
        password=password,
    )
    client = sentinel.master_for(
        service,
        db=db,
        decode_responses=False,
        retry=_RETRY,
        retry_on_error=_RETRY_ERRORS,
        socket_connect_timeout=_CONNECT_TIMEOUT,
        socket_timeout=_SOCKET_TIMEOUT,
    )
    logger.info(
        "Redis (sentinel) connected: service=%s hosts=%s",
        service, hosts,
    )
    return client


class RedisClientSingleton:
    _instance: redis.Redis | None = None
    _last_failure: float = 0.0          # monotonic timestamp of last failed connect attempt
    _failure_logged: bool = False        # suppress repeated log noise during cooldown

    @classmethod
    def get_client(cls) -> redis.Redis | None:
        """
        Return the active Redis client, or None if unavailable.

        - If connected: returns the existing client immediately (no ping overhead).
        - If disconnected and within cooldown: returns None without attempting reconnect.
        - If disconnected and cooldown has elapsed: attempts reconnect.

        Call mark_failed() from a middleware's except block to signal that an
        apparently-live client just produced a connection error.
        """
        if cls._instance is not None:
            redis_connected.set(1)
            return cls._instance

        now = time.monotonic()
        if (now - cls._last_failure) < _COOLDOWN_SECONDS:
            redis_connected.set(0)
            return None  # still cooling down — don't hammer Redis

        # Attempt (re)connection
        try:
            use_sentinel = bool(os.getenv("REDIS_SENTINEL_HOSTS", "").strip())
            client = _build_sentinel_client() if use_sentinel else _build_standalone_client()
            client.ping()
            cls._instance = client
            cls._last_failure = 0.0
            cls._failure_logged = False
            redis_connected.set(1)
            logger.info("Redis connected successfully.")
        except Exception as exc:
            cls._instance = None
            cls._last_failure = time.monotonic()
            redis_connected.set(0)
            if not cls._failure_logged:
                logger.warning(
                    "Redis unavailable (retrying in %.0fs): %s. "
                    "Features requiring Redis will fail-open.",
                    _COOLDOWN_SECONDS, exc,
                )
                cls._failure_logged = True

        return cls._instance

    @classmethod
    def mark_failed(cls) -> None:
        """
        Signal that a live Redis client just raised a connection/timeout error.

        Resets the singleton so the next get_client() call attempts reconnection
        after the cooldown, without a thundering herd.

        Call this from middleware except blocks when a Redis operation fails:

            try:
                redis.incr(key)
            except (ConnectionError, TimeoutError) as e:
                logger.error("Redis op failed: %s", e)
                RedisClientSingleton.mark_failed()
        """
        cls._instance = None
        cls._last_failure = time.monotonic()
        cls._failure_logged = False
        redis_connected.set(0)
        logger.warning("Redis client marked as failed — will reconnect after cooldown.")

    @classmethod
    def reset(cls) -> None:
        """Force reconnection on next get_client() call (bypasses cooldown). Used in tests."""
        cls._instance = None
        cls._last_failure = 0.0
        cls._failure_logged = False
