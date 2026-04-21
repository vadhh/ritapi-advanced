"""
Redis pub/sub broadcaster for cross-worker config reload (L-1 fix).

broadcast_reload() — called by POST /admin/reload to notify other workers.
reload_listener_task() — async task started in lifespan on each worker.

Channel: ritapi:config:reload
Message: JSON {"pid": <int>}  — sender's PID for self-message guard.
"""
import asyncio
import json
import logging
import os

import redis.asyncio as aioredis

from app.utils.redis_client import RedisClientSingleton

logger = logging.getLogger(__name__)

RELOAD_CHANNEL = "ritapi:config:reload"


def broadcast_reload() -> int:
    """Publish a reload signal to all other workers.

    Returns the number of subscribers that received the message (0 on failure).
    """
    r = RedisClientSingleton.get_client()
    if r is None:
        logger.warning("broadcast_reload: Redis unavailable — other workers won't reload")
        return 0
    try:
        payload = json.dumps({"pid": os.getpid()})
        count = r.publish(RELOAD_CHANNEL, payload)
        logger.info("broadcast_reload: notified %d subscriber(s)", count)
        return count
    except Exception as exc:
        logger.warning("broadcast_reload failed: %s", exc)
        return 0


async def reload_listener_task() -> None:
    """Async background task: subscribe to RELOAD_CHANNEL and reload config on signal.

    Runs for the lifetime of the worker. Reconnects automatically on Redis errors.
    Skips messages published by this same process (self-message guard via PID).
    """
    from app.policies.service import reload_policies
    from app.routing.service import reload_routes

    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/1")
    my_pid = os.getpid()

    while True:
        try:
            async with aioredis.from_url(redis_url, decode_responses=True) as r:
                async with r.pubsub() as ps:
                    await ps.subscribe(RELOAD_CHANNEL)
                    logger.info(
                        "reload_listener: subscribed to %s (pid=%d)", RELOAD_CHANNEL, my_pid
                    )
                    async for message in ps.listen():
                        if message["type"] != "message":
                            continue
                        try:
                            data = json.loads(message["data"])
                            sender_pid = data.get("pid")
                        except Exception:
                            sender_pid = None

                        if sender_pid == my_pid:
                            logger.debug("reload_listener: ignoring self-published message")
                            continue

                        logger.info(
                            "reload_listener: reload signal from pid=%s, reloading config",
                            sender_pid,
                        )
                        reload_routes()
                        reload_policies()

        except asyncio.CancelledError:
            logger.info("reload_listener: shutting down")
            return
        except Exception as exc:
            logger.warning("reload_listener: error (%s), reconnecting in 5s", exc)
            await asyncio.sleep(5)
