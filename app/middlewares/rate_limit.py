import logging
import os

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.utils.logging import log_request
from app.utils.metrics import rate_limit_hits, requests_total, threat_score
from app.utils.redis_client import RedisClientSingleton

logger = logging.getLogger(__name__)

RATE_LIMIT = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
RATE_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))

# Paths that bypass rate limiting entirely
_SKIP_PREFIXES = (
    "/healthz",
    "/readyz",
    "/metrics",
    "/docs",
    "/openapi",
)


def _get_client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else ""


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if any(path.startswith(p) for p in _SKIP_PREFIXES):
            return await call_next(request)

        client_ip = _get_client_ip(request)
        api_key = request.headers.get("x-api-key", "")

        redis = RedisClientSingleton.get_client()
        if redis and (client_ip or api_key):
            path_key = path.split("?")[0].replace("/", "_")

            # Build one key per identity: IP and (if present) API key
            identities = []
            if client_ip:
                identities.append(("ip", f"ritapi:rate:ip:{client_ip}:{path_key}"))
            if api_key:
                identities.append(("apikey", f"ritapi:rate:apikey:{api_key}:{path_key}"))

            for id_type, rate_key in identities:
                log_key = rate_key.replace(":rate:", ":rate_log:")
                try:
                    current = redis.incr(rate_key)
                    if current == 1:
                        redis.expire(rate_key, RATE_WINDOW)

                    if current > RATE_LIMIT:
                        if not redis.exists(log_key):
                            identity_label = client_ip if id_type == "ip" else f"key:{api_key[:8]}…"
                            logger.warning(
                                "Rate limit exceeded for %s %s: %d/%d (window %ds)",
                                id_type, identity_label, current, RATE_LIMIT, RATE_WINDOW,
                            )
                            redis.setex(log_key, RATE_WINDOW, "1")
                            log_request(
                                client_ip=client_ip,
                                path=path,
                                method=request.method,
                                action="block",
                                detection_type="rate_limit",
                                score=0.9,
                                reasons=f"RATE_LIMIT_EXCEEDED ({id_type}): {current}/{RATE_LIMIT} per {RATE_WINDOW}s",
                            )
                            rate_limit_hits.labels(identity_type=id_type).inc()
                            requests_total.labels(method=request.method, action="block", detection_type="rate_limit").inc()
                            threat_score.observe(0.9)

                        return JSONResponse(
                            {
                                "error": "Too Many Requests",
                                "detail": f"Rate limit exceeded ({RATE_LIMIT}/{RATE_WINDOW}s)",
                            },
                            status_code=429,
                        )
                except Exception as e:
                    logger.error("Rate limiter Redis error: %s", e)
                    RedisClientSingleton.mark_failed()

        return await call_next(request)
