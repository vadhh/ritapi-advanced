"""
Rate Limit Middleware.

Per-IP and per-API-key Redis-backed rate limiting. When a per-route policy is
available (set by DecisionEngine on request.state.policy), the rate limit and
window are taken from the policy. Otherwise falls back to global env var defaults.

Policy-driven behavior:
  - policy.rate_limit.requests  → max requests per window for this route
  - policy.rate_limit.window_seconds → window duration in seconds
"""
import logging
import os

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.utils.logging import log_request
from app.utils.metrics import rate_limit_hits, requests_total, threat_score
from app.utils.redis_client import RedisClientSingleton

logger = logging.getLogger(__name__)

# Global defaults (used when no per-route policy is set)
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

        # Read per-route policy if available
        policy = getattr(request.state, "policy", None)
        if policy is not None:
            rate_limit = policy.rate_limit.requests
            rate_window = policy.rate_limit.window_seconds
        else:
            rate_limit = RATE_LIMIT
            rate_window = RATE_WINDOW

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
                        redis.expire(rate_key, rate_window)

                    if current > rate_limit:
                        if not redis.exists(log_key):
                            identity_label = client_ip if id_type == "ip" else f"key:{api_key[:8]}…"
                            logger.warning(
                                "Rate limit exceeded for %s %s: %d/%d (window %ds)",
                                id_type, identity_label, current, rate_limit, rate_window,
                            )
                            redis.setex(log_key, rate_window, "1")
                            log_request(
                                client_ip=client_ip,
                                path=path,
                                method=request.method,
                                action="block",
                                detection_type="rate_limit",
                                score=0.9,
                                reasons=(
                                    f"RATE_LIMIT_EXCEEDED ({id_type}): "
                                    f"{current}/{rate_limit} per {rate_window}s"
                                ),
                            )
                            rate_limit_hits.labels(identity_type=id_type).inc()
                            requests_total.labels(
                                method=request.method, action="block", detection_type="rate_limit"
                            ).inc()
                            threat_score.observe(0.9)

                        return JSONResponse(
                            {
                                "error": "Too Many Requests",
                                "detail": f"Rate limit exceeded ({rate_limit}/{rate_window}s)",
                            },
                            status_code=429,
                        )
                except Exception as e:
                    logger.error("Rate limiter Redis error: %s", e)
                    RedisClientSingleton.mark_failed()

        return await call_next(request)
