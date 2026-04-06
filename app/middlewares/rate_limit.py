"""
Rate Limit Middleware.

Per-IP and per-API-key Redis-backed rate limiting. When a per-route policy is
available (set by DecisionEngine on request.state.policy), the rate limit and
window are taken from the policy. Otherwise falls back to global env var defaults.

Policy-driven behavior:
  - policy.rate_limit.requests  → max requests per window for this route
  - policy.rate_limit.window_seconds → window duration in seconds
"""
import hashlib
import logging
import os

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.middlewares.detection_schema import append_detection, ensure_detections_container
from app.policies.service import DEFAULT_POLICY, get_policy
from app.utils.tenant_key import tenant_scoped_key
from app.utils.metrics import rate_limit_hits, requests_total, threat_score
from app.utils.redis_client import RedisClientSingleton

logger = logging.getLogger(__name__)

# Global defaults (used when no per-route policy is set)
RATE_LIMIT = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
RATE_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))

# Paths that bypass rate limiting entirely
_SKIP_PREFIXES = (
    "/healthz",
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

        # Keep a stable list for all detections observed during this request.
        ensure_detections_container(request)

        if any(path.startswith(p) for p in _SKIP_PREFIXES):
            return await call_next(request)

        # Resolve tenant ID for key namespacing
        raw_tid = getattr(request.state, "tenant_id", None)
        tenant_id = raw_tid if isinstance(raw_tid, str) and raw_tid else "default"

        # Read per-route policy if available (set by DecisionEngine on prior pass).
        # When not yet set, fall back to the tenant default policy (which itself
        # falls back to global env var defaults when no tenant file exists).
        policy = getattr(request.state, "policy", None)
        if policy is not None:
            rate_limit = policy.rate_limit.requests
            rate_window = policy.rate_limit.window_seconds
        else:
            # No route policy yet — try tenant default policy file.
            # Only override env var globals when a tenant-specific file actually
            # exists (i.e. get_policy returns something other than DEFAULT_POLICY).
            tenant_policy = get_policy(None, tenant_id=tenant_id)
            if tenant_policy is not DEFAULT_POLICY:
                rate_limit = tenant_policy.rate_limit.requests
                rate_window = tenant_policy.rate_limit.window_seconds
            else:
                rate_limit = RATE_LIMIT
                rate_window = RATE_WINDOW

        client_ip = _get_client_ip(request)
        api_key = request.headers.get("x-api-key", "")

        redis = RedisClientSingleton.get_client()
        if redis and client_ip:
            try:
                if redis.exists(tenant_scoped_key(tenant_id, "throttle", client_ip)):
                    rate_limit = max(1, rate_limit // 2)
            except Exception as e:
                logger.error("Throttle check Redis error: %s", e)

        if redis and (client_ip or api_key):
            path_key = path.split("?")[0].replace("/", "_")

            # Build one key per identity: IP and (if present) API key
            identities = []
            if client_ip:
                identities.append(("ip", tenant_scoped_key(tenant_id, "rate:ip", f"{client_ip}:{path_key}")))
            if api_key:
                api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()[:16]
                identities.append(("apikey", tenant_scoped_key(tenant_id, "rate:apikey", f"{api_key_hash}:{path_key}")))

            for id_type, rate_key in identities:
                log_key = rate_key.replace(":rate:", ":rate_log:")
                try:
                    pipe = redis.pipeline()
                    pipe.incr(rate_key)
                    pipe.expire(rate_key, rate_window, nx=True)
                    current, _ = pipe.execute()

                    if current > rate_limit:
                        # SET NX EX: atomic log-dedup — True only on first breach per window
                        was_first = redis.set(log_key, "1", ex=rate_window, nx=True)
                        if was_first:
                            identity_label = client_ip if id_type == "ip" else f"key:{api_key[:8]}…"
                            logger.warning(
                                "Rate limit exceeded for %s %s: %d/%d (window %ds)",
                                id_type, identity_label, current, rate_limit, rate_window,
                            )
                            rate_limit_hits.labels(identity_type=id_type).inc()
                            requests_total.labels(
                                method=request.method, action="block", detection_type="rate_limit"
                            ).inc()
                            threat_score.observe(0.9)

                        identity_label = client_ip if id_type == "ip" else f"key:{api_key[:8]}…"
                        append_detection(
                            request,
                            detection_type="rate_limit",
                            score=1.0,
                            reason=f"Rate limit exceeded for {id_type}:{identity_label}",
                            status_code=429,
                            source="rate_limit",
                            metadata={"identity_type": id_type, "path": path},
                        )
                        return await call_next(request)
                except Exception as e:
                    logger.error("Rate limiter Redis error: %s", e)
                    RedisClientSingleton.mark_failed()

        return await call_next(request)
