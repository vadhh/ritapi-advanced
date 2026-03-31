"""
Data Exfiltration Detection Middleware.

No source existed anywhere in the codebase — written from scratch.

Detection heuristics (all Redis-backed, fail-open):

1. LARGE_RESPONSE   — single response body > LARGE_RESPONSE_BYTES (default 1 MB)
2. BULK_ACCESS      — same endpoint accessed > BULK_ACCESS_THRESHOLD times
                      by the same IP within BULK_ACCESS_WINDOW seconds
3. SEQUENTIAL_CRAWL — IP accesses > CRAWL_ENDPOINT_THRESHOLD distinct endpoints
                      within CRAWL_WINDOW seconds (separate from bot detection:
                      bot tracks request counts, this tracks response data volume)
4. HIGH_VOLUME      — cumulative response bytes from one IP exceed
                      VOLUME_THRESHOLD_BYTES within VOLUME_WINDOW seconds

Actions:
  - LARGE_RESPONSE and HIGH_VOLUME → "monitor" (log, pass through)
  - BULK_ACCESS and SEQUENTIAL_CRAWL → "block" (403) after threshold
"""
import logging

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.utils.logging import log_request
from app.utils.metrics import exfiltration_alerts, requests_total, response_size_bytes
from app.utils.redis_client import RedisClientSingleton

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

LARGE_RESPONSE_BYTES   = 1 * 1024 * 1024   # 1 MB — flag single large response
VOLUME_THRESHOLD_BYTES = 10 * 1024 * 1024  # 10 MB — cumulative per IP per window
VOLUME_WINDOW          = 300               # 5 minutes
BULK_ACCESS_THRESHOLD  = 50               # same endpoint hits per window
BULK_ACCESS_WINDOW     = 60               # 1 minute
CRAWL_ENDPOINT_THRESHOLD = 30             # distinct endpoints per window
CRAWL_WINDOW             = 300            # 5 minutes


# ---------------------------------------------------------------------------
# Redis helpers
# ---------------------------------------------------------------------------

def _incr(redis, key: str, ttl: int) -> int:
    val = redis.incr(key)
    if val == 1:
        redis.expire(key, ttl)
    return val


def _incrby(redis, key: str, amount: int, ttl: int) -> int:
    """Increment key by amount, setting TTL only if not already set (atomic via pipeline).

    Uses EXPIRE key ttl NX to set TTL atomically only on first write, eliminating
    the race condition from checking `if val == amount` with variable byte amounts.
    Requires Redis 7+ for NX support.
    """
    pipe = redis.pipeline()
    pipe.incrby(key, amount)
    pipe.expire(key, ttl, nx=True)  # NX: set only if no TTL exists — Redis 7+
    results = pipe.execute()
    return results[0]


def _sadd_count(redis, key: str, member: str, ttl: int) -> int:
    redis.sadd(key, member)
    redis.expire(key, ttl)
    return redis.scard(key)


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class ExfiltrationDetectionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        ip = (
            (request.headers.get("x-forwarded-for", "").split(",")[0].strip())
            or (request.client.host if request.client else "")
        )
        path = request.url.path
        method = request.method

        # --- Pre-request block for counter-based detections ---
        redis_pre = RedisClientSingleton.get_client()
        if redis_pre is not None:
            try:
                bulk_count = int(redis_pre.get(f"exfil:bulk:{ip}:{path}") or 0)
                ep_count = int(redis_pre.scard(f"exfil:crawl:{ip}") or 0)
                pre_reason = None
                if bulk_count > BULK_ACCESS_THRESHOLD:
                    pre_reason = "bulk_access"
                elif ep_count > CRAWL_ENDPOINT_THRESHOLD:
                    pre_reason = "sequential_crawl"

                if pre_reason is not None:
                    logger.warning(
                        "Exfiltration pre-block [%s] from %s on %s",
                        pre_reason, ip, path,
                    )
                    if not hasattr(request.state, "detections"):
                        request.state.detections = []
                    request.state.detections.append({
                        "type": "exfiltration_block",
                        "score": 0.9,
                        "reason": f"{pre_reason} (pre-request counter exceeded)",
                        "status_code": 403,
                    })
                    return await call_next(request)
            except Exception:
                pass  # fail-open

        # Let the request go through and capture the response
        response = await call_next(request)

        # ---- Determine response body size --------------------------------
        # Prefer Content-Length header (O(1)); fall back to consuming stream.
        body_size = 0
        content_length_header = response.headers.get("content-length")

        if content_length_header:
            try:
                body_size = int(content_length_header)
            except ValueError:
                pass

        # If no Content-Length, consume the body to measure it, then rebuild
        if body_size == 0:
            body_chunks: list[bytes] = []
            async for chunk in response.body_iterator:
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8")
                body_chunks.append(chunk)
            body_bytes = b"".join(body_chunks)
            body_size = len(body_bytes)

            # Rebuild response so the client still receives the body
            from starlette.responses import Response as StarletteResponse
            response = StarletteResponse(
                content=body_bytes,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.media_type,
            )

        # Record size in Prometheus histogram
        response_size_bytes.observe(body_size)

        # ---- Run detections (only if Redis available) --------------------
        redis = RedisClientSingleton.get_client()
        if redis is None:
            return response

        alerts: list[tuple[str, str]] = []  # (reason, action)

        try:
            # 1. Large single response
            if body_size > LARGE_RESPONSE_BYTES:
                alerts.append(("large_response", "monitor"))

            # 2. High cumulative volume from this IP
            total_bytes = _incrby(redis, f"exfil:bytes:{ip}", body_size, VOLUME_WINDOW)
            if total_bytes > VOLUME_THRESHOLD_BYTES:
                alerts.append(("high_volume", "monitor"))

            # 3. Bulk access to same endpoint
            bulk_count = _incr(redis, f"exfil:bulk:{ip}:{path}", BULK_ACCESS_WINDOW)
            if bulk_count > BULK_ACCESS_THRESHOLD:
                alerts.append(("bulk_access", "block"))

            # 4. Sequential endpoint crawling
            ep_count = _sadd_count(redis, f"exfil:crawl:{ip}", path, CRAWL_WINDOW)
            if ep_count > CRAWL_ENDPOINT_THRESHOLD:
                alerts.append(("sequential_crawl", "block"))

        except Exception as e:
            logger.error("Exfiltration detection Redis error: %s", e)
            RedisClientSingleton.mark_failed()
            return response

        if not alerts:
            return response

        # Highest severity wins: block > monitor
        action = "block" if any(a == "block" for _, a in alerts) else "monitor"
        reasons = ", ".join(r for r, _ in alerts)
        top_reason = next(r for r, a in alerts if a == action)
        score = 0.9 if action == "block" else 0.5

        logger.warning(
            "Exfiltration alert [%s] from %s on %s — body_size=%d bytes",
            reasons, ip, path, body_size,
        )

        log_request(
            client_ip=ip,
            path=path,
            method=method,
            action=action,
            detection_type=f"exfil:{top_reason}",
            score=score,
            reasons=f"{reasons} (response_size={body_size})",
        )

        for reason, _ in alerts:
            exfiltration_alerts.labels(reason=reason).inc()
        requests_total.labels(
            method=method, action=action, detection_type=f"exfil:{top_reason}"
        ).inc()

        if action == "block":
            return JSONResponse(
                {"error": "Forbidden", "detail": "Suspicious data access pattern detected"},
                status_code=403,
            )

        return response
