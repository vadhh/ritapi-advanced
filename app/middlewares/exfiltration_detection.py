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
import time as _time

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.middlewares.detection_schema import append_detection
from app.utils.metrics import exfiltration_alerts, requests_total, response_size_bytes
from app.utils.perf import add_redis_ms, get_perf
from app.utils.redis_client import RedisClientSingleton
from app.utils.tenant_key import tenant_scoped_key

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

    Prefers EXPIRE NX (Redis 7+) for true atomicity. Falls back to a TTL check
    for Redis < 7: sets TTL only when the key has no existing expiry (TTL == -1).
    """
    pipe = redis.pipeline()
    pipe.incrby(key, amount)
    try:
        pipe.expire(key, ttl, nx=True)  # NX: set only if no TTL exists — Redis 7+
        results = pipe.execute()
    except Exception:
        # Redis < 7 doesn't support EXPIRE NX — fall back to conditional set
        results = pipe.execute()
        if redis.ttl(key) == -1:  # key exists but has no TTL
            redis.expire(key, ttl)
    return results[0]


def _sadd_count(redis, key: str, member: str, ttl: int) -> int:
    """Add member to a Redis set, refresh TTL, return cardinality (single pipeline)."""
    pipe = redis.pipeline()
    pipe.sadd(key, member)
    pipe.expire(key, ttl)
    pipe.scard(key)
    _, _, count = pipe.execute()
    return count


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

        raw_tid = getattr(request.state, "tenant_id", None)
        tenant_id = raw_tid if isinstance(raw_tid, str) and raw_tid else "default"
        pfx = tenant_scoped_key(tenant_id, "exfil")

        # --- Pre-request block for counter-based detections ---
        _t_exfil_pre = _time.monotonic()
        redis_pre = RedisClientSingleton.get_client()
        if redis_pre is not None:
            try:
                # Combine both pre-check reads into a single pipeline round-trip.
                pipe_pre = redis_pre.pipeline()
                pipe_pre.get(f"{pfx}:bulk:{ip}:{path}")
                pipe_pre.scard(f"{pfx}:crawl:{ip}")
                _t_r = _time.monotonic()
                bulk_raw, ep_raw = pipe_pre.execute()
                add_redis_ms(request, (_time.monotonic() - _t_r) * 1000)
                bulk_count = int(bulk_raw or 0)
                ep_count = int(ep_raw or 0)
                pre_reason = None
                if bulk_count > BULK_ACCESS_THRESHOLD:
                    pre_reason = "bulk_access"
                elif ep_count > CRAWL_ENDPOINT_THRESHOLD:
                    pre_reason = "sequential_crawl"

                if pre_reason is not None:
                    get_perf(request)["exfil_ms"] = round((_time.monotonic() - _t_exfil_pre) * 1000, 3)
                    logger.warning(
                        "Exfiltration pre-block [%s] from %s on %s",
                        pre_reason, ip, path,
                    )
                    append_detection(
                        request,
                        detection_type="exfiltration_block",
                        score=0.9,
                        reason=f"{pre_reason} (pre-request counter exceeded)",
                        status_code=403,
                        source="exfiltration_detection",
                        metadata={"reason": pre_reason, "phase": "pre_request"},
                    )
                    return await call_next(request)
            except Exception as e:
                logger.debug("Exfil pre-request Redis check failed (fail-open): %s", e)
        _t_exfil_pre_elapsed = (_time.monotonic() - _t_exfil_pre) * 1000

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
        _t_exfil_post = _time.monotonic()
        redis = RedisClientSingleton.get_client()
        if redis is None:
            get_perf(request)["exfil_ms"] = round(_t_exfil_pre_elapsed, 3)
            return response

        alerts: list[tuple[str, str]] = []  # (reason, action)

        try:
            # 1. Large single response
            if body_size > LARGE_RESPONSE_BYTES:
                alerts.append(("large_response", "monitor"))

            _t_r = _time.monotonic()
            # 2. High cumulative volume from this IP
            total_bytes = _incrby(redis, f"{pfx}:bytes:{ip}", body_size, VOLUME_WINDOW)
            if total_bytes > VOLUME_THRESHOLD_BYTES:
                alerts.append(("high_volume", "monitor"))

            # 3. Bulk access to same endpoint
            bulk_count = _incr(redis, f"{pfx}:bulk:{ip}:{path}", BULK_ACCESS_WINDOW)
            if bulk_count > BULK_ACCESS_THRESHOLD:
                alerts.append(("bulk_access", "block"))

            # 4. Sequential endpoint crawling
            ep_count = _sadd_count(redis, f"{pfx}:crawl:{ip}", path, CRAWL_WINDOW)
            if ep_count > CRAWL_ENDPOINT_THRESHOLD:
                alerts.append(("sequential_crawl", "block"))
            add_redis_ms(request, (_time.monotonic() - _t_r) * 1000)

        except Exception as e:
            logger.error("Exfiltration detection Redis error: %s", e)
            RedisClientSingleton.mark_failed()
            get_perf(request)["exfil_ms"] = round(
                _t_exfil_pre_elapsed + (_time.monotonic() - _t_exfil_post) * 1000, 3
            )
            return response

        if not alerts:
            get_perf(request)["exfil_ms"] = round(
                _t_exfil_pre_elapsed + (_time.monotonic() - _t_exfil_post) * 1000, 3
            )
            return response

        # Highest severity wins: block > monitor
        action = "block" if any(a == "block" for _, a in alerts) else "monitor"
        reasons = ", ".join(r for r, _ in alerts)
        top_reason = next(r for r, a in alerts if a == action)
        score = 0.9 if action == "block" else 0.5

        append_detection(
            request,
            detection_type="exfiltration_block" if action == "block" else "exfiltration",
            score=score,
            reason=f"{reasons} (response_size={body_size})",
            status_code=403 if action == "block" else 200,
            source="exfiltration_detection",
            metadata={
                "alerts": [r for r, _ in alerts],
                "top_reason": top_reason,
                "response_size": body_size,
                "action": action,
            },
        )

        logger.warning(
            "Exfiltration alert [%s] from %s on %s — body_size=%d bytes",
            reasons, ip, path, body_size,
        )

        get_perf(request)["exfil_ms"] = round(
            _t_exfil_pre_elapsed + (_time.monotonic() - _t_exfil_post) * 1000, 3
        )

        for reason, _ in alerts:
            exfiltration_alerts.labels(reason=reason).inc()
        requests_total.labels(
            method=method, action=action, detection_type=f"exfil:{top_reason}"
        ).inc()

        return response
