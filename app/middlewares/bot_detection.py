"""
Bot Detection Middleware.

Ported from _archive/ritapi_v/ritapi/utils/behaviour_detection.py.
Changes from source:
  - Django `cache.get/set/delete` replaced with direct Redis calls
  - Wrapped in Starlette BaseHTTPMiddleware
  - Runs AFTER call_next() so response status code is available for error-rate rules
  - Gracefully degrades (fail-open) when Redis is unavailable
"""
import logging
import os

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.middlewares.detection_schema import append_detection
from app.utils.metrics import bot_blocks, bot_signals, requests_total, threat_score
from app.utils.redis_client import RedisClientSingleton
from app.utils.tenant_key import tenant_scoped_key

logger = logging.getLogger(__name__)

# IPs exempt from bot detection (monitoring systems, internal probes).
# Comma-separated; set via BOT_DETECTION_BYPASS_IPS env var.
_BYPASS_IPS: frozenset[str] = frozenset(
    ip.strip()
    for ip in os.getenv("BOT_DETECTION_BYPASS_IPS", "127.0.0.1,::1").split(",")
    if ip.strip()
)

# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

RULES: dict = {
    "LARGE_PAYLOAD":              {"threshold": 10_000,  "score": 70},
    "RAPID_FIRE":                 {"threshold": 50,      "window": 10,  "score": 85},
    "BURST_TRAFFIC":              {"threshold": 100,     "window": 60,  "score": 70},
    "ENDPOINT_SCANNING":          {"threshold": 15,      "window": 300, "score": 75},
    "SUSPICIOUS_USER_AGENT":      {"score": 60},
    "NO_USER_AGENT":              {"score": 50},
    "HIGH_ERROR_RATE":            {"threshold": 0.5, "window": 60, "min_requests": 10, "score": 75},
    "CONSECUTIVE_ERRORS":         {"count": 5,                          "score": 65},
    "REPEATED_404":               {"threshold": 10,      "window": 60,  "score": 60},
    "REPEATED_401":               {"threshold": 5,       "window": 300, "score": 80},
    "REPEATED_403":               {"threshold": 3,       "window": 300, "score": 70},
    "EXCESSIVE_POST":             {"threshold": 30,      "window": 60,  "score": 65},
    "SUSPICIOUS_METHOD":          {"score": 70},
}

_SUSPICIOUS_UA_TOKENS = frozenset([
    "bot", "crawler", "spider", "scraper", "scanner",
    "curl", "wget", "python-requests", "go-http-client",
    "masscan", "nmap", "nikto", "sqlmap", "havij",
    "acunetix", "burp", "nessus", "metasploit",
    "benchmark", "stress", "load",
])

# Risk score threshold above which the request is blocked
BLOCK_THRESHOLD = 70


# ---------------------------------------------------------------------------
# Redis helpers
# ---------------------------------------------------------------------------

def _incr(redis, key: str, ttl: int) -> int:
    """Increment a counter, setting TTL atomically on first write (EXPIRE NX)."""
    pipe = redis.pipeline()
    pipe.incr(key)
    pipe.expire(key, ttl, nx=True)
    results = pipe.execute()
    return results[0]


def _get_int(redis, key: str) -> int:
    raw = redis.get(key)
    return int(raw) if raw else 0


def _sadd_count(redis, key: str, member: str, ttl: int) -> int:
    """Add member to a Redis set, refresh TTL, return cardinality (single pipeline)."""
    pipe = redis.pipeline()
    pipe.sadd(key, member)
    pipe.expire(key, ttl)
    pipe.scard(key)
    _, _, count = pipe.execute()
    return count


# ---------------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------------

def _is_suspicious_ua(ua: str) -> bool:
    lower = ua.lower()
    return any(token in lower for token in _SUSPICIOUS_UA_TOKENS)


def _detect(redis, ip: str, method: str, path: str, ua: str,
            payload_size: int, status_code: int,
            tenant_id: str = "default") -> list[tuple[str, int]]:
    """Return a list of (anomaly_name, score) tuples for the given request.

    tenant_id is used to namespace Redis keys so different tenants do not share
    bot counters.  Defaults to "default" for backward compatibility with tests
    that call this function directly without a tenant context.
    """
    hits: list[tuple[str, int]] = []

    # --- Static signal checks ---
    if payload_size > RULES["LARGE_PAYLOAD"]["threshold"]:
        hits.append(("LARGE_PAYLOAD", RULES["LARGE_PAYLOAD"]["score"]))

    if not ua or ua.strip() == "":
        hits.append(("NO_USER_AGENT", RULES["NO_USER_AGENT"]["score"]))
    elif _is_suspicious_ua(ua):
        hits.append(("SUSPICIOUS_USER_AGENT", RULES["SUSPICIOUS_USER_AGENT"]["score"]))

    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        hits.append(("SUSPICIOUS_METHOD", RULES["SUSPICIOUS_METHOD"]["score"]))

    pfx = tenant_scoped_key(tenant_id, "bot")

    try:
        # --- Rate-based checks ---
        rapid_count = _incr(redis, f"{pfx}:rapid:{ip}", RULES["RAPID_FIRE"]["window"])
        if rapid_count > RULES["RAPID_FIRE"]["threshold"]:
            hits.append(("RAPID_FIRE", RULES["RAPID_FIRE"]["score"]))

        burst_count = _incr(redis, f"{pfx}:burst:{ip}", RULES["BURST_TRAFFIC"]["window"])
        if burst_count > RULES["BURST_TRAFFIC"]["threshold"]:
            hits.append(("BURST_TRAFFIC", RULES["BURST_TRAFFIC"]["score"]))

        ep_count = _sadd_count(
            redis, f"{pfx}:endpoints:{ip}", path, RULES["ENDPOINT_SCANNING"]["window"]
        )
        if ep_count > RULES["ENDPOINT_SCANNING"]["threshold"]:
            hits.append(("ENDPOINT_SCANNING", RULES["ENDPOINT_SCANNING"]["score"]))

        if method == "POST":
            post_count = _incr(redis, f"{pfx}:post:{ip}", RULES["EXCESSIVE_POST"]["window"])
            if post_count > RULES["EXCESSIVE_POST"]["threshold"]:
                hits.append(("EXCESSIVE_POST", RULES["EXCESSIVE_POST"]["score"]))

        # --- Status-code based checks ---
        total_count = _incr(redis, f"{pfx}:total:{ip}", RULES["HIGH_ERROR_RATE"]["window"])

        if status_code >= 400:
            err_count = _incr(redis, f"{pfx}:errors:{ip}", RULES["HIGH_ERROR_RATE"]["window"])
            consec = _incr(redis, f"{pfx}:consec:{ip}", 60)

            if consec >= RULES["CONSECUTIVE_ERRORS"]["count"]:
                hits.append(("CONSECUTIVE_ERRORS", RULES["CONSECUTIVE_ERRORS"]["score"]))

            if total_count >= RULES["HIGH_ERROR_RATE"]["min_requests"]:
                rate = err_count / total_count
                if rate > RULES["HIGH_ERROR_RATE"]["threshold"]:
                    hits.append(("HIGH_ERROR_RATE", RULES["HIGH_ERROR_RATE"]["score"]))

            if status_code == 404:
                n = _incr(redis, f"{pfx}:404:{ip}", RULES["REPEATED_404"]["window"])
                if n > RULES["REPEATED_404"]["threshold"]:
                    hits.append(("REPEATED_404", RULES["REPEATED_404"]["score"]))

            if status_code == 401:
                n = _incr(redis, f"{pfx}:401:{ip}", RULES["REPEATED_401"]["window"])
                if n > RULES["REPEATED_401"]["threshold"]:
                    hits.append(("REPEATED_401", RULES["REPEATED_401"]["score"]))

            if status_code == 403:
                n = _incr(redis, f"{pfx}:403:{ip}", RULES["REPEATED_403"]["window"])
                if n > RULES["REPEATED_403"]["threshold"]:
                    hits.append(("REPEATED_403", RULES["REPEATED_403"]["score"]))
        else:
            # Reset consecutive-error streak on success
            redis.delete(f"{pfx}:consec:{ip}")

    except Exception as e:
        logger.error("Bot detection Redis error: %s", e)
        RedisClientSingleton.mark_failed()

    return hits


def _accumulate_risk(redis, ip: str, score: int, tenant_id: str = "default") -> int:
    """Add score to per-IP risk accumulator (1-hour decay). Returns new total."""
    key = tenant_scoped_key(tenant_id, "bot:risk", ip)
    new_score = min(100, _get_int(redis, key) + score)
    redis.set(key, new_score)
    redis.expire(key, 3600)
    return new_score


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class BotDetectionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        ip = (
            (request.headers.get("x-forwarded-for", "").split(",")[0].strip())
            or (request.client.host if request.client else "")
        )

        if ip in _BYPASS_IPS:
            return await call_next(request)

        redis = RedisClientSingleton.get_client()
        if redis is None:
            return await call_next(request)

        raw_tid = getattr(request.state, "tenant_id", None)
        tenant_id = raw_tid if isinstance(raw_tid, str) and raw_tid else "default"

        ua = request.headers.get("user-agent", "")
        method = request.method
        path = request.url.path

        # Read Content-Length for payload size (body not consumed here)
        try:
            payload_size = int(request.headers.get("content-length", "0"))
        except ValueError:
            payload_size = 0

        # --- Pre-request block: if prior cumulative risk >= threshold, block immediately ---
        redis_pre = RedisClientSingleton.get_client()
        if redis_pre is not None:
            try:
                existing_risk = int(
                    redis_pre.get(tenant_scoped_key(tenant_id, "bot:risk", ip)) or 0
                )
                if existing_risk >= BLOCK_THRESHOLD:
                    logger.warning(
                        "Bot pre-block %s on %s — cumulative risk %d >= %d",
                        ip, path, existing_risk, BLOCK_THRESHOLD,
                    )
                    append_detection(
                        request,
                        detection_type="bot_block",
                        score=round(existing_risk / 100, 4),
                        reason=f"Cumulative bot risk {existing_risk} >= {BLOCK_THRESHOLD}",
                        status_code=403,
                        source="bot_detection",
                        metadata={"cumulative_risk": existing_risk, "threshold": BLOCK_THRESHOLD},
                    )
                    return await call_next(request)
            except Exception as e:
                logger.debug("Bot pre-request Redis check failed (fail-open): %s", e)

        # Let the request proceed to get the response status code
        response = await call_next(request)
        status_code = response.status_code

        hits = _detect(redis, ip, method, path, ua, payload_size, status_code,
                       tenant_id=tenant_id)

        if not hits:
            return response

        hits.sort(key=lambda x: x[1], reverse=True)
        top_name, top_score = hits[0]
        cumulative = _accumulate_risk(redis, ip, top_score, tenant_id=tenant_id)
        all_names = ", ".join(h[0] for h in hits)

        logger.warning(
            "Bot signal [%s] from %s on %s — top: %s (%d pts), cumulative risk: %d",
            all_names, ip, path, top_name, top_score, cumulative,
        )

        action = "block" if cumulative >= BLOCK_THRESHOLD else "monitor"
        score = round(cumulative / 100, 4)

        append_detection(
            request,
            detection_type="bot_detection",
            score=score,
            reason=f"Bot signals: {all_names}",
            status_code=403 if action == "block" else 200,
            source="bot_detection",
            metadata={
                "top_rule": top_name,
                "top_score": top_score,
                "all_rules": [name for name, _ in hits],
                "cumulative_risk": cumulative,
                "action": action,
            },
        )

        for name, _ in hits:
            bot_signals.labels(rule=name).inc()
        requests_total.labels(
            method=method, action=action, detection_type=f"bot:{top_name.lower()}"
        ).inc()
        threat_score.observe(score)
        if cumulative >= BLOCK_THRESHOLD:
            bot_blocks.inc()

        return response
