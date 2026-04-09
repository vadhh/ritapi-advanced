"""
Hard Gate Middleware.

Runs after TenantContext, before RateLimit and all detection middlewares.
Appends detections for known-bad conditions (blocked IPs/ASNs, DDoS spikes,
YARA body matches, invalid API keys) onto request.state.detections so that
DecisionEngineMiddleware (innermost) is the sole authority that issues 403/429
responses.

Fail-open guarantee
-------------------
If a component (YARA scanner, ASN lookup, Redis) is absent or raises, that
individual check is skipped and the request continues.  The middleware never
raises an unhandled exception.
"""
import logging
import os

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.middlewares.detection_schema import append_detection, ensure_detections_container
from app.utils.redis_client import RedisClientSingleton
from app.utils.tenant_key import tenant_scoped_key

logger = logging.getLogger(__name__)

# Per-IP requests-per-second threshold before DDoS spike detection.
_SPIKE_THRESHOLD: int = int(os.getenv("HARD_GATE_SPIKE_THRESHOLD", "100"))


def _load_set_from_env(env_var: str, file_var: str | None = None) -> frozenset[str]:
    """Build a frozenset from a comma-separated env var and an optional file."""
    values: set[str] = set()
    raw = os.getenv(env_var, "")
    if raw:
        values.update(v.strip() for v in raw.split(",") if v.strip())
    if file_var:
        filepath = os.getenv(file_var, "")
        if filepath:
            try:
                with open(filepath) as fh:
                    for line in fh:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            values.add(line)
            except Exception:
                logger.warning("HardGate: could not read %s=%s", file_var, filepath)
    return frozenset(values)


# Loaded once at import time; patch these module-level names in tests.
_BLOCKED_IPS: frozenset[str] = _load_set_from_env("BLOCKED_IPS", "BLOCKED_IPS_FILE")
_BLOCKED_ASNS: frozenset[str] = _load_set_from_env("BLOCKED_ASNS")


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    return forwarded or (request.client.host if request.client else "unknown")


class HardGateMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        ensure_detections_container(request)
        ip = _get_client_ip(request)

        # 0. DDoS spike check — runs before all other checks
        self._check_spike(request, ip)

        # 1. Blocked IP
        if ip in _BLOCKED_IPS:
            logger.warning(
                "HardGate: blocked IP %s on %s %s", ip, request.method, request.url.path
            )
            append_detection(
                request,
                detection_type="blocked_ip",
                score=1.0,
                reason=f"IP {ip} is blocked",
                status_code=403,
                source="hard_gate",
                metadata={"ip": ip},
            )

        # 2. Blocked ASN (skip gracefully if lookup unavailable)
        if _BLOCKED_ASNS:
            asn = self._lookup_asn(ip)
            if asn and asn in _BLOCKED_ASNS:
                logger.warning(
                    "HardGate: blocked ASN %s (%s) on %s %s",
                    asn, ip, request.method, request.url.path,
                )
                append_detection(
                    request,
                    detection_type="blocked_asn",
                    score=1.0,
                    reason=f"ASN {asn} is blocked",
                    status_code=403,
                    source="hard_gate",
                    metadata={"asn": asn, "ip": ip},
                )

        # 3. YARA match on request body (skip gracefully if scanner unavailable).
        # Always mark yara_scanned=True so InjectionDetectionMiddleware skips a second scan.
        await self._check_yara(request, ip)
        request.state.yara_scanned = True

        # 4. Invalid API key when route policy requires API-key auth
        self._check_api_key(request, ip)

        return await call_next(request)

    # ------------------------------------------------------------------
    # Internal helpers — append detections, never return responses
    # ------------------------------------------------------------------

    def _lookup_asn(self, ip: str) -> str | None:
        """Return ASN string for the IP, or None if lookup is unavailable or fails."""
        try:
            from app.utils.asn_lookup import lookup_asn  # type: ignore[import]
            return lookup_asn(ip)
        except Exception:
            return None

    async def _check_yara(self, request: Request, ip: str) -> None:
        """Append a detection if the request body matches a YARA rule."""
        try:
            from app.utils.yara_scanner import get_yara_scanner
            scanner = get_yara_scanner()
            if not scanner.rules_loaded:
                return
            body = await request.body()
            if not body:
                return
            matches = scanner.scan_payload(body)
            if matches:
                reason = f"YARA rule match: {matches[0].rule}"
                logger.warning("HardGate: YARA match from %s — %s", ip, reason)
                append_detection(
                    request,
                    detection_type="yara",
                    score=1.0,
                    reason=reason,
                    status_code=403,
                    source="hard_gate",
                    metadata={"rule": matches[0].rule, "ip": ip},
                )
        except Exception:  # noqa: S110
            pass

    def _check_spike(self, request: Request, ip: str) -> None:
        """Append a detection if IP exceeds HARD_GATE_SPIKE_THRESHOLD req/s.

        Uses a 1-second Redis sliding window via INCR + EXPIRE NX.
        Fail-open: if Redis is unavailable the check is skipped.
        """
        try:
            redis = RedisClientSingleton.get_client()
            if redis is None:
                return

            raw_tid = getattr(request.state, "claimed_tenant_id", None)
            tenant_id = raw_tid if isinstance(raw_tid, str) and raw_tid else "default"

            key = tenant_scoped_key(tenant_id, "spike", ip)
            pipe = redis.pipeline()
            pipe.incr(key)
            pipe.expire(key, 1, nx=True)
            results = pipe.execute()
            count = results[0]

            if count > _SPIKE_THRESHOLD:
                logger.warning(
                    "HardGate: DDoS spike from %s — %d req/s > threshold %d",
                    ip, count, _SPIKE_THRESHOLD,
                )
                append_detection(
                    request,
                    detection_type="ddos_spike",
                    score=1.0,
                    reason=f"DDoS spike: {count} req/s exceeds threshold {_SPIKE_THRESHOLD}",
                    status_code=429,
                    source="hard_gate",
                    metadata={"count": count, "threshold": _SPIKE_THRESHOLD, "ip": ip},
                )
        except Exception:  # noqa: S110
            pass

    def _check_api_key(self, request: Request, ip: str) -> None:
        """Append a detection if the API key is present but invalid.

        Only triggered when request.state.policy is already attached AND
        the policy requires API-key auth.  DecisionEngineMiddleware runs
        innermost (after HardGate), so policy is typically not yet resolved
        here — in that case the check is skipped (fail-open).
        """
        raw_key = request.headers.get("x-api-key") or request.headers.get("X-API-Key")
        if not raw_key:
            return

        # Only proceed if policy is already in request state (set by a prior
        # middleware or test setup).  If not present, skip — fail open.
        policy = getattr(request.state, "policy", None)
        if policy is None:
            return

        if not getattr(getattr(policy, "auth", None), "api_key", False):
            return

        try:
            from app.utils.redis_client import RedisClientSingleton
            if RedisClientSingleton.get_client() is None:
                return  # Redis unavailable — cannot validate, fail open

            from app.auth.api_key_handler import validate_api_key
            if validate_api_key(raw_key) is None:
                logger.warning("HardGate: API auth rejected — invalid identity from %s", ip)
                append_detection(
                    request,
                    detection_type="invalid_api_key",
                    score=1.0,
                    reason="Invalid or revoked API key",
                    status_code=403,
                    source="hard_gate",
                    metadata={"ip": ip},
                )
        except Exception:  # noqa: S110
            pass
