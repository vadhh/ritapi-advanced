"""
Hard Gate Middleware.

Runs immediately after RequestIDMiddleware (second outermost), before all
detection middlewares.  Returns 403 immediately — never calls call_next —
when any of the following hard-block conditions are met:

  1. Client IP is in the blocked-IP set (BLOCKED_IPS env var or BLOCKED_IPS_FILE)
  2. Client ASN is in the blocked-ASN set (BLOCKED_ASNS env var)
  3. A non-empty X-API-Key header contains an invalid or revoked key, but only
     when the resolved route policy explicitly requires API-key auth
  4. The request body matches a YARA rule (uses existing scanner if available)

Every hard block is audited via log_decision before the response is returned.
The X-Request-ID header is echoed in all 403 responses.

Fail-open guarantee
-------------------
If a component (YARA scanner, ASN lookup, Redis) is absent or raises, that
individual check is skipped and the request continues.  The middleware never
raises an unhandled exception.
"""
import logging
import os

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.security.security_event_logger import log_security_event
from app.utils.redis_client import RedisClientSingleton

logger = logging.getLogger(__name__)

# Per-IP requests-per-second threshold before DDoS spike block.
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
        ip = _get_client_ip(request)
        request_id = getattr(request.state, "request_id", "")

        # 0. DDoS spike check — runs before all other checks
        spike_response = self._check_spike(request, ip, request_id)
        if spike_response is not None:
            return spike_response

        # 1. Blocked IP
        if ip in _BLOCKED_IPS:
            return self._hard_block(request, ip, request_id, "blocked_ip", f"IP {ip} is blocked")

        # 2. Blocked ASN (skip gracefully if lookup unavailable)
        if _BLOCKED_ASNS:
            asn = self._lookup_asn(ip)
            if asn and asn in _BLOCKED_ASNS:
                return self._hard_block(
                    request, ip, request_id, "blocked_asn", f"ASN {asn} is blocked"
                )

        # 3. YARA match on request body (skip gracefully if scanner unavailable).
        # Always mark yara_scanned=True so InjectionDetectionMiddleware skips a second scan.
        yara_block = await self._check_yara(request, ip, request_id)
        request.state.yara_scanned = True
        if yara_block is not None:
            return yara_block

        # 4. Invalid API key when route policy requires API-key auth
        api_key_block = self._check_api_key(request, ip, request_id)
        if api_key_block is not None:
            return api_key_block

        return await call_next(request)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _hard_block(
        self,
        request: Request,
        ip: str,
        request_id: str,
        trigger_type: str,
        reason: str,
    ) -> JSONResponse:
        log_security_event(
            request,
            action="block",
            status_code=403,
            reason=reason,
            trigger_type=trigger_type,
            trigger_source="hard_gate",
        )
        logger.warning(
            "HardGate: blocking %s %s from %s — %s", request.method, request.url.path, ip, reason
        )
        return JSONResponse(
            {"error": "Forbidden", "detail": reason},
            status_code=403,
            headers={"X-Request-ID": request_id},
        )

    def _lookup_asn(self, ip: str) -> str | None:
        """Return ASN string for the IP, or None if lookup is unavailable or fails."""
        try:
            from app.utils.asn_lookup import lookup_asn  # type: ignore[import]
            return lookup_asn(ip)
        except Exception:
            return None

    async def _check_yara(self, request: Request, ip: str, request_id: str):
        """Return a block response on YARA match, or None to continue."""
        try:
            from app.utils.yara_scanner import get_yara_scanner
            scanner = get_yara_scanner()
            if not scanner.rules_loaded:
                return None
            body = await request.body()
            if not body:
                return None
            matches = scanner.scan_payload(body)
            if matches:
                reason = f"YARA rule match: {matches[0].rule}"
                return self._hard_block(request, ip, request_id, "yara", reason)
        except Exception:  # noqa: S110
            pass
        return None

    def _check_spike(self, request: Request, ip: str, request_id: str):
        """Return 429 if IP exceeds HARD_GATE_SPIKE_THRESHOLD req/s, else None.

        Uses a 1-second Redis sliding window via INCR + EXPIRE NX.
        Fail-open: if Redis is unavailable the check is skipped.
        """
        try:
            redis = RedisClientSingleton.get_client()
            if redis is None:
                return None

            raw_tid = getattr(request.state, "tenant_id", None)
            tenant_id = raw_tid if isinstance(raw_tid, str) and raw_tid else "default"

            key = f"ritapi:{tenant_id}:spike:{ip}"
            pipe = redis.pipeline()
            pipe.incr(key)
            pipe.expire(key, 1, nx=True)
            results = pipe.execute()
            count = results[0]

            if count > _SPIKE_THRESHOLD:
                log_security_event(
                    request,
                    action="block",
                    status_code=429,
                    reason=f"DDoS spike: {count} req/s exceeds threshold {_SPIKE_THRESHOLD}",
                    trigger_type="ddos_spike",
                    trigger_source="hard_gate",
                )
                logger.warning(
                    "HardGate: DDoS spike from %s — %d req/s > threshold %d",
                    ip, count, _SPIKE_THRESHOLD,
                )
                return JSONResponse(
                    {"error": "Too Many Requests", "detail": "ddos_spike"},
                    status_code=429,
                    headers={"X-Request-ID": request_id},
                )
        except Exception:  # noqa: S110
            pass
        return None

    def _check_api_key(self, request: Request, ip: str, request_id: str):
        """Return a block response if the API key is present but invalid.

        Only triggered when request.state.policy is already attached AND
        the policy requires API-key auth.  DecisionEngineMiddleware runs
        innermost (after HardGate), so policy is typically not yet resolved
        here — in that case the check is skipped (fail-open).
        """
        raw_key = request.headers.get("x-api-key") or request.headers.get("X-API-Key")
        if not raw_key:
            return None

        # Only proceed if policy is already in request state (set by a prior
        # middleware or test setup).  If not present, skip — fail open.
        policy = getattr(request.state, "policy", None)
        if policy is None:
            return None

        if not getattr(getattr(policy, "auth", None), "api_key", False):
            return None

        try:
            from app.utils.redis_client import RedisClientSingleton
            if RedisClientSingleton.get_client() is None:
                return None  # Redis unavailable — cannot validate, fail open

            from app.auth.api_key_handler import validate_api_key
            if validate_api_key(raw_key) is None:
                return self._hard_block(
                    request, ip, request_id, "invalid_api_key", "Invalid or revoked API key"
                )
        except Exception:  # noqa: S110
            pass
        return None
