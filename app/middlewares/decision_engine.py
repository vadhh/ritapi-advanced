"""
Unified Decision Engine Middleware.

Runs innermost (closest to route handlers). Resolves each request to a route
via routing/service.py, loads the associated policy, and applies the configured
decision action for each detection type.

Decision actions:
  - allow:    pass through, structured event logged for traceability
  - monitor:  pass through, log the detection for review
  - throttle: pass through but mark for reduced rate limit (upstream middleware reads this)
  - block:    return 403 Forbidden

Upstream middlewares annotate detections on request.state.detections (list of dicts):
    request.state.detections.append({
        "type": "injection",          # detection_type
        "score": 0.9,
        "reason": "SQLi pattern match",
    })

Legacy support: request.state.block = True still triggers a block for middlewares
that short-circuit directly.
"""
import logging
import os
import time as _time

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.middlewares.detection_schema import normalize_detection
from app.policies.service import get_policy
from app.routing.service import resolve_route
from app.security.security_event_logger import log_security_event
from app.utils.perf import get_perf
from app.utils.redis_client import RedisClientSingleton
from app.utils.tenant_key import tenant_scoped_key

logger = logging.getLogger(__name__)

# Throttle: maximum number of throttle-flagged requests before escalating to 429.
# Each additional throttle detection increments a per-IP Redis counter; once
# count > THROTTLE_MAX_HITS the request is blocked with 429 (not just slowed).
THROTTLE_MAX_HITS: int = int(os.getenv("THROTTLE_MAX_HITS", "5"))
THROTTLE_WINDOW: int = int(os.getenv("THROTTLE_WINDOW_SECONDS", "60"))


class DecisionEngineMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, handler):
        _t_de = _time.monotonic()
        # Resolve route and attach policy to request state for other middlewares
        route = resolve_route(request.url.path, request.method)
        raw_tid = getattr(request.state, "tenant_id", None)
        tenant_id = raw_tid if isinstance(raw_tid, str) and raw_tid else "default"
        policy = get_policy(route.policy if route else None, tenant_id=tenant_id)
        request.state.route = route
        request.state.policy = policy

        ip = (
            (request.headers.get("x-forwarded-for", "").split(",")[0].strip())
            or (request.client.host if request.client else "unknown")
        )

        # --- PRE-REQUEST: process detections from outer middlewares ---
        # Outer middlewares execute their pre-request code and write to
        # request.state.detections BEFORE call_next reaches us here.
        # We process them now so the route handler never runs for blocked requests.
        raw_detections = getattr(request.state, "detections", [])
        detections = [
            normalize_detection(d) for d in raw_detections if isinstance(d, dict)
        ]
        if detections:
            request.state.detections = detections
            logger.info(
                "DecisionEngine: received detections for %s %s from %s: %s",
                request.method,
                request.url.path,
                ip,
                detections,
            )
        for detection in detections:
            det_type = detection.get("type", "unknown")
            score = detection.get("score", 0.0)
            reason = detection.get("reason", "")
            status_code = detection.get("status_code", 403)
            source = detection.get("source", "unknown")
            action = policy.decision_actions.get_action(det_type)

            if action == "block":
                get_perf(request)["decision_ms"] = round((_time.monotonic() - _t_de) * 1000, 3)
                return self._block_response(
                    request, ip, reason, det_type, score, status_code, source
                )
            elif action == "throttle":
                throttle_response = self._apply_throttle(request, ip, reason, det_type, score, source)
                if throttle_response is not None:
                    get_perf(request)["decision_ms"] = round((_time.monotonic() - _t_de) * 1000, 3)
                    return throttle_response
            elif action == "monitor":
                self._log_monitor(request, ip, reason, det_type, score, source)
            else:
                # action == "allow": emit structured event for full traceability
                log_security_event(
                    request,
                    action="allow",
                    status_code=200,
                    reason=reason,
                    trigger_type=det_type,
                    trigger_source=source,
                )
        # Legacy block flag support — DEPRECATED, will be removed in a future release.
        # Migrate to: append_detection(request, detection_type="...", ...)
        if getattr(request.state, "block", False):
            self._warn_legacy_block(request)
            reason = getattr(request.state, "block_reason", "Security policy violation")
            get_perf(request)["decision_ms"] = round((_time.monotonic() - _t_de) * 1000, 3)
            return self._block_response(
                request, ip, reason, "decision_engine", 1.0, 403, "decision_engine"
            )

        # Route handler executes only if no block
        get_perf(request)["decision_ms"] = round((_time.monotonic() - _t_de) * 1000, 3)
        call_next = handler
        response = await call_next(request)
        # Emit a perf-carrying allow event only when no detection already produced a
        # SIEM event (throttle / monitor / allow detection paths each call
        # log_security_event themselves; this covers the zero-detection fast path).
        if not detections and not getattr(request.state, "block", False):
            log_security_event(
                request,
                action="allow",
                status_code=response.status_code,
                reason="clean request — no detections",
                trigger_type="none",
                trigger_source="decision_engine",
            )
        return response

    def _warn_legacy_block(self, request: Request) -> None:
        """Emit a deprecation warning for the legacy request.state.block flag."""
        logger.warning(
            "DEPRECATED: request.state.block flag detected on %s %s — "
            "migrate to append_detection() instead of setting request.state.block directly",
            request.method, request.url.path,
        )

    def _block_response(
        self,
        request: Request,
        ip: str,
        reason: str,
        det_type: str,
        score: float,
        status_code: int = 403,
        trigger_source: str = "decision_engine",
    ) -> JSONResponse:
        logger.warning(
            "DecisionEngine: blocking %s %s from %s — %s",
            request.method, request.url.path, ip, reason,
        )
        log_security_event(
            request,
            action="block",
            status_code=status_code,
            reason=reason,
            trigger_type=det_type,
            trigger_source=trigger_source,
        )
        if status_code == 429:
            error_msg = "Too Many Requests"
        elif status_code == 401:
            error_msg = "Unauthorized"
        elif status_code == 422:
            error_msg = "Unprocessable Entity"
        else:
            error_msg = "Forbidden"
        headers: dict[str, str] = {}
        if status_code == 401:
            headers["WWW-Authenticate"] = "Bearer"
        return JSONResponse(
            {"error": error_msg, "detail": reason},
            status_code=status_code,
            headers=headers or None,
        )

    def _apply_throttle(
        self, request: Request, ip: str, reason: str, det_type: str, score: float,
        trigger_source: str = "decision_engine",
    ) -> "JSONResponse | None":
        """Increment the throttle counter for this IP.

        Returns a 429 JSONResponse when the counter exceeds THROTTLE_MAX_HITS,
        blocking the request immediately. Returns None to pass the request through
        (below threshold or Redis unavailable — fail-open).
        """
        redis = RedisClientSingleton.get_client()
        if redis:
            try:
                raw_tid = getattr(request.state, "tenant_id", None)
                tenant_id = raw_tid if isinstance(raw_tid, str) and raw_tid else "default"
                key = tenant_scoped_key(tenant_id, "throttle", ip)
                pipe = redis.pipeline()
                pipe.incr(key)
                pipe.expire(key, THROTTLE_WINDOW, nx=True)
                results = pipe.execute()
                count = int(results[0])
                if count > THROTTLE_MAX_HITS:
                    logger.info(
                        "DecisionEngine: throttle escalated to block for %s on %s %s"
                        " — %s (count=%d > max=%d)",
                        ip, request.method, request.url.path, reason, count, THROTTLE_MAX_HITS,
                    )
                    return self._block_response(
                        request, ip,
                        f"{reason} (throttle limit exceeded: {count}/{THROTTLE_MAX_HITS})",
                        det_type, score, 429, trigger_source,
                    )
            except Exception as e:
                logger.error("Throttle Redis error: %s", e)

        # Below threshold (or Redis unavailable): log throttle event and pass through
        logger.info(
            "DecisionEngine: throttling %s %s from %s — %s",
            request.method, request.url.path, ip, reason,
        )
        log_security_event(
            request,
            action="throttle",
            status_code=200,
            reason=reason,
            trigger_type=det_type,
            trigger_source=trigger_source,
        )
        return None

    def _log_monitor(
        self, request: Request, ip: str, reason: str, det_type: str, score: float,
        trigger_source: str = "decision_engine",
    ) -> None:
        logger.info(
            "DecisionEngine: monitoring %s %s from %s — %s",
            request.method, request.url.path, ip, reason,
        )
        log_security_event(
            request,
            action="monitor",
            status_code=200,
            reason=reason,
            trigger_type=det_type,
            trigger_source=trigger_source,
        )
