"""
Unified Decision Engine Middleware.

Runs innermost (closest to route handlers). Resolves each request to a route
via routing/service.py, loads the associated policy, and applies the configured
decision action for each detection type.

Decision actions:
  - allow:    pass through, no logging
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

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.policies.service import get_policy
from app.routing.service import resolve_route
from app.utils.logging import log_request

logger = logging.getLogger(__name__)


class DecisionEngineMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, handler):
        # Resolve route and attach policy to request state for other middlewares
        route = resolve_route(request.url.path, request.method)
        policy = get_policy(route.policy if route else None)
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
        detections = getattr(request.state, "detections", [])
        for detection in detections:
            det_type = detection.get("type", "unknown")
            score = detection.get("score", 0.0)
            reason = detection.get("reason", "")
            status_code = detection.get("status_code", 403)
            action = policy.decision_actions.get_action(det_type)

            if action == "block":
                return self._block_response(request, ip, reason, det_type, score, status_code)
            elif action == "throttle":
                self._apply_throttle(request, ip, reason, det_type, score)
            elif action == "monitor":
                self._log_monitor(request, ip, reason, det_type, score)
            # action == "allow" → no-op

        # Legacy block flag support
        if getattr(request.state, "block", False):
            reason = getattr(request.state, "block_reason", "Security policy violation")
            return self._block_response(request, ip, reason, "decision_engine", 1.0, 403)

        # Route handler executes only if no block
        call_next = handler
        return await call_next(request)

    def _block_response(
        self,
        request: Request,
        ip: str,
        reason: str,
        det_type: str,
        score: float,
        status_code: int = 403,
    ) -> JSONResponse:
        logger.warning(
            "DecisionEngine: blocking %s %s from %s — %s",
            request.method, request.url.path, ip, reason,
        )
        log_request(
            client_ip=ip,
            path=request.url.path,
            method=request.method,
            action="block",
            detection_type=det_type,
            score=score,
            reasons=reason,
        )
        error_msg = "Too Many Requests" if status_code == 429 else "Forbidden"
        return JSONResponse(
            {"error": error_msg, "detail": reason},
            status_code=status_code,
        )

    def _apply_throttle(
        self, request: Request, ip: str, reason: str, det_type: str, score: float
    ) -> None:
        """Mark this IP for throttling — rate_limit reads this on next request."""
        self._log_monitor(request, ip, reason, det_type, score)
        # Full Redis implementation added in Task C3

    def _log_monitor(
        self, request: Request, ip: str, reason: str, det_type: str, score: float
    ) -> None:
        logger.info(
            "DecisionEngine: monitoring %s %s from %s — %s",
            request.method, request.url.path, ip, reason,
        )
        log_request(
            client_ip=ip,
            path=request.url.path,
            method=request.method,
            action="monitor",
            detection_type=det_type,
            score=score,
            reasons=reason,
        )
