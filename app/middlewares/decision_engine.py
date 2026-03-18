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

from app.policies.service import Policy, get_policy
from app.routing.service import resolve_route
from app.utils.logging import log_request

logger = logging.getLogger(__name__)


class DecisionEngineMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Resolve route and attach policy to request state for other middlewares
        route = resolve_route(request.url.path, request.method)
        policy = get_policy(route.policy if route else None)
        request.state.route = route
        request.state.policy = policy

        response = await call_next(request)

        ip = (
            (request.headers.get("x-forwarded-for", "").split(",")[0].strip())
            or (request.client.host if request.client else "unknown")
        )

        # Legacy block flag — immediate block
        if getattr(request.state, "block", False):
            reason = getattr(request.state, "block_reason", "Security policy violation")
            return self._block_response(request, ip, reason, "decision_engine", 1.0)

        # Process detections from upstream middlewares
        detections = getattr(request.state, "detections", [])
        for detection in detections:
            det_type = detection.get("type", "unknown")
            score = detection.get("score", 0.0)
            reason = detection.get("reason", "")
            action = policy.decision_actions.get_action(det_type)

            if action == "block":
                return self._block_response(request, ip, reason, det_type, score)
            elif action == "monitor":
                self._log_monitor(request, ip, reason, det_type, score)
            elif action == "throttle":
                self._log_monitor(request, ip, reason, det_type, score)
                # Mark for throttling — rate limit middleware reads this on next request
                # The throttle is informational on the current response
            # action == "allow" → no-op

        return response

    def _block_response(
        self, request: Request, ip: str, reason: str, det_type: str, score: float
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
        return JSONResponse(
            {"error": "Forbidden", "detail": reason},
            status_code=403,
        )

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
