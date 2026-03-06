"""
Unified Decision Engine Middleware.

Runs innermost (closest to route handlers). Its job is to act as a final gate
before a request reaches any route handler.

How it works:
  - Any upstream middleware can set request.state.block = True and optionally
    request.state.block_reason = "<reason>" instead of returning immediately.
  - This middleware calls call_next() and then checks for the flag *before*
    forwarding the response. Because it runs innermost, the response from
    call_next() is the actual route response — if a middleware above already
    blocked, this code is never reached for that request.
  - The primary value here is as a unified gate for middlewares that want to
    annotate rather than short-circuit, allowing score aggregation across
    multiple signals before a final block decision.

Usage in a middleware:
    request.state.block = True
    request.state.block_reason = "Rate limit + bot signals combined"
    return await call_next(request)   # engine will intercept

Note: Middlewares that already return JSONResponse directly (current default)
bypass this gate — they short-circuit before call_next() is called. This gate
handles the cooperative annotation pattern for future middlewares.
"""
import logging

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.utils.logging import log_request

logger = logging.getLogger(__name__)


class DecisionEngineMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        if getattr(request.state, "block", False):
            reason = getattr(request.state, "block_reason", "Security policy violation")
            ip = (
                (request.headers.get("x-forwarded-for", "").split(",")[0].strip())
                or (request.client.host if request.client else "unknown")
            )
            logger.warning(
                "DecisionEngine: blocking %s %s from %s — %s",
                request.method, request.url.path, ip, reason,
            )
            log_request(
                client_ip=ip,
                path=request.url.path,
                method=request.method,
                action="block",
                detection_type="decision_engine",
                score=1.0,
                reasons=reason,
            )
            return JSONResponse(
                {"error": "Forbidden", "detail": reason},
                status_code=403,
            )

        return response
