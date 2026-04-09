"""
Request ID middleware.

Runs outermost (first on inbound, last on outbound) so every downstream
middleware and route handler can read request.state.request_id.

Also stamps request.state.started_at (monotonic clock) for latency tracking,
and logs a stderr warning when total request latency exceeds
PERF_WARN_THRESHOLD_MS (default 50 ms).
"""
import os
import sys
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.utils.perf import get_perf

_PERF_WARN_MS: float = float(os.getenv("PERF_WARN_THRESHOLD_MS", "50"))


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        request.state.started_at = time.monotonic()
        # Initialise perf dict early so every downstream middleware can write into it.
        request.state.perf = {}
        response = await call_next(request)
        elapsed = (time.monotonic() - request.state.started_at) * 1000
        get_perf(request)["total_ms"] = round(elapsed, 3)
        if elapsed > _PERF_WARN_MS:
            print(
                f"[PERF] {request.url.path} took {elapsed:.1f}ms"
                f" — exceeds {_PERF_WARN_MS:.0f}ms soft limit",
                file=sys.stderr,
            )
        response.headers["X-Request-ID"] = request_id
        return response
