"""
Per-request performance dictionary helpers.

All middleware stages write their elapsed CPU+I/O time into
request.state.perf so the SIEM logger can include a lightweight
breakdown in every security_decision event.

Key contract:
  - get_perf(request)  → always returns the live dict; initialises it lazily.
  - add_redis_ms()     → accumulates Redis I/O time across middleware stages.
    Called from any middleware that performs Redis operations.

Dict schema written by middleware:
  auth_ms       float  credential verification (JWT decode / Redis key lookup + tenant check)
  bot_ms        float  bot detection logic (pre-check + post-response; excludes call_next)
  injection_ms  float  regex + YARA scan (excludes call_next)
  exfil_ms      float  exfiltration analysis (pre-check + post-response; excludes call_next)
  decision_ms   float  route resolution + policy loading + detection processing
  redis_ms      float  accumulated raw Redis I/O across all stages
  total_ms      float  end-to-end request time (written by RequestIDMiddleware on response)

All values are milliseconds, rounded to 3 decimal places.
"""
from __future__ import annotations

from fastapi import Request


def get_perf(request: Request) -> dict:
    """Return request.state.perf, initialising it if absent."""
    if not hasattr(request.state, "perf") or not isinstance(request.state.perf, dict):
        request.state.perf = {}
    return request.state.perf


def add_redis_ms(request: Request, delta_ms: float) -> None:
    """Add delta_ms to the accumulated redis_ms counter."""
    p = get_perf(request)
    p["redis_ms"] = round(p.get("redis_ms", 0.0) + delta_ms, 3)
