"""
Centralized structured security event logger.

This is the canonical audit trail for all enforcement decisions.
DecisionEngine calls log_security_event() once per request, after all
detections from upstream middleware have been evaluated.

Output: one JSON line to stdout per event, compatible with
Fluentd / Logstash / CloudWatch Logs / any line-oriented SIEM ingestor.

The emitted line is built by siem_export.build_siem_event() and therefore
satisfies the SIEM flat-schema contract. A rich `detections` extension array
is appended for non-SIEM consumers (log aggregators, forensics tools) that
need per-detection detail; SIEM tools should ignore it.

Canonical field list — see siem_export.build_siem_event() docstring.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import Request

from app.security.siem_export import build_siem_event


def _get_source_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _safe_str(value: Any, default: str = "") -> str:
    return value if isinstance(value, str) else default


_MAX_DETECTIONS = 10    # cap array length serialised into each SIEM event
_MAX_REASON_LEN = 300   # truncate free-text reason strings under hot paths


def _safe_detections(request: Request) -> list[dict[str, Any]]:
    raw = getattr(request.state, "detections", None)
    if not isinstance(raw, list):
        return []
    out = []
    for d in raw[:_MAX_DETECTIONS]:   # never serialise more than cap
        if not isinstance(d, dict):
            continue
        reason = _safe_str(d.get("reason"))
        out.append({
            "type":     _safe_str(d.get("type"), "unknown"),
            "score":    d.get("score", 0.0) if isinstance(d.get("score"), (int, float)) else 0.0,
            "severity": _safe_str(d.get("severity"), "low"),
            "reason":   reason[:_MAX_REASON_LEN],
            "source":   _safe_str(d.get("source"), "unknown"),
        })
    return out


def log_security_event(
    request: Request,
    *,
    action: str,
    status_code: int,
    reason: str,
    trigger_type: str,
    trigger_source: str,
) -> None:
    """
    Emit one structured security event to stdout.

    Builds a flat SIEM-compatible event via siem_export.build_siem_event(),
    then appends a `detections` extension array for rich consumers.

    Must never raise — log failures must not affect request processing.
    """
    try:
        request_id = _safe_str(getattr(request.state, "request_id", ""))

        raw_tid = getattr(request.state, "tenant_id", None)
        tenant_id = raw_tid if isinstance(raw_tid, str) and raw_tid else "default"

        latency_ms: float | None = None
        try:
            started_at = getattr(request.state, "started_at", None)
            if isinstance(started_at, (int, float)):
                latency_ms = round((time.monotonic() - started_at) * 1000, 2)
        except Exception:
            pass

        detections = _safe_detections(request)
        det_types_csv = ",".join(sorted({d["type"] for d in detections if d.get("type")}))

        event = build_siem_event(
            action=_safe_str(action, "allow"),
            status_code=status_code,
            timestamp=datetime.now(timezone.utc).isoformat(),
            request_id=request_id,
            tenant_id=tenant_id,
            source_ip=_get_source_ip(request),
            method=_safe_str(request.method),
            route=_safe_str(request.url.path),
            reason=_safe_str(reason)[:_MAX_REASON_LEN],
            trigger_type=_safe_str(trigger_type),
            trigger_source=_safe_str(trigger_source),
            latency_ms=latency_ms,
            detection_count=len(detections),
            detection_types=det_types_csv,
        )

        # Rich extension for non-SIEM consumers — SIEM tools should ignore this key
        event["detections"] = detections

        print(json.dumps(event, ensure_ascii=False))
    except Exception:
        pass
