"""
Security decision logger.

Writes structured JSON decision records to stdout so they feed into any
log aggregator without filesystem dependencies.  Plain print() is used
intentionally — no logging framework so the output is predictable and
easy to pipe into Fluentd, Logstash, or CloudWatch Logs.

Functions
---------
log_decision(request, decision)
    Write a full decision log line to stdout.
format_siem_event(request, decision) -> dict
    Return a SIEM-compatible event dict (caller decides what to do with it).
"""
import json
import time
from datetime import UTC, datetime


def format_siem_event(request, decision: dict) -> dict:
    """Return a SIEM-compatible event dict for the given decision.

    Severity mapping:
      block    → high
      throttle → medium
      monitor  → low
      allow    → low
    """
    action = decision.get("action", "allow")
    severity_map = {
        "block": "high",
        "throttle": "medium",
        "monitor": "low",
        "allow": "low",
    }
    return {
        "event_type": "security_decision",
        "severity": severity_map.get(action, "low"),
        "action": action,
        "source_ip": request.client.host if request.client else "unknown",
        "route": request.url.path,
        "reason": decision.get("reason", ""),
        "timestamp": datetime.now(UTC).isoformat(),
        "request_id": getattr(request.state, "request_id", ""),
    }


def _safe_str(value, default: str = "") -> str:
    """Return value if it is a plain str, otherwise default.  Never raises."""
    return value if isinstance(value, str) else default


def log_decision(request, decision: dict) -> None:
    """Write a structured decision log line to stdout.

    Fields emitted:
      timestamp    — float (Unix epoch)
      request_id   — UUID from request.state.request_id
      route        — URL path
      method       — HTTP method
      client_ip    — originating IP
      action       — allow | monitor | throttle | block
      reason       — human-readable reason string
      trigger_type — detection type that caused the decision
      detections   — list of {type, severity, reason} from request.state.detections
      siem_event   — nested SIEM-formatted dict (see format_siem_event)

    Never raises — log failures must not affect request processing.
    """
    try:
        # Coerce fields that may be MagicMock objects in unit tests
        request_id = _safe_str(getattr(request.state, "request_id", ""))

        client_ip = "unknown"
        try:
            if request.client:
                client_ip = _safe_str(request.client.host, default="unknown")
        except Exception:  # noqa: S110
            pass

        raw_detections = getattr(request.state, "detections", None)
        detections_list = raw_detections if isinstance(raw_detections, list) else []

        # Compute request latency. started_at is set by RequestIDMiddleware as a
        # monotonic float. Guard against missing/non-numeric values (e.g. MagicMock
        # in unit tests) so this never raises.
        try:
            started_at = getattr(request.state, "started_at", None)
            if isinstance(started_at, (int, float)):
                latency_ms = round((time.monotonic() - started_at) * 1000, 2)
            else:
                latency_ms = None
        except Exception:  # noqa: S110
            latency_ms = None

        siem_event = format_siem_event(request, decision)

        record = {
            "timestamp": time.time(),
            "request_id": request_id,
            "route": _safe_str(request.url.path),
            "method": _safe_str(request.method),
            "client_ip": client_ip,
            "latency_ms": latency_ms,
            "action": _safe_str(decision.get("action", "allow"), default="allow"),
            "reason": _safe_str(decision.get("reason", "")),
            "trigger_type": _safe_str(decision.get("trigger_type", "")),
            "detections": [
                {
                    "type": _safe_str(d.get("type", "")),
                    "severity": _safe_str(d.get("severity", "")),
                    "reason": _safe_str(d.get("reason", "")),
                }
                for d in detections_list
                if isinstance(d, dict)
            ],
            "siem_event": siem_event,
        }
        print(json.dumps(record))
    except Exception:  # noqa: S110
        pass
