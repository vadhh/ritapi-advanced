"""
SIEM-ready event export.

Provides build_siem_event() — converts enforcement decision parameters into
a flat, normalized dict suitable for direct ingestion by Splunk, Elastic SIEM,
Chronicle, QRadar, or any line-oriented log ingestor.

Contract:
  - Every required field is always present.
  - Every required field is scalar (str / int / float / None) — no nested objects.
  - Field names and types are stable across all action types (block / throttle /
    monitor / allow) and all trigger types.
  - severity is derived internally from action + trigger_type; callers do not
    compute it.

Required SIEM fields (always scalar, always present):
  event_type      — always "security_decision"
  severity        — critical | high | medium | low | info
  action          — block | throttle | monitor | allow
  timestamp       — ISO 8601 UTC string
  request_id      — UUID string (empty string when unavailable)
  tenant_id       — tenant identifier (default: "default")
  source_ip       — originating client IP (XFF-first)
  method          — HTTP method
  route           — URL path (no query string)
  reason          — human-readable trigger description
  trigger_type    — detection category (e.g. "injection", "bot_block")
  trigger_source  — middleware that produced the detection
  status_code     — HTTP status code returned to the client

Extension fields (scalar, SIEM-safe; SIEM tools may ignore):
  latency_ms      — float | null
  detection_count — int (number of detections accumulated on this request)
  detection_types — comma-joined sorted set of detection type strings
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

_ACTION_SEVERITY: dict[str, str] = {
    "block": "high",
    "throttle": "medium",
    "monitor": "low",
    "allow": "info",
}

# Trigger types that escalate a block from "high" to "critical"
_CRITICAL_TRIGGERS: frozenset[str] = frozenset({
    "injection",
    "bot_block",
    "exfiltration_block",
    "schema_violation",
    "ddos_spike",
    "blocked_ip",
    "blocked_asn",
    "yara",
})


def _derive_severity(action: str, trigger_type: str) -> str:
    """Return normalized severity for this action/trigger combination."""
    base = _ACTION_SEVERITY.get(action, "low")
    if base == "high" and trigger_type in _CRITICAL_TRIGGERS:
        return "critical"
    return base


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_siem_event(
    *,
    event_type: str = "security_decision",
    action: str,
    status_code: int,
    timestamp: str,
    request_id: str,
    tenant_id: str,
    source_ip: str,
    method: str,
    route: str,
    reason: str,
    trigger_type: str,
    trigger_source: str,
    latency_ms: float | None = None,
    detection_count: int = 0,
    detection_types: str = "",
) -> dict[str, object]:
    """
    Return a flat SIEM-compatible event dict.

    All required fields are scalar — no nested objects.
    The extension fields (latency_ms, detection_count, detection_types) are
    scalar summaries of richer data; SIEM tools can index them as-is.

    Never raises. Callers are responsible for providing correct types.
    """
    return {
        # ---- Required SIEM fields ----
        "event_type": event_type,
        "severity": _derive_severity(action, trigger_type),
        "action": action,
        "timestamp": timestamp,
        "request_id": request_id,
        "tenant_id": tenant_id,
        "source_ip": source_ip,
        "method": method,
        "route": route,
        "reason": reason,
        "trigger_type": trigger_type,
        "trigger_source": trigger_source,
        "status_code": status_code,
        # ---- Extension fields (scalar, SIEM-safe) ----
        "latency_ms": latency_ms,
        "detection_count": detection_count,
        "detection_types": detection_types,
    }
