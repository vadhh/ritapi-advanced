"""
SIEM export format tests and runtime proof.

Verifies that build_siem_event() produces a flat, normalized, SIEM-ready
dict for each enforcement action type, with all required fields present
and correctly typed.

Run with:
    pytest tests/test_siem_export.py -v -s

Required scenarios:
  - bot block      (severity: critical, action: block)
  - injection block (severity: critical, action: block)
  - exfiltration block (severity: critical, action: block)
  - throttle       (severity: medium,   action: throttle)
"""
import json

import pytest

from app.security.siem_export import _derive_severity, build_siem_event

# All fields that must be present in every SIEM event (flat scalars only)
SIEM_REQUIRED_FIELDS = {
    "event_type", "severity", "action", "timestamp",
    "request_id", "tenant_id", "tenant_status", "source_ip",
    "method", "route", "reason", "trigger_type", "trigger_source",
    "status_code", "latency_ms", "detection_count", "detection_types",
}

# Types that must be scalar (no nested objects)
_SCALAR_TYPES = (str, int, float, type(None))


def _assert_siem_event(event: dict, *, action: str, severity: str) -> None:
    """Common structural assertions for all SIEM event scenarios."""
    missing = SIEM_REQUIRED_FIELDS - event.keys()
    assert not missing, f"SIEM event missing required fields: {missing}"

    for field in SIEM_REQUIRED_FIELDS:
        assert isinstance(event[field], _SCALAR_TYPES), (
            f"Field '{field}' must be scalar, got {type(event[field]).__name__}: {event[field]!r}"
        )

    assert event["event_type"] == "security_decision"
    assert event["action"] == action
    assert event["severity"] == severity
    assert isinstance(event["request_id"], str)
    assert isinstance(event["status_code"], int)


# ---------------------------------------------------------------------------
# PROOF 1: bot block
# ---------------------------------------------------------------------------

def test_siem_export_bot_block():
    """
    PROOF — bot block

    Cumulative bot risk >= threshold triggers a pre-request block.
    Severity must be critical (bot_block is in _CRITICAL_TRIGGERS).
    """
    event = build_siem_event(
        action="block",
        status_code=403,
        timestamp="2026-04-02T05:00:00.000000+00:00",
        request_id="b07b10ck-b07b-10ck-b07b-10ckb07b10ck",
        tenant_id="acme-corp",
        source_ip="198.51.100.7",
        method="GET",
        route="/api/v1/products",
        reason="Cumulative bot risk 85 >= 70",
        trigger_type="bot_block",
        trigger_source="bot_detection",
        latency_ms=3.12,
        detection_count=1,
        detection_types="bot_block",
    )

    _assert_siem_event(event, action="block", severity="critical")
    assert event["trigger_type"] == "bot_block"
    assert event["trigger_source"] == "bot_detection"
    assert event["source_ip"] == "198.51.100.7"
    assert event["detection_types"] == "bot_block"

    print(f"\n{'='*60}")
    print("PROOF — bot block")
    print('='*60)
    print(json.dumps(event, indent=2))


# ---------------------------------------------------------------------------
# PROOF 2: injection block
# ---------------------------------------------------------------------------

def test_siem_export_injection_block():
    """
    PROOF — injection block

    SQLi pattern matched in request body before backend sees the request.
    Severity must be critical (injection is in _CRITICAL_TRIGGERS).
    """
    event = build_siem_event(
        action="block",
        status_code=403,
        timestamp="2026-04-02T05:00:01.000000+00:00",
        request_id="1nj3c710n-cafe-babe-dead-beef12345678",
        tenant_id="tenant-prod",
        source_ip="203.0.113.99",
        method="POST",
        route="/api/v1/search",
        reason="sqli: UNION SELECT username, password FROM users--",
        trigger_type="injection",
        trigger_source="injection_detection",
        latency_ms=1.84,
        detection_count=1,
        detection_types="injection",
    )

    _assert_siem_event(event, action="block", severity="critical")
    assert event["trigger_type"] == "injection"
    assert event["trigger_source"] == "injection_detection"
    assert event["status_code"] == 403

    print(f"\n{'='*60}")
    print("PROOF — injection block")
    print('='*60)
    print(json.dumps(event, indent=2))


# ---------------------------------------------------------------------------
# PROOF 3: exfiltration block
# ---------------------------------------------------------------------------

def test_siem_export_exfiltration_block():
    """
    PROOF — exfiltration block

    BULK_ACCESS counter exceeded threshold — pre-request block on repeat access.
    Severity must be critical (exfiltration_block is in _CRITICAL_TRIGGERS).
    """
    event = build_siem_event(
        action="block",
        status_code=403,
        timestamp="2026-04-02T05:00:02.000000+00:00",
        request_id="exf11tra-7e57-exf1-1tra-7e57exf11tra",
        tenant_id="tenant-prod",
        source_ip="10.0.0.88",
        method="GET",
        route="/dashboard/demo-proof",
        reason="bulk_access (pre-request counter exceeded)",
        trigger_type="exfiltration_block",
        trigger_source="exfiltration_detection",
        latency_ms=0.94,
        detection_count=1,
        detection_types="exfiltration_block",
    )

    _assert_siem_event(event, action="block", severity="critical")
    assert event["trigger_type"] == "exfiltration_block"
    assert event["trigger_source"] == "exfiltration_detection"
    assert event["route"] == "/dashboard/demo-proof"

    print(f"\n{'='*60}")
    print("PROOF — exfiltration block")
    print('='*60)
    print(json.dumps(event, indent=2))


# ---------------------------------------------------------------------------
# PROOF 4: throttle
# ---------------------------------------------------------------------------

def test_siem_export_throttle():
    """
    PROOF — throttle

    Bot signals detected post-response; policy action is throttle.
    Request passes through but IP rate limit is halved on next request.
    Severity must be medium.
    """
    event = build_siem_event(
        action="throttle",
        status_code=200,
        timestamp="2026-04-02T05:00:03.000000+00:00",
        request_id="7h20771e-7h20-771e-7h20-771e7h20771e",
        tenant_id="tenant-beta",
        source_ip="192.0.2.45",
        method="POST",
        route="/api/v1/orders",
        reason="Bot signals: RAPID_FIRE, SUSPICIOUS_USER_AGENT",
        trigger_type="bot_detection",
        trigger_source="bot_detection",
        latency_ms=12.7,
        detection_count=1,
        detection_types="bot_detection",
    )

    _assert_siem_event(event, action="throttle", severity="medium")
    assert event["status_code"] == 200   # request passed through
    assert event["trigger_type"] == "bot_detection"
    assert event["latency_ms"] == 12.7

    print(f"\n{'='*60}")
    print("PROOF — throttle")
    print('='*60)
    print(json.dumps(event, indent=2))


# ---------------------------------------------------------------------------
# Severity matrix
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("action,trigger_type,expected_severity", [
    # Critical triggers on block
    ("block", "injection",          "critical"),
    ("block", "bot_block",          "critical"),
    ("block", "exfiltration_block", "critical"),
    ("block", "schema_violation",   "critical"),
    ("block", "ddos_spike",         "critical"),
    ("block", "blocked_ip",         "critical"),
    ("block", "yara",               "critical"),
    # Non-critical block
    ("block", "rate_limit",         "high"),
    ("block", "auth_failure",       "high"),
    # Other actions
    ("throttle", "bot_detection",   "medium"),
    ("monitor",  "exfiltration",    "low"),
    ("allow",    "exfiltration",    "info"),
])
def test_severity_matrix(action, trigger_type, expected_severity):
    assert _derive_severity(action, trigger_type) == expected_severity, (
        f"_derive_severity({action!r}, {trigger_type!r}) should be "
        f"{expected_severity!r}"
    )


# ---------------------------------------------------------------------------
# Scalar-only contract for all required fields
# ---------------------------------------------------------------------------

def test_all_required_fields_are_scalar():
    """No required SIEM field may be a list or dict."""
    event = build_siem_event(
        action="block",
        status_code=403,
        timestamp="2026-04-02T05:00:00+00:00",
        request_id="scalar-test-0000-0000-000000000000",
        tenant_id="default",
        source_ip="127.0.0.1",
        method="GET",
        route="/api/test",
        reason="test",
        trigger_type="injection",
        trigger_source="injection_detection",
        detection_count=2,
        detection_types="injection,rate_limit",
    )
    for field in SIEM_REQUIRED_FIELDS:
        assert isinstance(event[field], _SCALAR_TYPES), (
            f"Required field '{field}' is not scalar: {type(event[field]).__name__}"
        )
