"""
Security event correlation tests — request_id / tenant_id / source traceability.

Verifies that DecisionEngine emits exactly one structured JSON event per
enforcement decision (block / throttle / allow), and that every event contains
the required correlation fields.

Run with:
    pytest tests/test_security_event_correlation.py -v -s
"""
import asyncio
import json
from unittest.mock import MagicMock, patch

from fastapi import Request
from starlette.responses import JSONResponse as StarletteJSONResponse

from app.middlewares.decision_engine import DecisionEngineMiddleware
from app.policies.service import DecisionActions, Policy

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_request(
    request_id: str,
    tenant_id: str,
    detections: list[dict],
    path: str = "/api/v1/resource",
    method: str = "GET",
    client_ip: str = "203.0.113.42",
) -> MagicMock:
    req = MagicMock(spec=Request)
    # XFF header — _get_client_ip reads this first
    req.headers.get.return_value = client_ip
    req.client.host = client_ip
    req.url.path = path
    req.method = method
    req.state = MagicMock()
    req.state.request_id = request_id
    req.state.tenant_id = tenant_id
    req.state.started_at = None   # latency_ms will be null — no monotonic ref
    req.state.block = False
    req.state.detections = detections
    req.state.route = None
    return req


async def _noop_next(req):
    return StarletteJSONResponse({"ok": True}, status_code=200)


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _dispatch(middleware, req, policy):
    with patch("app.middlewares.decision_engine.get_policy", return_value=policy):
        with patch("app.middlewares.decision_engine.resolve_route", return_value=None):
            return _run(middleware.dispatch(req, _noop_next))


REQUIRED_FIELDS = {
    # SIEM flat fields
    "event_type", "severity", "action", "timestamp",
    "request_id", "tenant_id", "tenant_status", "source_ip",
    "method", "route", "reason", "trigger_type", "trigger_source", "status_code",
    # Extension fields
    "latency_ms", "detection_count", "detection_types",
    # Rich extension (non-SIEM consumers)
    "detections",
}


def _assert_common(event: dict, request_id: str, tenant_id: str, action: str) -> None:
    missing = REQUIRED_FIELDS - event.keys()
    assert not missing, f"Event missing fields: {missing}"
    assert event["event_type"] == "security_decision"
    assert event["request_id"] == request_id, "request_id must match"
    assert event["tenant_id"] == tenant_id, "tenant_id must match"
    assert event["tenant_status"] in ("authenticated", "unauthenticated"), (
        f"tenant_status must be 'authenticated' or 'unauthenticated', got {event['tenant_status']!r}"
    )
    assert event["action"] == action
    assert isinstance(event["detections"], list)


# ---------------------------------------------------------------------------
# PROOF 1: block
# ---------------------------------------------------------------------------

def test_block_event_correlation(capsys):
    """
    PROOF — block

    A SQLi detection produced by injection_detection must result in exactly one
    structured block event with:
      - the correct request_id
      - trigger_source == "injection_detection"
      - status_code == 403
    """
    request_id = "b10cb10c-b10c-b10c-b10c-b10cb10cb10c"

    req = _make_request(
        request_id=request_id,
        tenant_id="acme-corp",
        detections=[{
            "type": "injection",
            "score": 0.95,
            "reason": "sqli: UNION SELECT username, password FROM users--",
            "status_code": 403,
            "source": "injection_detection",
        }],
        path="/api/v1/users",
        method="GET",
        client_ip="203.0.113.42",
    )

    policy = Policy(
        name="strict",
        decision_actions=DecisionActions(on_injection="block"),
    )

    middleware = DecisionEngineMiddleware(app=MagicMock())
    response = _dispatch(middleware, req, policy)

    # Only one line should be emitted (no duplicates)
    raw = capsys.readouterr().out.strip()
    lines = [line for line in raw.splitlines() if line.strip()]
    assert len(lines) == 1, f"Expected 1 structured event, got {len(lines)}: {raw}"

    event = json.loads(lines[0])
    _assert_common(event, request_id, "acme-corp", "block")

    assert response.status_code == 403
    assert event["status_code"] == 403
    assert event["severity"] == "critical"    # injection block → critical
    assert event["trigger_type"] == "injection"
    assert event["trigger_source"] == "injection_detection"
    assert event["route"] == "/api/v1/users"
    assert event["method"] == "GET"
    assert event["source_ip"] == "203.0.113.42"
    assert event["detection_count"] == 1
    assert "injection" in event["detection_types"]
    assert event["detections"][0]["source"] == "injection_detection"

    print(f"\n{'='*60}")
    print("PROOF — block event")
    print('='*60)
    print(json.dumps(event, indent=2))


# ---------------------------------------------------------------------------
# PROOF 2: throttle
# ---------------------------------------------------------------------------

def test_throttle_event_correlation(capsys):
    """
    PROOF — throttle

    A bot detection must result in exactly one structured throttle event with:
      - the correct request_id
      - action == "throttle"  (previously logged as "monitor" — regression check)
      - trigger_source == "bot_detection"
    """
    request_id = "cafecafe-cafe-cafe-cafe-cafecafecafe"

    req = _make_request(
        request_id=request_id,
        tenant_id="tenant-beta",
        detections=[{
            "type": "bot_detection",
            "score": 0.72,
            "reason": "Bot signals: RAPID_FIRE, SUSPICIOUS_USER_AGENT",
            "status_code": 403,
            "source": "bot_detection",
        }],
        path="/api/v1/products",
        method="POST",
        client_ip="198.51.100.77",
    )

    policy = Policy(
        name="throttle-bots",
        decision_actions=DecisionActions(on_bot_detection="throttle"),
    )

    middleware = DecisionEngineMiddleware(app=MagicMock())

    # Redis write in _apply_throttle is a side effect — skip it cleanly
    with patch("app.middlewares.decision_engine.RedisClientSingleton.get_client", return_value=None):
        response = _dispatch(middleware, req, policy)

    raw = capsys.readouterr().out.strip()
    lines = [line for line in raw.splitlines() if line.strip()]
    assert len(lines) == 1, f"Expected 1 structured event, got {len(lines)}: {raw}"

    event = json.loads(lines[0])
    _assert_common(event, request_id, "tenant-beta", "throttle")

    assert response.status_code == 200   # throttle passes the request through
    assert event["action"] == "throttle"  # must NOT be "monitor" — regression
    assert event["severity"] == "medium"  # throttle → medium
    assert event["trigger_type"] == "bot_detection"
    assert event["trigger_source"] == "bot_detection"
    assert event["source_ip"] == "198.51.100.77"
    assert event["detection_count"] == 1

    print(f"\n{'='*60}")
    print("PROOF — throttle event")
    print('='*60)
    print(json.dumps(event, indent=2))


# ---------------------------------------------------------------------------
# PROOF 3: allow
# ---------------------------------------------------------------------------

def test_allow_event_correlation(capsys):
    """
    PROOF — allow

    A detection whose policy action is "allow" must emit exactly one structured
    allow event with the correct request_id (previously silent — regression check).
    """
    request_id = "deadbeef-dead-beef-dead-beefdeadbeef"

    req = _make_request(
        request_id=request_id,
        tenant_id="tenant-gamma",
        detections=[{
            "type": "exfiltration",
            "score": 0.45,
            "reason": "large_response (response_size=1_258_291)",
            "status_code": 200,
            "source": "exfiltration_detection",
        }],
        path="/api/v1/export",
        method="GET",
        client_ip="10.0.1.55",
    )

    policy = Policy(
        name="permissive-export",
        decision_actions=DecisionActions(on_exfiltration="allow"),
    )

    middleware = DecisionEngineMiddleware(app=MagicMock())
    response = _dispatch(middleware, req, policy)

    raw = capsys.readouterr().out.strip()
    lines = [line for line in raw.splitlines() if line.strip()]
    assert len(lines) == 1, f"Expected 1 structured event, got {len(lines)}: {raw}"

    event = json.loads(lines[0])
    _assert_common(event, request_id, "tenant-gamma", "allow")

    assert response.status_code == 200
    assert event["action"] == "allow"
    assert event["severity"] == "info"   # allow → info
    assert event["trigger_type"] == "exfiltration"
    assert event["trigger_source"] == "exfiltration_detection"
    assert event["source_ip"] == "10.0.1.55"
    assert event["detection_count"] == 1

    print(f"\n{'='*60}")
    print("PROOF — allow event")
    print('='*60)
    print(json.dumps(event, indent=2))


# ---------------------------------------------------------------------------
# Structural invariants
# ---------------------------------------------------------------------------

def test_no_duplicate_events_for_single_detection(capsys):
    """A single detection must produce exactly one stdout line, not two."""
    req = _make_request(
        request_id="dededede-dede-dede-dede-dededededede",
        tenant_id="default",
        detections=[{
            "type": "rate_limit",
            "score": 1.0,
            "reason": "Rate limit exceeded for ip:10.0.0.1",
            "status_code": 429,
            "source": "rate_limit",
        }],
    )
    policy = Policy(name="default", decision_actions=DecisionActions(on_rate_limit="block"))
    middleware = DecisionEngineMiddleware(app=MagicMock())
    _dispatch(middleware, req, policy)

    raw = capsys.readouterr().out.strip()
    lines = [line for line in raw.splitlines() if line.strip()]
    assert len(lines) == 1, (
        f"Duplicate event detected: expected 1 stdout line, got {len(lines)}\n{raw}"
    )


def test_request_id_propagates_from_state(capsys):
    """request_id must come from request.state, not be generated anew per event."""
    specific_id = "f00df00d-f00d-f00d-f00d-f00df00df00d"
    req = _make_request(
        request_id=specific_id,
        tenant_id="default",
        detections=[{
            "type": "injection",
            "score": 0.9,
            "reason": "path_traversal: ../etc/passwd",
            "status_code": 403,
            "source": "injection_detection",
        }],
    )
    policy = Policy(name="default")
    middleware = DecisionEngineMiddleware(app=MagicMock())
    _dispatch(middleware, req, policy)

    raw = capsys.readouterr().out.strip()
    event = json.loads(raw.splitlines()[0])
    assert event["request_id"] == specific_id, (
        f"Event request_id {event['request_id']!r} does not match "
        f"request.state.request_id {specific_id!r}"
    )
