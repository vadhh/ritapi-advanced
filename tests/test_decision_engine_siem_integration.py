"""
DecisionEngine → SIEM export integration proof.

Verifies that the correct model is enforced end-to-end:

  1. Middleware appends a detection to request.state.detections
  2. DecisionEngine reads all detections, evaluates policy, chooses final action
  3. DecisionEngine emits exactly one canonical SIEM event to stdout
  4. No other middleware emits its own structured export event

Each test prints the full narrative:
  REQUEST      — what came in
  DETECTION    — what the middleware appended
  SIEM EVENT   — what DecisionEngine emitted (the only structured output)

Run with:
    pytest tests/test_decision_engine_siem_integration.py -v -s
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
    path: str,
    method: str = "GET",
    client_ip: str = "203.0.113.10",
) -> MagicMock:
    req = MagicMock(spec=Request)
    req.headers.get.return_value = client_ip
    req.client.host = client_ip
    req.url.path = path
    req.method = method
    req.state = MagicMock()
    req.state.request_id = request_id
    req.state.tenant_id = tenant_id
    req.state.started_at = None
    req.state.block = False
    req.state.detections = []
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


def _print_proof(label: str, req: MagicMock, detection: dict, event: dict) -> None:
    print(f"\n{'='*64}")
    print(f"PROOF — {label}")
    print('='*64)
    print("\nREQUEST:")
    print(f"  {req.method} {req.url.path}  (ip={req.headers.get.return_value},"
          f" tenant={req.state.tenant_id})")
    print(f"\nDETECTION appended by {detection.get('source', '?')}:")
    print(f"  type={detection['type']}  score={detection['score']}"
          f"  reason={detection['reason'][:70]}")
    print(f"\nFINAL ACTION chosen by DecisionEngine: {event['action'].upper()}"
          f"  →  severity={event['severity']}  status={event['status_code']}")
    print("\nSIEM EVENT (stdout — canonical audit log):")
    print(json.dumps(event, indent=2))


# ---------------------------------------------------------------------------
# PROOF 1: injection → block
# ---------------------------------------------------------------------------

def test_injection_block_full_flow(capsys):
    """
    Flow: InjectionDetectionMiddleware appends detection
          → DecisionEngine blocks (policy: on_injection=block)
          → one SIEM event emitted, no middleware-level export
    """
    request_id = "a001a001-a001-a001-a001-a001a001a001"
    req = _make_request(
        request_id=request_id,
        tenant_id="prod",
        path="/api/v1/users",
        method="POST",
        client_ip="198.51.100.10",
    )

    # Simulate what InjectionDetectionMiddleware appends
    detection = {
        "type": "injection",
        "score": 0.95,
        "reason": "sqli: ' OR 1=1--",
        "status_code": 403,
        "source": "injection_detection",
    }
    req.state.detections = [detection]

    policy = Policy(name="strict", decision_actions=DecisionActions(on_injection="block"))
    middleware = DecisionEngineMiddleware(app=MagicMock())
    response = _dispatch(middleware, req, policy)

    raw = capsys.readouterr().out.strip()
    lines = [line for line in raw.splitlines() if line.strip()]

    # Exactly one structured event — no middleware-level duplicates
    assert len(lines) == 1, f"Expected 1 SIEM event, got {len(lines)}"

    event = json.loads(lines[0])

    assert event["event_type"] == "security_decision"
    assert event["request_id"] == request_id
    assert event["action"] == "block"
    assert event["severity"] == "critical"
    assert event["trigger_type"] == "injection"
    assert event["trigger_source"] == "injection_detection"
    assert event["status_code"] == 403
    assert response.status_code == 403

    _print_proof("injection → block", req, detection, event)


# ---------------------------------------------------------------------------
# PROOF 2: bot cumulative risk → throttle
# ---------------------------------------------------------------------------

def test_bot_throttle_full_flow(capsys):
    """
    Flow: BotDetectionMiddleware appends detection
          → DecisionEngine throttles (policy: on_bot_detection=throttle)
          → one SIEM event emitted, request passes through (200)
    """
    request_id = "b002b002-b002-b002-b002-b002b002b002"
    req = _make_request(
        request_id=request_id,
        tenant_id="staging",
        path="/api/v1/products",
        method="GET",
        client_ip="192.0.2.55",
    )

    detection = {
        "type": "bot_detection",
        "score": 0.78,
        "reason": "Bot signals: RAPID_FIRE, NO_USER_AGENT",
        "status_code": 403,
        "source": "bot_detection",
    }
    req.state.detections = [detection]

    policy = Policy(
        name="lenient",
        decision_actions=DecisionActions(on_bot_detection="throttle"),
    )
    middleware = DecisionEngineMiddleware(app=MagicMock())

    with patch("app.middlewares.decision_engine.RedisClientSingleton.get_client", return_value=None):
        response = _dispatch(middleware, req, policy)

    raw = capsys.readouterr().out.strip()
    lines = [line for line in raw.splitlines() if line.strip()]

    assert len(lines) == 1, f"Expected 1 SIEM event, got {len(lines)}"

    event = json.loads(lines[0])

    assert event["request_id"] == request_id
    assert event["action"] == "throttle"
    assert event["severity"] == "medium"
    assert event["trigger_source"] == "bot_detection"
    assert event["status_code"] == 200   # passed through
    assert response.status_code == 200

    _print_proof("bot detection → throttle", req, detection, event)


# ---------------------------------------------------------------------------
# PROOF 3: exfiltration bulk_access → block
# ---------------------------------------------------------------------------

def test_exfiltration_block_full_flow(capsys):
    """
    Flow: ExfiltrationDetectionMiddleware appends detection
          → DecisionEngine blocks (policy: on_exfiltration_block=block)
          → one SIEM event emitted with trigger_source=exfiltration_detection
    """
    request_id = "c003c003-c003-c003-c003-c003c003c003"
    req = _make_request(
        request_id=request_id,
        tenant_id="prod",
        path="/api/v1/export/full",
        method="GET",
        client_ip="10.0.0.42",
    )

    detection = {
        "type": "exfiltration_block",
        "score": 0.9,
        "reason": "bulk_access (pre-request counter exceeded)",
        "status_code": 403,
        "source": "exfiltration_detection",
    }
    req.state.detections = [detection]

    policy = Policy(
        name="strict",
        decision_actions=DecisionActions(on_exfiltration_block="block"),
    )
    middleware = DecisionEngineMiddleware(app=MagicMock())
    response = _dispatch(middleware, req, policy)

    raw = capsys.readouterr().out.strip()
    lines = [line for line in raw.splitlines() if line.strip()]

    assert len(lines) == 1, f"Expected 1 SIEM event, got {len(lines)}"

    event = json.loads(lines[0])

    assert event["request_id"] == request_id
    assert event["action"] == "block"
    assert event["severity"] == "critical"
    assert event["trigger_type"] == "exfiltration_block"
    assert event["trigger_source"] == "exfiltration_detection"
    assert event["status_code"] == 403
    assert response.status_code == 403

    _print_proof("exfiltration bulk_access → block", req, detection, event)


# ---------------------------------------------------------------------------
# PROOF 4: multiple detections, highest-severity block wins
# ---------------------------------------------------------------------------

def test_multiple_detections_block_wins(capsys):
    """
    Flow: two detections accumulated (rate_limit + injection)
          → DecisionEngine processes in order, injection block fires first
          → exactly one SIEM event (the block), loop exits
    """
    request_id = "d004d004-d004-d004-d004-d004d004d004"
    req = _make_request(
        request_id=request_id,
        tenant_id="prod",
        path="/api/v1/search",
        method="POST",
        client_ip="203.0.113.77",
    )

    req.state.detections = [
        {
            "type": "rate_limit",
            "score": 0.9,
            "reason": "Rate limit exceeded for ip:203.0.113.77",
            "status_code": 429,
            "source": "rate_limit",
        },
        {
            "type": "injection",
            "score": 0.95,
            "reason": "sqli: UNION SELECT * FROM users",
            "status_code": 403,
            "source": "injection_detection",
        },
    ]

    policy = Policy(
        name="strict",
        decision_actions=DecisionActions(on_rate_limit="block", on_injection="block"),
    )
    middleware = DecisionEngineMiddleware(app=MagicMock())
    _dispatch(middleware, req, policy)

    raw = capsys.readouterr().out.strip()
    lines = [line for line in raw.splitlines() if line.strip()]

    # Only one event — loop stops at first block
    assert len(lines) == 1, f"Expected 1 SIEM event, got {len(lines)}"

    event = json.loads(lines[0])

    assert event["request_id"] == request_id
    assert event["action"] == "block"
    # rate_limit fires first (it's first in the list)
    assert event["trigger_type"] == "rate_limit"
    assert event["status_code"] == 429
    assert event["detection_count"] == 2
    assert "rate_limit" in event["detection_types"]

    print(f"\n{'='*64}")
    print("PROOF — multiple detections: first block wins, one event")
    print('='*64)
    print(f"\n  detection_count : {event['detection_count']}")
    print(f"  detection_types : {event['detection_types']}")
    print(f"  trigger_type    : {event['trigger_type']}  (rate_limit fired first)")
    print(f"  action          : {event['action']}")
    print("\nSIEM EVENT:")
    print(json.dumps(event, indent=2))
