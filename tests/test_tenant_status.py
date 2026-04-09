"""
Tenant status tests.

SIEM events must carry:
  - tenant_id: null + tenant_status: "unauthenticated" for pre-auth / failed-auth requests
  - tenant_id: "<real>" + tenant_status: "authenticated" for verified credentials
"""
import asyncio
import json
from unittest.mock import MagicMock, patch

from fastapi import Request
from starlette.responses import JSONResponse as StarletteJSONResponse

from app.middlewares.decision_engine import DecisionEngineMiddleware
from app.policies.service import DecisionActions, Policy
from app.security.security_event_logger import log_security_event
from app.security.siem_export import build_siem_event

# ---------------------------------------------------------------------------
# Unit: build_siem_event carries tenant_status
# ---------------------------------------------------------------------------

def test_build_siem_event_includes_tenant_status_authenticated():
    event = build_siem_event(
        action="block",
        status_code=403,
        timestamp="2026-04-08T00:00:00+00:00",
        request_id="test-req-id",
        tenant_id="acme",
        tenant_status="authenticated",
        source_ip="1.2.3.4",
        method="GET",
        route="/api/test",
        reason="injection",
        trigger_type="injection",
        trigger_source="injection_detection",
    )
    assert event["tenant_id"] == "acme"
    assert event["tenant_status"] == "authenticated"


def test_build_siem_event_includes_tenant_status_unauthenticated():
    event = build_siem_event(
        action="block",
        status_code=401,
        timestamp="2026-04-08T00:00:00+00:00",
        request_id="test-req-id",
        tenant_id=None,
        tenant_status="unauthenticated",
        source_ip="1.2.3.4",
        method="GET",
        route="/api/test",
        reason="auth_failure",
        trigger_type="auth_failure",
        trigger_source="auth",
    )
    assert event["tenant_id"] is None
    assert event["tenant_status"] == "unauthenticated"


def test_build_siem_event_tenant_id_null_is_json_serializable():
    """tenant_id=None must serialize to JSON null, not the string 'None'."""
    event = build_siem_event(
        action="block",
        status_code=401,
        timestamp="2026-04-08T00:00:00+00:00",
        request_id="test-req-id",
        tenant_id=None,
        tenant_status="unauthenticated",
        source_ip="1.2.3.4",
        method="GET",
        route="/api/test",
        reason="no credential",
        trigger_type="auth_failure",
        trigger_source="auth",
    )
    serialized = json.dumps(event)
    assert '"tenant_id": null' in serialized
    assert '"tenant_status": "unauthenticated"' in serialized


# ---------------------------------------------------------------------------
# Integration: log_security_event with authenticated vs unauthenticated state
# ---------------------------------------------------------------------------

def _make_request(tenant_id_on_state=None) -> MagicMock:
    req = MagicMock(spec=Request)
    req.headers.get.return_value = "10.0.0.1"
    req.client.host = "10.0.0.1"
    req.url.path = "/api/v1/resource"
    req.method = "GET"
    req.state = MagicMock()
    req.state.request_id = "test-req-corr-id"
    req.state.tenant_id = tenant_id_on_state
    req.state.started_at = None
    req.state.detections = []
    req.state.perf = {}
    return req


def test_log_security_event_unauthenticated_emits_null_tenant(capsys):
    """When request has no tenant_id on state, log must emit tenant_id=null."""
    req = _make_request(tenant_id_on_state=None)

    log_security_event(
        req,
        action="block",
        status_code=401,
        reason="no credential",
        trigger_type="auth_failure",
        trigger_source="auth",
    )

    raw = capsys.readouterr().out.strip()
    event = json.loads(raw)
    assert event["tenant_id"] is None, (
        f"Unauthenticated request must log tenant_id=null, got {event['tenant_id']!r}"
    )
    assert event["tenant_status"] == "unauthenticated", (
        f"Unauthenticated request must log tenant_status='unauthenticated', got {event['tenant_status']!r}"
    )


def test_log_security_event_authenticated_emits_real_tenant(capsys):
    """When request has tenant_id on state, log must emit that tenant_id."""
    req = _make_request(tenant_id_on_state="acme-corp")

    log_security_event(
        req,
        action="allow",
        status_code=200,
        reason="clean request",
        trigger_type="none",
        trigger_source="decision_engine",
    )

    raw = capsys.readouterr().out.strip()
    event = json.loads(raw)
    assert event["tenant_id"] == "acme-corp", (
        f"Authenticated request must log real tenant_id, got {event['tenant_id']!r}"
    )
    assert event["tenant_status"] == "authenticated", (
        f"Authenticated request must log tenant_status='authenticated', got {event['tenant_status']!r}"
    )


def test_log_security_event_default_string_tenant_is_authenticated(capsys):
    """A request with tenant_id='default' is considered authenticated (real tenant name)."""
    req = _make_request(tenant_id_on_state="default")

    log_security_event(
        req,
        action="allow",
        status_code=200,
        reason="clean request",
        trigger_type="none",
        trigger_source="decision_engine",
    )

    raw = capsys.readouterr().out.strip()
    event = json.loads(raw)
    # "default" is a valid tenant name — must not be treated as unauthenticated
    assert event["tenant_id"] == "default"
    assert event["tenant_status"] == "authenticated"


# ---------------------------------------------------------------------------
# Integration: full DecisionEngine flow captures tenant_status in SIEM event
# ---------------------------------------------------------------------------

def test_decision_engine_block_emits_unauthenticated_tenant_status(capsys):
    """When auth fails, the blocked SIEM event must show tenant_status=unauthenticated."""
    req = _make_request(tenant_id_on_state=None)  # auth not yet verified
    req.state.block = False
    req.state.route = None
    req.state.detections = [{
        "type": "auth_failure",
        "score": 1.0,
        "reason": "No valid credential",
        "status_code": 401,
        "source": "auth",
        "metadata": {},
    }]

    policy = Policy(name="default", decision_actions=DecisionActions(on_auth_failure="block"))
    middleware = DecisionEngineMiddleware(app=MagicMock())

    with patch("app.middlewares.decision_engine.get_policy", return_value=policy):
        with patch("app.middlewares.decision_engine.resolve_route", return_value=None):
            asyncio.get_event_loop().run_until_complete(
                middleware.dispatch(req, lambda r: StarletteJSONResponse({}, 200))
            )

    raw = capsys.readouterr().out.strip()
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    assert lines, "Expected at least one SIEM event"
    event = json.loads(lines[0])
    assert event["tenant_id"] is None, (
        f"Auth failure event must have tenant_id=null, got {event['tenant_id']!r}"
    )
    assert event["tenant_status"] == "unauthenticated"
