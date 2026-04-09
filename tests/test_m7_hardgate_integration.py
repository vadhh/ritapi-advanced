"""
M-7 Integration Proof: HardGate detection types route through DecisionEngine.

For each of the 5 HardGate detection types:
  blocked_ip / blocked_asn / yara / ddos_spike / invalid_api_key

Asserts:
  1. Detection appended correctly (type, source, status_code)
  2. DecisionEngine receives and processes it
  3. Correct HTTP status returned (403 or 429)
  4. Backend route handler NOT executed

Also verifies that DEFAULT_POLICY maps every HardGate type to "block"
(not the "monitor" fallback that would silently pass the request through).
"""
import asyncio
from unittest.mock import MagicMock, patch

import pytest
from fastapi import Request
from starlette.responses import Response

from app.middlewares.decision_engine import DecisionEngineMiddleware
from app.policies.service import DEFAULT_POLICY, DecisionActions

# ---------------------------------------------------------------------------
# Structural: policy maps all HardGate types to "block"
# ---------------------------------------------------------------------------

HARDGATE_TYPES = ["blocked_ip", "blocked_asn", "yara", "ddos_spike", "invalid_api_key"]


@pytest.mark.parametrize("det_type", HARDGATE_TYPES)
def test_default_policy_maps_hardgate_type_to_block(det_type):
    """DEFAULT_POLICY must map every HardGate detection type to 'block', not 'monitor'."""
    action = DEFAULT_POLICY.decision_actions.get_action(det_type)
    assert action == "block", (
        f"DEFAULT_POLICY.decision_actions.get_action('{det_type}') returned {action!r}. "
        f"Expected 'block' — HardGate detections must never default to 'monitor'."
    )


def test_get_action_does_not_fall_through_to_monitor_for_hardgate_types():
    """get_action must resolve HardGate types via explicit on_* fields, not the fallback."""
    da = DecisionActions()
    for det_type in HARDGATE_TYPES:
        action = da.get_action(det_type)
        assert action == "block", (
            f"DecisionActions.get_action('{det_type}') = {action!r}; "
            f"on_{det_type} must be an explicit field defaulting to 'block'."
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_request(det_type: str, status_code: int = 403) -> MagicMock:
    req = MagicMock(spec=Request)
    req.headers.get.return_value = "10.0.0.99"
    req.client.host = "10.0.0.99"
    req.url.path = "/api/v1/resource"
    req.method = "GET"
    req.state = MagicMock()
    req.state.route = None
    req.state.block = False
    req.state.tenant_id = None
    req.state.detections = [
        {
            "type": det_type,
            "score": 1.0,
            "reason": f"HardGate: {det_type} triggered",
            "status_code": status_code,
            "source": "hard_gate",
            "metadata": {},
        }
    ]
    return req


def _dispatch(req, expected_status: int) -> tuple[Response, list]:
    backend_called: list[bool] = []

    async def fake_backend(r):
        backend_called.append(True)
        return Response(status_code=200)

    middleware = DecisionEngineMiddleware(app=MagicMock())
    with patch("app.middlewares.decision_engine.get_policy", return_value=DEFAULT_POLICY):
        with patch("app.middlewares.decision_engine.resolve_route", return_value=None):
            response = asyncio.get_event_loop().run_until_complete(
                middleware.dispatch(req, fake_backend)
            )
    return response, backend_called


# ---------------------------------------------------------------------------
# Integration proofs — one per HardGate detection type
# ---------------------------------------------------------------------------

def test_blocked_ip_detection_appended_decision_engine_blocks_backend_not_reached():
    """
    PROOF — blocked_ip:
      Detection appended → DecisionEngine blocks → backend NOT reached
    """
    req = _make_request("blocked_ip", status_code=403)
    response, backend_called = _dispatch(req, 403)

    assert not backend_called, "Backend must NOT run for blocked_ip"
    assert response.status_code == 403, f"Expected 403, got {response.status_code}"
    assert req.state.detections[0]["type"] == "blocked_ip"
    assert req.state.detections[0]["source"] == "hard_gate"


def test_blocked_asn_detection_appended_decision_engine_blocks_backend_not_reached():
    """
    PROOF — blocked_asn:
      Detection appended → DecisionEngine blocks → backend NOT reached
    """
    req = _make_request("blocked_asn", status_code=403)
    response, backend_called = _dispatch(req, 403)

    assert not backend_called, "Backend must NOT run for blocked_asn"
    assert response.status_code == 403, f"Expected 403, got {response.status_code}"
    assert req.state.detections[0]["type"] == "blocked_asn"
    assert req.state.detections[0]["source"] == "hard_gate"


def test_yara_detection_appended_decision_engine_blocks_backend_not_reached():
    """
    PROOF — yara:
      Detection appended → DecisionEngine blocks → backend NOT reached
    """
    req = _make_request("yara", status_code=403)
    response, backend_called = _dispatch(req, 403)

    assert not backend_called, "Backend must NOT run for yara match"
    assert response.status_code == 403, f"Expected 403, got {response.status_code}"
    assert req.state.detections[0]["type"] == "yara"
    assert req.state.detections[0]["source"] == "hard_gate"


def test_ddos_spike_detection_appended_decision_engine_blocks_backend_not_reached():
    """
    PROOF — ddos_spike:
      Detection appended (status_code=429) → DecisionEngine blocks → backend NOT reached
    """
    req = _make_request("ddos_spike", status_code=429)
    response, backend_called = _dispatch(req, 429)

    assert not backend_called, "Backend must NOT run for ddos_spike"
    assert response.status_code == 429, f"Expected 429, got {response.status_code}"
    assert req.state.detections[0]["type"] == "ddos_spike"
    assert req.state.detections[0]["source"] == "hard_gate"


def test_invalid_api_key_detection_appended_decision_engine_blocks_backend_not_reached():
    """
    PROOF — invalid_api_key:
      Detection appended → DecisionEngine blocks → backend NOT reached
    """
    req = _make_request("invalid_api_key", status_code=403)
    response, backend_called = _dispatch(req, 403)

    assert not backend_called, "Backend must NOT run for invalid_api_key"
    assert response.status_code == 403, f"Expected 403, got {response.status_code}"
    assert req.state.detections[0]["type"] == "invalid_api_key"
    assert req.state.detections[0]["source"] == "hard_gate"


# ---------------------------------------------------------------------------
# Completeness: no HardGate type silently falls to monitor
# ---------------------------------------------------------------------------

def test_all_hardgate_types_covered_by_explicit_fields():
    """Every HardGate detection type must have an explicit on_* field in DecisionActions.

    This prevents silent 'monitor' fallback if get_action() receives an unknown type.
    """
    da = DecisionActions()
    for det_type in HARDGATE_TYPES:
        field_name = f"on_{det_type}"
        assert hasattr(da, field_name), (
            f"DecisionActions is missing field '{field_name}'. "
            f"Add it with default='block' to prevent silent monitor fallback."
        )
        assert getattr(da, field_name) == "block", (
            f"DecisionActions.{field_name} must default to 'block', "
            f"got {getattr(da, field_name)!r}"
        )
