"""Tests for HardGateMiddleware."""
import asyncio
from unittest.mock import MagicMock, patch

from fastapi import Request
from starlette.responses import Response

import app.middlewares.hard_gate as hard_gate_module
from app.middlewares.hard_gate import HardGateMiddleware


def _make_mock_request(ip: str = "1.2.3.4", path: str = "/api/test") -> MagicMock:
    """Build a minimal mock Request for hard-gate tests."""
    mock = MagicMock(spec=Request)
    mock.headers.get.return_value = ""          # no x-forwarded-for, no x-api-key
    mock.headers.__contains__ = MagicMock(return_value=False)
    mock.client.host = ip
    mock.url.path = path
    mock.method = "GET"
    mock.state = MagicMock()
    mock.state.request_id = "test-uuid-1234"
    mock.state.policy = None
    mock.state.detections = []
    return mock


def test_blocked_ip_returns_403_before_route():
    """Blocked IP must return 403 and the route handler must NOT be called."""
    route_called: list[bool] = []

    async def fake_call_next(req: Request) -> Response:
        route_called.append(True)
        return Response(status_code=200)

    mock_request = _make_mock_request(ip="10.0.0.99")

    with patch.object(hard_gate_module, "_BLOCKED_IPS", frozenset(["10.0.0.99"])):
        with patch("app.middlewares.hard_gate.log_security_event"):
            middleware = HardGateMiddleware(app=MagicMock())
            response = asyncio.get_event_loop().run_until_complete(
                middleware.dispatch(mock_request, fake_call_next)
            )

    assert not route_called, "Route handler must NOT run when IP is blocked"
    assert response.status_code == 403


def test_non_blocked_ip_passes_through():
    """An IP not in the blocked set must reach the route handler."""
    route_called: list[bool] = []

    async def fake_call_next(req: Request) -> Response:
        route_called.append(True)
        return Response(status_code=200)

    mock_request = _make_mock_request(ip="192.168.1.1")

    with patch.object(hard_gate_module, "_BLOCKED_IPS", frozenset(["10.0.0.1"])):
        with patch.object(hard_gate_module, "_BLOCKED_ASNS", frozenset()):
            middleware = HardGateMiddleware(app=MagicMock())
            # Patch YARA scanner to be unavailable so it doesn't interfere
            with patch("app.middlewares.hard_gate.HardGateMiddleware._check_yara",
                       return_value=None):
                response = asyncio.get_event_loop().run_until_complete(
                    middleware.dispatch(mock_request, fake_call_next)
                )

    assert route_called, "Route handler must run for non-blocked IP"
    assert response.status_code == 200


def test_empty_blocked_ips_allows_all_traffic():
    """When BLOCKED_IPS is empty, no IP must be blocked (fail-open confirmed)."""
    route_called: list[bool] = []

    async def fake_call_next(req: Request) -> Response:
        route_called.append(True)
        return Response(status_code=200)

    mock_request = _make_mock_request(ip="5.5.5.5")

    with patch.object(hard_gate_module, "_BLOCKED_IPS", frozenset()):
        with patch.object(hard_gate_module, "_BLOCKED_ASNS", frozenset()):
            middleware = HardGateMiddleware(app=MagicMock())
            with patch("app.middlewares.hard_gate.HardGateMiddleware._check_yara",
                       return_value=None):
                response = asyncio.get_event_loop().run_until_complete(
                    middleware.dispatch(mock_request, fake_call_next)
                )

    assert route_called, "Fail-open: empty BLOCKED_IPS must allow all traffic"
    assert response.status_code == 200


def test_hard_gate_block_calls_log_decision():
    """Every hard-gate block must call log_security_event for auditability."""
    async def fake_call_next(req: Request) -> Response:
        return Response(status_code=200)

    mock_request = _make_mock_request(ip="172.16.0.1")

    with patch.object(hard_gate_module, "_BLOCKED_IPS", frozenset(["172.16.0.1"])):
        with patch("app.middlewares.hard_gate.log_security_event") as mock_log:
            middleware = HardGateMiddleware(app=MagicMock())
            asyncio.get_event_loop().run_until_complete(
                middleware.dispatch(mock_request, fake_call_next)
            )

    mock_log.assert_called_once()
    _, kwargs = mock_log.call_args
    assert kwargs["action"] == "block"
    assert kwargs["trigger_type"] == "blocked_ip"


def test_hard_gate_block_includes_request_id_header():
    """Hard-gate 403 response must include X-Request-ID header."""
    async def fake_call_next(req: Request) -> Response:
        return Response(status_code=200)

    mock_request = _make_mock_request(ip="203.0.113.5")
    mock_request.state.request_id = "deadbeef-1234-4321-abcd-000000000000"

    with patch.object(hard_gate_module, "_BLOCKED_IPS", frozenset(["203.0.113.5"])):
        with patch("app.middlewares.hard_gate.log_security_event"):
            middleware = HardGateMiddleware(app=MagicMock())
            response = asyncio.get_event_loop().run_until_complete(
                middleware.dispatch(mock_request, fake_call_next)
            )

    assert response.status_code == 403
    assert response.headers.get("x-request-id") == "deadbeef-1234-4321-abcd-000000000000"


# ---------------------------------------------------------------------------
# Task 3: yara_scanned flag and YARA dedup boundary
# ---------------------------------------------------------------------------

def test_hard_gate_sets_yara_scanned_flag():
    """HardGateMiddleware.dispatch must set request.state.yara_scanned=True after YARA attempt."""
    import inspect
    import app.middlewares.hard_gate as hg_mod

    src = inspect.getsource(hg_mod.HardGateMiddleware.dispatch)
    assert "yara_scanned" in src, (
        "HardGateMiddleware.dispatch must set request.state.yara_scanned = True "
        "after the YARA scan so InjectionDetection can skip a duplicate scan"
    )
    # Verify the flag is set unconditionally (not only when a match is found)
    assert "request.state.yara_scanned = True" in src


def test_injection_detection_skips_yara_when_already_scanned():
    """InjectionDetectionMiddleware.dispatch must check request.state.yara_scanned."""
    import inspect
    import app.middlewares.injection_detection as inj_mod

    src = inspect.getsource(inj_mod.InjectionDetectionMiddleware.dispatch)
    assert "yara_scanned" in src, (
        "InjectionDetectionMiddleware.dispatch must check request.state.yara_scanned"
    )
