"""Tests for HardGateMiddleware.

Post M-7: HardGate never returns a response directly.
It appends detections to request.state.detections and always calls call_next,
delegating all blocking decisions to DecisionEngineMiddleware.
"""
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


def test_blocked_ip_pushes_detection_and_calls_next():
    """Blocked IP must push a 'blocked_ip' detection and still call call_next.

    DecisionEngine (not HardGate) is responsible for the 403 response.
    """
    call_next_called: list[bool] = []

    async def fake_call_next(req: Request) -> Response:
        call_next_called.append(True)
        return Response(status_code=200)

    mock_request = _make_mock_request(ip="10.0.0.99")

    with patch.object(hard_gate_module, "_BLOCKED_IPS", frozenset(["10.0.0.99"])):
        with patch.object(hard_gate_module, "_BLOCKED_ASNS", frozenset()):
            with patch("app.middlewares.hard_gate.HardGateMiddleware._check_yara",
                       return_value=None):
                middleware = HardGateMiddleware(app=MagicMock())
                asyncio.get_event_loop().run_until_complete(
                    middleware.dispatch(mock_request, fake_call_next)
                )

    assert call_next_called, "HardGate must call call_next — DecisionEngine handles the block"
    detections = mock_request.state.detections
    assert any(
        d.get("type") == "blocked_ip" or d.get("detection_type") == "blocked_ip"
        for d in detections
    ), f"Expected 'blocked_ip' detection; got: {detections}"


def test_non_blocked_ip_passes_through():
    """An IP not in the blocked set must reach call_next with no detections."""
    call_next_called: list[bool] = []

    async def fake_call_next(req: Request) -> Response:
        call_next_called.append(True)
        return Response(status_code=200)

    mock_request = _make_mock_request(ip="192.168.1.1")
    mock_request.state.detections = []

    with patch.object(hard_gate_module, "_BLOCKED_IPS", frozenset(["10.0.0.1"])):
        with patch.object(hard_gate_module, "_BLOCKED_ASNS", frozenset()):
            middleware = HardGateMiddleware(app=MagicMock())
            with patch("app.middlewares.hard_gate.HardGateMiddleware._check_yara",
                       return_value=None):
                with patch("app.middlewares.hard_gate.RedisClientSingleton") as mock_rc:
                    mock_rc.get_client.return_value = None  # spike check: fail-open
                    asyncio.get_event_loop().run_until_complete(
                        middleware.dispatch(mock_request, fake_call_next)
                    )

    assert call_next_called, "Route handler must run for non-blocked IP"
    assert mock_request.state.detections == [], (
        "No detections expected for clean non-blocked IP"
    )


def test_empty_blocked_ips_allows_all_traffic():
    """When BLOCKED_IPS is empty, no IP must be blocked (fail-open confirmed)."""
    call_next_called: list[bool] = []

    async def fake_call_next(req: Request) -> Response:
        call_next_called.append(True)
        return Response(status_code=200)

    mock_request = _make_mock_request(ip="5.5.5.5")
    mock_request.state.detections = []

    with patch.object(hard_gate_module, "_BLOCKED_IPS", frozenset()):
        with patch.object(hard_gate_module, "_BLOCKED_ASNS", frozenset()):
            middleware = HardGateMiddleware(app=MagicMock())
            with patch("app.middlewares.hard_gate.HardGateMiddleware._check_yara",
                       return_value=None):
                with patch("app.middlewares.hard_gate.RedisClientSingleton") as mock_rc:
                    mock_rc.get_client.return_value = None
                    asyncio.get_event_loop().run_until_complete(
                        middleware.dispatch(mock_request, fake_call_next)
                    )

    assert call_next_called, "Fail-open: empty BLOCKED_IPS must allow all traffic"
    assert mock_request.state.detections == []


def test_blocked_ip_detection_has_correct_fields():
    """Blocked IP detection must carry type, score=1.0, status_code=403, source=hard_gate."""
    async def fake_call_next(req: Request) -> Response:
        return Response(status_code=200)

    mock_request = _make_mock_request(ip="172.16.0.1")
    mock_request.state.detections = []

    with patch.object(hard_gate_module, "_BLOCKED_IPS", frozenset(["172.16.0.1"])):
        with patch.object(hard_gate_module, "_BLOCKED_ASNS", frozenset()):
            with patch("app.middlewares.hard_gate.HardGateMiddleware._check_yara",
                       return_value=None):
                with patch("app.middlewares.hard_gate.RedisClientSingleton") as mock_rc:
                    mock_rc.get_client.return_value = None
                    middleware = HardGateMiddleware(app=MagicMock())
                    asyncio.get_event_loop().run_until_complete(
                        middleware.dispatch(mock_request, fake_call_next)
                    )

    detections = mock_request.state.detections
    assert len(detections) == 1
    d = detections[0]
    assert d["type"] == "blocked_ip"
    assert d["score"] == 1.0
    assert d["status_code"] == 403
    assert d["source"] == "hard_gate"


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


def test_hard_gate_never_returns_jsonresponse_directly():
    """HardGate dispatch source must not contain a direct JSONResponse return.

    All blocking must be delegated to DecisionEngine via append_detection.
    """
    import inspect

    import app.middlewares.hard_gate as hg_mod

    src = inspect.getsource(hg_mod.HardGateMiddleware.dispatch)
    assert "return JSONResponse" not in src, (
        "HardGate.dispatch must not return JSONResponse directly — "
        "append_detection() + call_next() is the correct pattern (M-7)"
    )
