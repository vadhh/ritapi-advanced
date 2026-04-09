"""
M-7 Compliance Tests: ZERO direct blocking outside DecisionEngine.

Every block (403/429) must flow through DecisionEngine.
Outer middlewares push detections; DecisionEngine is the sole authority
that returns block responses.

Assertions per test:
  - 403/429 returned
  - DecisionEngine triggered (processes detection)
  - Backend (route handler) NOT executed
"""
import asyncio
import inspect
from unittest.mock import MagicMock, patch

import pytest
from fastapi import Request
from starlette.responses import JSONResponse as StarletteJSONResponse
from starlette.responses import Response

from app.middlewares.decision_engine import DecisionEngineMiddleware
from app.middlewares.detection_schema import append_detection, ensure_detections_container
from app.middlewares.hard_gate import HardGateMiddleware
from app.middlewares.injection_detection import InjectionDetectionMiddleware
from app.policies.service import DEFAULT_POLICY


# ---------------------------------------------------------------------------
# Structural / static assertions
# ---------------------------------------------------------------------------

def test_hard_gate_dispatch_has_no_direct_jsonresponse_return():
    """HardGate.dispatch must never return JSONResponse directly (M-7)."""
    src = inspect.getsource(HardGateMiddleware.dispatch)
    assert "return JSONResponse" not in src, (
        "HardGate.dispatch returns JSONResponse directly — violates M-7. "
        "Use append_detection() + call_next() instead."
    )


def test_injection_detection_dispatch_has_no_direct_jsonresponse_return():
    """InjectionDetectionMiddleware.dispatch must never return JSONResponse directly (M-7)."""
    src = inspect.getsource(InjectionDetectionMiddleware.dispatch)
    assert "return JSONResponse" not in src, (
        "InjectionDetectionMiddleware.dispatch returns JSONResponse directly — violates M-7."
    )


def test_no_middleware_file_returns_403_directly():
    """No middleware module may contain 'return JSONResponse(... status_code=403'."""
    import glob
    import os

    middleware_dir = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "app", "middlewares"
    )
    offenders = []
    for path in glob.glob(os.path.join(middleware_dir, "*.py")):
        with open(path) as f:
            src = f.read()
        # decision_engine.py is the ONLY file allowed to return JSONResponse
        if os.path.basename(path) == "decision_engine.py":
            continue
        if "return JSONResponse" in src and "status_code=403" in src:
            # Check they're on the same logical line (rough proximity check)
            lines = src.splitlines()
            for i, line in enumerate(lines):
                if "return JSONResponse" in line:
                    # Look at the next 5 lines for status_code=403
                    block = "\n".join(lines[i:i+5])
                    if "status_code=403" in block:
                        offenders.append(f"{os.path.basename(path)}:{i+1}")
    assert not offenders, (
        f"Middleware files return 403 directly (M-7 violation): {offenders}"
    )


# ---------------------------------------------------------------------------
# Unit test: injection detection routes through DecisionEngine
# ---------------------------------------------------------------------------

def test_injection_block_goes_through_decision_engine():
    """
    When InjectionDetection fires:
      - detection is appended to request.state.detections
      - call_next is called (reaching DecisionEngine)
      - DecisionEngine returns 403
      - backend route handler NOT executed
    """
    backend_called: list[bool] = []

    # Simulate DecisionEngine: reads detections, blocks if found
    async def fake_decision_engine(req: Request) -> Response:
        detections = getattr(req.state, "detections", [])
        if detections:
            return StarletteJSONResponse(
                {"error": "Forbidden", "detail": detections[0].get("reason", "")},
                status_code=403,
            )
        backend_called.append(True)
        return Response(status_code=200)

    mock_request = MagicMock(spec=Request)
    mock_request.headers.get = MagicMock(side_effect=lambda k, default="": {
        "user-agent": "sqlmap/1.0",
    }.get(k, default))
    mock_request.client.host = "1.2.3.4"
    mock_request.url = MagicMock()
    mock_request.url.path = "/api/data"
    mock_request.url.__str__ = MagicMock(return_value="http://localhost/api/data")
    mock_request.method = "GET"
    mock_request.state = MagicMock()
    mock_request.state.detections = []

    middleware = InjectionDetectionMiddleware(app=MagicMock())
    response = asyncio.get_event_loop().run_until_complete(
        middleware.dispatch(mock_request, fake_decision_engine)
    )

    assert not backend_called, "Backend must NOT execute when injection detected"
    assert response.status_code == 403, f"Expected 403, got {response.status_code}"
    detections = mock_request.state.detections
    assert len(detections) >= 1, "At least one detection must be appended"
    assert detections[0]["type"] == "injection"
    assert detections[0]["source"] == "injection_detection"


# ---------------------------------------------------------------------------
# Unit test: hard_gate detection routes through DecisionEngine
# ---------------------------------------------------------------------------

def test_hard_gate_block_goes_through_decision_engine():
    """
    When HardGate fires (blocked IP):
      - detection is appended to request.state.detections
      - call_next is called (reaching DecisionEngine)
      - DecisionEngine returns 403
      - backend route handler NOT executed
    """
    import app.middlewares.hard_gate as hg_mod

    backend_called: list[bool] = []

    # Simulate DecisionEngine: reads detections, blocks if found
    async def fake_decision_engine(req: Request) -> Response:
        detections = getattr(req.state, "detections", [])
        if detections:
            return StarletteJSONResponse(
                {"error": "Forbidden", "detail": detections[0].get("reason", "")},
                status_code=403,
            )
        backend_called.append(True)
        return Response(status_code=200)

    mock_request = MagicMock(spec=Request)
    mock_request.headers.get.return_value = ""
    mock_request.headers.__contains__ = MagicMock(return_value=False)
    mock_request.client.host = "10.0.0.99"
    mock_request.url.path = "/api/data"
    mock_request.method = "GET"
    mock_request.state = MagicMock()
    mock_request.state.detections = []
    mock_request.state.policy = None

    with patch.object(hg_mod, "_BLOCKED_IPS", frozenset(["10.0.0.99"])):
        with patch.object(hg_mod, "_BLOCKED_ASNS", frozenset()):
            with patch("app.middlewares.hard_gate.RedisClientSingleton") as mock_rc:
                mock_rc.get_client.return_value = None  # skip spike check
                middleware = HardGateMiddleware(app=MagicMock())
                with patch.object(middleware, "_check_yara", return_value=None):
                    response = asyncio.get_event_loop().run_until_complete(
                        middleware.dispatch(mock_request, fake_decision_engine)
                    )

    assert not backend_called, "Backend must NOT execute when IP is blocked"
    assert response.status_code == 403, f"Expected 403, got {response.status_code}"
    detections = mock_request.state.detections
    assert len(detections) >= 1
    assert detections[0]["type"] == "blocked_ip"
    assert detections[0]["source"] == "hard_gate"


# ---------------------------------------------------------------------------
# Integration test: full decision engine blocks injection, backend never runs
# ---------------------------------------------------------------------------

def test_decision_engine_blocks_injection_detection_before_backend():
    """
    DecisionEngine must check detections BEFORE calling the route handler,
    so a blocked injection never reaches the backend.
    """
    backend_called: list[bool] = []

    async def fake_backend(req: Request) -> Response:
        backend_called.append(True)
        return Response(status_code=200)

    mock_request = MagicMock(spec=Request)
    mock_request.headers.get.return_value = "10.0.0.1"
    mock_request.client.host = "10.0.0.1"
    mock_request.url.path = "/api/test"
    mock_request.method = "GET"
    mock_request.state = MagicMock()
    mock_request.state.route = None
    mock_request.state.block = False
    mock_request.state.detections = [
        {
            "type": "injection",
            "score": 0.95,
            "reason": "SQLi pattern detected",
            "status_code": 403,
            "source": "injection_detection",
            "metadata": {},
        }
    ]

    decision_engine_ran: list[bool] = []
    original_block_response = DecisionEngineMiddleware._block_response

    def tracking_block_response(self, *args, **kwargs):
        decision_engine_ran.append(True)
        return original_block_response(self, *args, **kwargs)

    middleware = DecisionEngineMiddleware(app=MagicMock())
    with patch("app.middlewares.decision_engine.get_policy", return_value=DEFAULT_POLICY):
        with patch("app.middlewares.decision_engine.resolve_route", return_value=None):
            with patch.object(DecisionEngineMiddleware, "_block_response", tracking_block_response):
                response = asyncio.get_event_loop().run_until_complete(
                    middleware.dispatch(mock_request, fake_backend)
                )

    assert not backend_called, "Backend must NOT run when DecisionEngine blocks"
    assert decision_engine_ran, "DecisionEngine _block_response must be called"
    assert response.status_code == 403
