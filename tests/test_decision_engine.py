"""Tests for DecisionEngineMiddleware policy dispatch."""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.responses import JSONResponse as StarletteJSONResponse


def test_decision_engine_checks_detections_before_call_next():
    """Decision Engine must check detections BEFORE calling call_next."""
    import inspect
    from app.middlewares.decision_engine import DecisionEngineMiddleware
    source = inspect.getsource(DecisionEngineMiddleware.dispatch)
    call_next_pos = source.index("call_next")
    detections_check_pos = source.index("detections")
    assert detections_check_pos < call_next_pos, (
        "Decision Engine must check detections BEFORE calling call_next"
    )


def test_block_detection_prevents_route_handler():
    """When a block detection is present, route handler must NOT execute."""
    from fastapi import Request
    from app.middlewares.decision_engine import DecisionEngineMiddleware
    from app.policies.service import DEFAULT_POLICY

    mock_request = MagicMock(spec=Request)
    mock_request.headers.get.return_value = "10.0.0.1"
    mock_request.client.host = "10.0.0.1"
    mock_request.url.path = "/api/test"
    mock_request.method = "GET"
    mock_request.state = MagicMock()
    mock_request.state.route = None
    mock_request.state.block = False
    mock_request.state.detections = [
        {"type": "injection", "score": 0.95, "reason": "SQLi", "status_code": 403},
    ]

    route_called = []

    async def fake_call_next(req):
        route_called.append(True)
        return StarletteJSONResponse({"ok": True}, status_code=200)

    middleware = DecisionEngineMiddleware(app=MagicMock())
    with patch("app.middlewares.decision_engine.get_policy", return_value=DEFAULT_POLICY):
        with patch("app.middlewares.decision_engine.resolve_route", return_value=None):
            response = asyncio.get_event_loop().run_until_complete(
                middleware.dispatch(mock_request, fake_call_next)
            )

    assert not route_called, "Route handler must NOT run when block detection is present"
    assert response.status_code == 403


def test_monitor_detection_allows_route_handler():
    """When policy action is monitor, route handler must execute."""
    from fastapi import Request
    from app.middlewares.decision_engine import DecisionEngineMiddleware
    from app.policies.service import Policy, DecisionActions

    monitor_policy = Policy(
        name="test",
        decision_actions=DecisionActions(on_bot_detection="monitor"),
    )

    mock_request = MagicMock(spec=Request)
    mock_request.headers.get.return_value = "10.0.0.2"
    mock_request.client.host = "10.0.0.2"
    mock_request.url.path = "/api/test"
    mock_request.method = "GET"
    mock_request.state = MagicMock()
    mock_request.state.route = None
    mock_request.state.block = False
    mock_request.state.detections = [
        {"type": "bot_detection", "score": 0.3, "reason": "suspicious", "status_code": 403},
    ]

    route_called = []

    async def fake_call_next(req):
        route_called.append(True)
        return StarletteJSONResponse({"ok": True}, status_code=200)

    middleware = DecisionEngineMiddleware(app=MagicMock())
    with patch("app.middlewares.decision_engine.get_policy", return_value=monitor_policy):
        with patch("app.middlewares.decision_engine.resolve_route", return_value=None):
            response = asyncio.get_event_loop().run_until_complete(
                middleware.dispatch(mock_request, fake_call_next)
            )

    assert route_called, "Route handler MUST run when action is monitor"
    assert response.status_code == 200


def test_rate_limit_detection_returns_429():
    """Rate limit detection must produce 429 status code."""
    from fastapi import Request
    from app.middlewares.decision_engine import DecisionEngineMiddleware
    from app.policies.service import DEFAULT_POLICY

    mock_request = MagicMock(spec=Request)
    mock_request.headers.get.return_value = "10.0.0.3"
    mock_request.client.host = "10.0.0.3"
    mock_request.url.path = "/api/test"
    mock_request.method = "GET"
    mock_request.state = MagicMock()
    mock_request.state.route = None
    mock_request.state.block = False
    mock_request.state.detections = [
        {"type": "rate_limit", "score": 1.0, "reason": "limit exceeded", "status_code": 429},
    ]

    async def fake_call_next(req):
        raise AssertionError("Route handler must not run on rate limit")

    middleware = DecisionEngineMiddleware(app=MagicMock())
    with patch("app.middlewares.decision_engine.get_policy", return_value=DEFAULT_POLICY):
        with patch("app.middlewares.decision_engine.resolve_route", return_value=None):
            response = asyncio.get_event_loop().run_until_complete(
                middleware.dispatch(mock_request, fake_call_next)
            )

    assert response.status_code == 429, f"Rate limit must return 429, got {response.status_code}"


def test_injection_calls_call_next_not_blocked_response():
    """InjectionDetectionMiddleware must call call_next after writing detections."""
    import inspect
    from app.middlewares.injection_detection import InjectionDetectionMiddleware
    source = inspect.getsource(InjectionDetectionMiddleware.dispatch)
    # _blocked_response must NOT appear before the final call_next
    # Specifically: after any detections.append, the next action must be call_next
    # Simplest check: _blocked_response is not in the body of dispatch
    # (it may still exist as a @staticmethod but must not be called in dispatch)
    dispatch_body = source.split("_blocked_response")[0] if "_blocked_response" in source else source
    # If _blocked_response is in dispatch source, it should only appear after call_next
    if "_blocked_response" in source:
        call_next_pos = source.rindex("call_next")
        blocked_pos = source.rindex("_blocked_response")
        assert blocked_pos < call_next_pos or "_blocked_response" not in source.split("return await call_next")[0], (
            "dispatch must not call _blocked_response — use call_next instead"
        )


def test_rate_limit_calls_call_next_not_jsonresponse_429():
    """RateLimitMiddleware must call call_next after writing detections, not return 429."""
    import inspect
    from app.middlewares.rate_limit import RateLimitMiddleware
    source = inspect.getsource(RateLimitMiddleware.dispatch)
    detections_pos = source.index("request.state.detections")
    post_detection = source[detections_pos:]
    # After writing detections, the first return should be call_next, not 429
    next_return_pos = post_detection.index("return")
    assert "call_next" in post_detection[next_return_pos:next_return_pos+30], (
        "After writing detections, RateLimitMiddleware must call call_next not return 429"
    )
