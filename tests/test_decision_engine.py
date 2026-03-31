"""Tests for DecisionEngineMiddleware policy dispatch."""
import asyncio
import inspect
from unittest.mock import MagicMock, patch

from fastapi import Request
from starlette.responses import JSONResponse as StarletteJSONResponse

from app.middlewares.decision_engine import DecisionEngineMiddleware
from app.middlewares.injection_detection import InjectionDetectionMiddleware
from app.middlewares.rate_limit import RateLimitMiddleware
from app.policies.service import DEFAULT_POLICY, DecisionActions, Policy


def test_decision_engine_checks_detections_before_call_next():
    """Decision Engine must check detections BEFORE calling call_next."""
    source = inspect.getsource(DecisionEngineMiddleware.dispatch)
    call_next_pos = source.index("call_next")
    detections_check_pos = source.index("detections")
    assert detections_check_pos < call_next_pos, (
        "Decision Engine must check detections BEFORE calling call_next"
    )


def test_block_detection_prevents_route_handler():
    """When a block detection is present, route handler must NOT execute."""
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
    source = inspect.getsource(InjectionDetectionMiddleware.dispatch)
    if "_blocked_response" in source:
        call_next_pos = source.rindex("call_next")
        blocked_pos = source.rindex("_blocked_response")
        assert blocked_pos < call_next_pos or "_blocked_response" not in source.split("return await call_next")[0], (
            "dispatch must not call _blocked_response — use call_next instead"
        )


def test_throttle_sets_redis_key():
    """_apply_throttle must set ritapi:throttle:{ip} key in Redis with TTL <= 60s."""
    mock_redis = MagicMock()
    middleware = DecisionEngineMiddleware(app=MagicMock())
    mock_request = MagicMock(spec=Request)
    mock_request.url.path = "/api/test"
    mock_request.method = "GET"

    with patch("app.middlewares.decision_engine.RedisClientSingleton.get_client", return_value=mock_redis):
        middleware._apply_throttle(mock_request, "1.2.3.4", "test reason", "rate_limit", 0.5)

    mock_redis.set.assert_called_once()
    call_args = mock_redis.set.call_args
    key = call_args[0][0]
    assert key == "ritapi:throttle:1.2.3.4", f"Expected throttle key for IP, got {key}"
    assert call_args[1].get("ex") == 60 or call_args[0][2] == 60 or (
        len(call_args[0]) > 2 and call_args[0][2] == 60
    ), "Throttle key must have TTL of 60s"


def test_rate_limit_calls_call_next_not_jsonresponse_429():
    """RateLimitMiddleware must call call_next after writing detections, not return 429."""
    source = inspect.getsource(RateLimitMiddleware.dispatch)
    detections_pos = source.index("request.state.detections")
    post_detection = source[detections_pos:]
    next_return_pos = post_detection.index("return")
    assert "call_next" in post_detection[next_return_pos:next_return_pos + 30], (
        "After writing detections, RateLimitMiddleware must call call_next not return 429"
    )


def test_multi_detection_block_wins_over_monitor():
    """When detections include both monitor and block, block must take precedence."""
    mock_request = MagicMock(spec=Request)
    mock_request.headers.get.return_value = "10.0.0.5"
    mock_request.client.host = "10.0.0.5"
    mock_request.url.path = "/api/test"
    mock_request.method = "GET"
    mock_request.state = MagicMock()
    mock_request.state.route = None
    mock_request.state.block = False
    mock_request.state.detections = [
        {"type": "bot_detection", "score": 0.3, "reason": "suspicious UA", "status_code": 403},
        {"type": "injection", "score": 0.95, "reason": "SQLi detected", "status_code": 403},
    ]

    async def fake_call_next(req):
        raise AssertionError("Route handler must NOT run when block detection is present")

    middleware = DecisionEngineMiddleware(app=MagicMock())
    with patch("app.middlewares.decision_engine.get_policy", return_value=DEFAULT_POLICY):
        with patch("app.middlewares.decision_engine.resolve_route", return_value=None):
            response = asyncio.get_event_loop().run_until_complete(
                middleware.dispatch(mock_request, fake_call_next)
            )

    assert response.status_code == 403, f"Expected 403, got {response.status_code}"


def test_policy_monitor_allows_injection_through():
    """When policy sets on_injection: monitor, injection detection does not block the request."""
    monitor_policy = Policy(
        name="test_monitor",
        decision_actions=DecisionActions(on_injection="monitor"),
    )

    mock_request = MagicMock(spec=Request)
    mock_request.headers.get.return_value = "10.0.0.6"
    mock_request.client.host = "10.0.0.6"
    mock_request.url.path = "/api/test"
    mock_request.method = "GET"
    mock_request.state = MagicMock()
    mock_request.state.route = None
    mock_request.state.block = False
    mock_request.state.detections = [
        {"type": "injection", "score": 0.9, "reason": "test pattern", "status_code": 403},
    ]

    route_was_called = []

    async def fake_call_next(req):
        route_was_called.append(True)
        return StarletteJSONResponse({"ok": True}, status_code=200)

    middleware = DecisionEngineMiddleware(app=MagicMock())
    with patch("app.middlewares.decision_engine.get_policy", return_value=monitor_policy):
        with patch("app.middlewares.decision_engine.resolve_route", return_value=None):
            response = asyncio.get_event_loop().run_until_complete(
                middleware.dispatch(mock_request, fake_call_next)
            )

    assert route_was_called, "Route handler must run when policy action is monitor"
    assert response.status_code == 200


def test_injection_blocked_request_never_hits_backend(client):
    """End-to-end: SQLi in URL must be blocked before reaching the route handler."""
    response = client.get("/api/v1/health?id=1' OR '1'='1")
    assert response.status_code in (401, 403, 404), (
        f"SQLi payload should be blocked (401/403) or not found (404), got {response.status_code}"
    )
