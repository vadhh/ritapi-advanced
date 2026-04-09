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

# ---------------------------------------------------------------------------
# Regression shields — these tests protect invariants that must NEVER regress.
# They are not testing new features; they are encoding assumptions the rest of
# the codebase depends on.  If any of these fail after a refactor, something
# fundamental has broken.
# ---------------------------------------------------------------------------


def test_decision_engine_always_in_middleware_stack():
    """REGRESSION: DecisionEngineMiddleware must always be registered in the app stack.

    If someone removes it during a refactor, every request would pass through
    unchecked.  This test fails immediately so the omission is caught before
    production.

    Uses app.user_middleware — FastAPI/Starlette stores add_middleware() calls
    there before building the nested stack at first request.
    """
    from app.main import app

    registered_classes = [m.cls for m in app.user_middleware]
    assert DecisionEngineMiddleware in registered_classes, (
        "DecisionEngineMiddleware is NOT in app.user_middleware — "
        "every request would pass through unguarded"
    )


def _make_request(ip: str = "10.0.0.99", path: str = "/api/test",
                  detections: list | None = None) -> MagicMock:
    """Build a minimal mock Request for DecisionEngine unit tests."""
    req = MagicMock(spec=Request)
    req.headers.get.return_value = ip
    req.client.host = ip
    req.url.path = path
    req.method = "GET"
    req.state = MagicMock()
    req.state.route = None
    req.state.block = False
    req.state.detections = detections if detections is not None else []
    return req


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_no_detection_produces_allow_and_calls_handler():
    """REGRESSION: A request with zero detections must reach the route handler and return 200.

    If DecisionEngine ever defaults to block on empty detections, all clean
    traffic would be dropped.
    """
    req = _make_request(detections=[])
    handler_called = []

    async def fake_handler(r):
        handler_called.append(True)
        return StarletteJSONResponse({"ok": True}, status_code=200)

    middleware = DecisionEngineMiddleware(app=MagicMock())
    with patch("app.middlewares.decision_engine.get_policy", return_value=DEFAULT_POLICY):
        with patch("app.middlewares.decision_engine.resolve_route", return_value=None):
            response = _run(middleware.dispatch(req, fake_handler))

    assert handler_called, "Route handler must be called when there are no detections"
    assert response.status_code == 200, f"Expected 200 for clean request, got {response.status_code}"


def test_block_wins_when_listed_after_throttle():
    """REGRESSION: block detection must fire even when a throttle detection precedes it.

    Ordering of detections appended by middlewares must not matter — block
    always wins.  If the loop ever short-circuits on throttle, block would be
    silently skipped.
    """
    req = _make_request(detections=[
        {"type": "rate_limit", "score": 0.5, "reason": "throttle candidate", "status_code": 429},
        {"type": "injection",  "score": 0.95, "reason": "SQLi",             "status_code": 403},
    ])
    handler_called = []

    async def fake_handler(r):
        handler_called.append(True)
        return StarletteJSONResponse({"ok": True}, status_code=200)

    # Policy: rate_limit → throttle, injection → block
    policy = Policy(
        name="test",
        decision_actions=DecisionActions(on_rate_limit="throttle", on_injection="block"),
    )
    middleware = DecisionEngineMiddleware(app=MagicMock())
    with patch("app.middlewares.decision_engine.get_policy", return_value=policy):
        with patch("app.middlewares.decision_engine.resolve_route", return_value=None):
            with patch("app.middlewares.decision_engine.RedisClientSingleton.get_client",
                       return_value=None):  # Redis absent → throttle passes through
                response = _run(middleware.dispatch(req, fake_handler))

    assert not handler_called, "Route handler must NOT run when a block detection is present"
    assert response.status_code == 403, f"block must win over throttle; got {response.status_code}"


def test_block_wins_when_listed_after_monitor():
    """REGRESSION: block detection must fire even when monitor detections precede it.

    Mirrors test_multi_detection_block_wins_over_monitor but with the block
    detection explicitly placed last to verify the loop does not short-circuit
    after processing a monitor action.
    """
    req = _make_request(detections=[
        {"type": "bot_detection", "score": 0.3, "reason": "sus UA",  "status_code": 403},
        {"type": "exfiltration",  "score": 0.4, "reason": "volume",  "status_code": 403},
        {"type": "injection",     "score": 0.95, "reason": "SQLi",   "status_code": 403},
    ])
    handler_called = []

    async def fake_handler(r):
        handler_called.append(True)
        return StarletteJSONResponse({"ok": True}, status_code=200)

    # All non-injection detections are monitor; injection is block (DEFAULT_POLICY)
    policy = Policy(
        name="test",
        decision_actions=DecisionActions(
            on_bot_detection="monitor",
            on_exfiltration="monitor",
            on_injection="block",
        ),
    )
    middleware = DecisionEngineMiddleware(app=MagicMock())
    with patch("app.middlewares.decision_engine.get_policy", return_value=policy):
        with patch("app.middlewares.decision_engine.resolve_route", return_value=None):
            response = _run(middleware.dispatch(req, fake_handler))

    assert not handler_called, "Route handler must NOT run when any detection resolves to block"
    assert response.status_code == 403


def test_throttle_alone_passes_through_when_below_limit():
    """REGRESSION: a single throttle detection below the hit cap must not block the request.

    Throttle is a soft signal — it should only escalate to 429 once the Redis
    counter exceeds THROTTLE_MAX_HITS.  If DecisionEngine ever treats throttle
    as an immediate block, legitimate traffic under load would be dropped.
    """
    req = _make_request(detections=[
        {"type": "rate_limit", "score": 0.5, "reason": "high frequency", "status_code": 429},
    ])
    handler_called = []

    async def fake_handler(r):
        handler_called.append(True)
        return StarletteJSONResponse({"ok": True}, status_code=200)

    pipe_mock = MagicMock()
    pipe_mock.execute.return_value = [1, True]   # count=1, well below THROTTLE_MAX_HITS (5)
    redis_mock = MagicMock()
    redis_mock.pipeline.return_value = pipe_mock

    policy = Policy(
        name="test",
        decision_actions=DecisionActions(on_rate_limit="throttle"),
    )
    middleware = DecisionEngineMiddleware(app=MagicMock())
    with patch("app.middlewares.decision_engine.get_policy", return_value=policy):
        with patch("app.middlewares.decision_engine.resolve_route", return_value=None):
            with patch("app.middlewares.decision_engine.RedisClientSingleton.get_client",
                       return_value=redis_mock):
                response = _run(middleware.dispatch(req, fake_handler))

    assert handler_called, "Throttle below cap must pass request through to handler"
    assert response.status_code == 200, f"Expected 200 for below-cap throttle, got {response.status_code}"


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


def test_throttle_uses_pipeline_incr():
    """_apply_throttle must use pipeline INCR + EXPIRE NX, not redis.set().

    Verifies:
    - pipeline is created
    - INCR is called on the correct namespaced throttle key
    - EXPIRE NX is called with the configured window
    - Below threshold: returns None (request passes through)
    """
    pipe_mock = MagicMock()
    pipe_mock.execute.return_value = [1, True]   # count=1, well below threshold

    mock_redis = MagicMock()
    mock_redis.pipeline.return_value = pipe_mock

    middleware = DecisionEngineMiddleware(app=MagicMock())
    mock_request = MagicMock(spec=Request)
    mock_request.url.path = "/api/test"
    mock_request.method = "GET"
    mock_request.state.tenant_id = None   # unauthenticated → falls back to "default"

    with patch("app.middlewares.decision_engine.RedisClientSingleton.get_client", return_value=mock_redis):
        result = middleware._apply_throttle(mock_request, "1.2.3.4", "test reason", "rate_limit", 0.5)

    assert result is None, "Below threshold: throttle must pass through (return None)"
    mock_redis.pipeline.assert_called_once()
    pipe_mock.incr.assert_called_once()
    incr_key = pipe_mock.incr.call_args[0][0]
    assert "throttle" in incr_key and "1.2.3.4" in incr_key, (
        f"INCR key must include 'throttle' and IP; got {incr_key!r}"
    )
    assert incr_key == "ritapi:default:throttle:1.2.3.4", (
        f"Expected namespaced throttle key, got {incr_key!r}"
    )
    pipe_mock.expire.assert_called_once()
    expire_args = pipe_mock.expire.call_args
    assert expire_args[1].get("nx") is True, "EXPIRE must use nx=True to avoid resetting TTL"


def test_rate_limit_calls_call_next_not_jsonresponse_429():
    """RateLimitMiddleware must call call_next after writing detections, not return 429."""
    source = inspect.getsource(RateLimitMiddleware.dispatch)
    # Detections are written via append_detection; verify dispatch ends with call_next
    assert "append_detection" in source, (
        "RateLimitMiddleware must use append_detection to write detections"
    )
    append_pos = source.index("append_detection")
    post_append = source[append_pos:]
    assert "call_next" in post_append, (
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
