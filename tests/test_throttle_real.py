"""
Real throttle tests — M-7 follow-up.

Throttle must actually limit traffic:
  - Requests 1..THROTTLE_MAX_HITS: allowed (200)
  - Request THROTTLE_MAX_HITS+1:  blocked (429)
  - Backend NOT executed on the blocking request
"""
import asyncio
from unittest.mock import MagicMock, patch

from fastapi import Request
from starlette.responses import Response

from app.middlewares.decision_engine import (
    THROTTLE_MAX_HITS,
    DecisionEngineMiddleware,
)
from app.policies.service import DecisionActions, Policy


def _make_request(ip: str = "10.0.0.1", count: int = 1) -> tuple:
    """Return (mock_request, mock_redis) with pipeline execute returning [count, True]."""
    pipe_mock = MagicMock()
    pipe_mock.execute.return_value = [count, True]

    redis_mock = MagicMock()
    redis_mock.pipeline.return_value = pipe_mock

    req = MagicMock(spec=Request)
    req.headers.get.return_value = ip
    req.client.host = ip
    req.url.path = "/api/v1/resource"
    req.method = "GET"
    req.state = MagicMock()
    req.state.route = None
    req.state.block = False
    req.state.tenant_id = None  # unauthenticated
    req.state.detections = [
        {
            "type": "bot_detection",
            "score": 0.75,
            "reason": "bot signals: RAPID_FIRE",
            "status_code": 403,
            "source": "bot_detection",
            "metadata": {},
        }
    ]
    return req, redis_mock


_THROTTLE_POLICY = Policy(
    name="throttle-policy",
    decision_actions=DecisionActions(on_bot_detection="throttle"),
)


def _dispatch_sync(middleware, req, redis_mock, backend_fn):
    with patch("app.middlewares.decision_engine.get_policy", return_value=_THROTTLE_POLICY):
        with patch("app.middlewares.decision_engine.resolve_route", return_value=None):
            with patch(
                "app.middlewares.decision_engine.RedisClientSingleton.get_client",
                return_value=redis_mock,
            ):
                return asyncio.get_event_loop().run_until_complete(
                    middleware.dispatch(req, backend_fn)
                )


def test_throttle_triggers_429():
    """
    Requests 1..THROTTLE_MAX_HITS → 200 (allowed).
    Request THROTTLE_MAX_HITS+1   → 429 (blocked).
    Backend NOT executed on the blocking request.
    """
    middleware = DecisionEngineMiddleware(app=MagicMock())
    backend_calls: list[int] = []

    async def fake_backend(req):
        backend_calls.append(1)
        return Response(status_code=200)

    # Requests 1..N: below threshold, must pass through
    for count in range(1, THROTTLE_MAX_HITS + 1):
        req, redis_mock = _make_request(count=count)
        response = _dispatch_sync(middleware, req, redis_mock, fake_backend)
        assert response.status_code == 200, (
            f"Request #{count} (count={count}, threshold={THROTTLE_MAX_HITS}) "
            f"should pass through, got {response.status_code}"
        )

    backend_calls.clear()

    # Request N+1: exceeds threshold → 429, backend NOT called
    req, redis_mock = _make_request(count=THROTTLE_MAX_HITS + 1)
    response = _dispatch_sync(middleware, req, redis_mock, fake_backend)

    assert response.status_code == 429, (
        f"Request at count={THROTTLE_MAX_HITS + 1} must return 429, got {response.status_code}"
    )
    assert not backend_calls, (
        "Backend must NOT execute when throttle limit is exceeded"
    )


def test_throttle_at_exact_threshold_passes():
    """Request at exactly THROTTLE_MAX_HITS (not over) must still pass through."""
    middleware = DecisionEngineMiddleware(app=MagicMock())
    backend_called: list[bool] = []

    async def fake_backend(req):
        backend_called.append(True)
        return Response(status_code=200)

    req, redis_mock = _make_request(count=THROTTLE_MAX_HITS)
    response = _dispatch_sync(middleware, req, redis_mock, fake_backend)

    assert response.status_code == 200, (
        f"count={THROTTLE_MAX_HITS} == threshold must still pass, got {response.status_code}"
    )
    assert backend_called, "Backend must execute at the threshold (not over it)"


def test_throttle_redis_unavailable_fails_open():
    """When Redis is unavailable throttle must fail-open: request passes through."""
    middleware = DecisionEngineMiddleware(app=MagicMock())
    backend_called: list[bool] = []

    async def fake_backend(req):
        backend_called.append(True)
        return Response(status_code=200)

    req, _ = _make_request(count=THROTTLE_MAX_HITS + 100)

    with patch("app.middlewares.decision_engine.get_policy", return_value=_THROTTLE_POLICY):
        with patch("app.middlewares.decision_engine.resolve_route", return_value=None):
            with patch(
                "app.middlewares.decision_engine.RedisClientSingleton.get_client",
                return_value=None,  # Redis unavailable
            ):
                response = asyncio.get_event_loop().run_until_complete(
                    middleware.dispatch(req, fake_backend)
                )

    assert response.status_code == 200, "Throttle must fail-open when Redis is unavailable"
    assert backend_called, "Backend must execute when Redis is unavailable (fail-open)"


def test_throttle_escalation_uses_429_not_403():
    """Throttle escalation must return 429, not 403."""
    middleware = DecisionEngineMiddleware(app=MagicMock())

    async def fake_backend(req):
        raise AssertionError("Backend must not run when throttle is exceeded")

    req, redis_mock = _make_request(count=THROTTLE_MAX_HITS + 1)
    response = _dispatch_sync(middleware, req, redis_mock, fake_backend)

    assert response.status_code == 429, (
        f"Throttle escalation must use 429, not {response.status_code}"
    )
    body = response.body
    import json
    data = json.loads(body)
    assert data.get("error") == "Too Many Requests", (
        f"429 response body error field must be 'Too Many Requests', got {data}"
    )
