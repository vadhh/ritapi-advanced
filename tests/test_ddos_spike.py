"""
Tests for DDoS spike detection in HardGateMiddleware.

Covers:
- IP above HARD_GATE_SPIKE_THRESHOLD → 429 before route runs
- IP below threshold → passes through
- Redis unavailable → fail-open, request proceeds
- 429 response includes X-Request-ID header
"""
import asyncio
from unittest.mock import MagicMock, patch

from fastapi import Request
from starlette.responses import Response

import app.middlewares.hard_gate as hard_gate_module
from app.middlewares.hard_gate import HardGateMiddleware


def _make_mock_request(ip: str = "1.2.3.4", path: str = "/api/test") -> MagicMock:
    mock = MagicMock(spec=Request)
    mock.headers.get.return_value = ""
    mock.headers.__contains__ = MagicMock(return_value=False)
    mock.client.host = ip
    mock.url.path = path
    mock.method = "GET"
    mock.state = MagicMock()
    mock.state.request_id = "spike-test-req-id"
    mock.state.tenant_id = "default"
    mock.state.policy = None
    mock.state.detections = []
    return mock


def _make_pipe_mock(count: int) -> MagicMock:
    """Return a Redis pipeline mock whose execute() yields [count, True]."""
    pipe = MagicMock()
    pipe.execute.return_value = [count, True]
    redis = MagicMock()
    redis.pipeline.return_value = pipe
    return redis


def test_spike_above_threshold_returns_429():
    """IP exceeding HARD_GATE_SPIKE_THRESHOLD must receive 429 and route must not execute."""
    route_called: list[bool] = []

    async def fake_call_next(req: Request) -> Response:
        route_called.append(True)
        return Response(status_code=200)

    mock_redis = _make_pipe_mock(count=101)
    mock_request = _make_mock_request(ip="9.9.9.9")

    with patch.object(hard_gate_module, "_BLOCKED_IPS", frozenset()):
        with patch.object(hard_gate_module, "_BLOCKED_ASNS", frozenset()):
            with patch.object(hard_gate_module, "_SPIKE_THRESHOLD", 100):
                with patch.object(hard_gate_module, "RedisClientSingleton") as mock_singleton:
                    mock_singleton.get_client.return_value = mock_redis
                    with patch("app.middlewares.hard_gate.log_security_event"):
                        middleware = HardGateMiddleware(app=MagicMock())
                        response = asyncio.get_event_loop().run_until_complete(
                            middleware.dispatch(mock_request, fake_call_next)
                        )

    assert not route_called, "Route must NOT execute when spike threshold is exceeded"
    assert response.status_code == 429


def test_spike_below_threshold_passes():
    """IP below HARD_GATE_SPIKE_THRESHOLD must reach the route handler."""
    route_called: list[bool] = []

    async def fake_call_next(req: Request) -> Response:
        route_called.append(True)
        return Response(status_code=200)

    mock_redis = _make_pipe_mock(count=50)
    mock_request = _make_mock_request(ip="8.8.8.8")

    with patch.object(hard_gate_module, "_BLOCKED_IPS", frozenset()):
        with patch.object(hard_gate_module, "_BLOCKED_ASNS", frozenset()):
            with patch.object(hard_gate_module, "_SPIKE_THRESHOLD", 100):
                with patch.object(hard_gate_module, "RedisClientSingleton") as mock_singleton:
                    mock_singleton.get_client.return_value = mock_redis
                    middleware = HardGateMiddleware(app=MagicMock())
                    with patch.object(middleware, "_check_yara", return_value=None):
                        response = asyncio.get_event_loop().run_until_complete(
                            middleware.dispatch(mock_request, fake_call_next)
                        )

    assert route_called, "Route must execute when spike is below threshold"
    assert response.status_code == 200


def test_spike_redis_unavailable_fails_open():
    """When Redis is unavailable the spike check must be skipped (fail-open)."""
    route_called: list[bool] = []

    async def fake_call_next(req: Request) -> Response:
        route_called.append(True)
        return Response(status_code=200)

    mock_request = _make_mock_request(ip="7.7.7.7")

    with patch.object(hard_gate_module, "_BLOCKED_IPS", frozenset()):
        with patch.object(hard_gate_module, "_BLOCKED_ASNS", frozenset()):
            with patch.object(hard_gate_module, "RedisClientSingleton") as mock_singleton:
                mock_singleton.get_client.return_value = None  # Redis unavailable
                middleware = HardGateMiddleware(app=MagicMock())
                with patch.object(middleware, "_check_yara", return_value=None):
                    response = asyncio.get_event_loop().run_until_complete(
                        middleware.dispatch(mock_request, fake_call_next)
                    )

    assert route_called, "Spike check must fail open when Redis is unavailable"
    assert response.status_code == 200


def test_spike_429_includes_request_id_header():
    """429 response from spike check must echo the X-Request-ID header."""
    async def fake_call_next(req: Request) -> Response:
        return Response(status_code=200)

    mock_redis = _make_pipe_mock(count=200)
    mock_request = _make_mock_request(ip="6.6.6.6")
    mock_request.state.request_id = "spike-req-id-abc123"
    mock_request.state.tenant_id = "default"

    with patch.object(hard_gate_module, "_BLOCKED_IPS", frozenset()):
        with patch.object(hard_gate_module, "_BLOCKED_ASNS", frozenset()):
            with patch.object(hard_gate_module, "_SPIKE_THRESHOLD", 100):
                with patch.object(hard_gate_module, "RedisClientSingleton") as mock_singleton:
                    mock_singleton.get_client.return_value = mock_redis
                    with patch("app.middlewares.hard_gate.log_security_event"):
                        middleware = HardGateMiddleware(app=MagicMock())
                        response = asyncio.get_event_loop().run_until_complete(
                            middleware.dispatch(mock_request, fake_call_next)
                        )

    assert response.status_code == 429
    assert response.headers.get("x-request-id") == "spike-req-id-abc123"


def test_spike_calls_log_decision_with_ddos_spike():
    """Spike block must call log_security_event with action=block, trigger_type=ddos_spike."""
    async def fake_call_next(req: Request) -> Response:
        return Response(status_code=200)

    mock_redis = _make_pipe_mock(count=150)
    mock_request = _make_mock_request(ip="5.5.5.5")

    with patch.object(hard_gate_module, "_BLOCKED_IPS", frozenset()):
        with patch.object(hard_gate_module, "_BLOCKED_ASNS", frozenset()):
            with patch.object(hard_gate_module, "_SPIKE_THRESHOLD", 100):
                with patch.object(hard_gate_module, "RedisClientSingleton") as mock_singleton:
                    mock_singleton.get_client.return_value = mock_redis
                    with patch("app.middlewares.hard_gate.log_security_event") as mock_log:
                        middleware = HardGateMiddleware(app=MagicMock())
                        asyncio.get_event_loop().run_until_complete(
                            middleware.dispatch(mock_request, fake_call_next)
                        )

    mock_log.assert_called_once()
    _, kwargs = mock_log.call_args
    assert kwargs["action"] == "block"
    assert kwargs["trigger_type"] == "ddos_spike"
