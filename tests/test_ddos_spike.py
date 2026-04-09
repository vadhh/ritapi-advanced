"""
Tests for DDoS spike detection in HardGateMiddleware.

Post M-7: HardGate appends a 'ddos_spike' detection and calls call_next.
DecisionEngineMiddleware is the sole authority that issues 429 responses.

Covers:
- IP above HARD_GATE_SPIKE_THRESHOLD → ddos_spike detection appended, call_next called
- IP below threshold → no detection, passes through
- Redis unavailable → fail-open, request proceeds
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


def test_spike_above_threshold_pushes_detection_and_calls_next():
    """IP exceeding HARD_GATE_SPIKE_THRESHOLD must push ddos_spike detection and call call_next.

    DecisionEngine (not HardGate) is responsible for the 429 response.
    """
    call_next_called: list[bool] = []

    async def fake_call_next(req: Request) -> Response:
        call_next_called.append(True)
        return Response(status_code=200)

    mock_redis = _make_pipe_mock(count=101)
    mock_request = _make_mock_request(ip="9.9.9.9")

    with patch.object(hard_gate_module, "_BLOCKED_IPS", frozenset()):
        with patch.object(hard_gate_module, "_BLOCKED_ASNS", frozenset()):
            with patch.object(hard_gate_module, "_SPIKE_THRESHOLD", 100):
                with patch.object(hard_gate_module, "RedisClientSingleton") as mock_singleton:
                    mock_singleton.get_client.return_value = mock_redis
                    middleware = HardGateMiddleware(app=MagicMock())
                    with patch.object(middleware, "_check_yara", return_value=None):
                        asyncio.get_event_loop().run_until_complete(
                            middleware.dispatch(mock_request, fake_call_next)
                        )

    assert call_next_called, "HardGate must call call_next — DecisionEngine handles the 429"
    detections = mock_request.state.detections
    assert any(
        d.get("type") == "ddos_spike" or d.get("detection_type") == "ddos_spike"
        for d in detections
    ), f"Expected 'ddos_spike' detection; got: {detections}"


def test_spike_detection_has_correct_fields():
    """ddos_spike detection must carry status_code=429, score=1.0, source=hard_gate."""
    async def fake_call_next(req: Request) -> Response:
        return Response(status_code=200)

    mock_redis = _make_pipe_mock(count=101)
    mock_request = _make_mock_request(ip="9.9.9.9")
    mock_request.state.detections = []

    with patch.object(hard_gate_module, "_BLOCKED_IPS", frozenset()):
        with patch.object(hard_gate_module, "_BLOCKED_ASNS", frozenset()):
            with patch.object(hard_gate_module, "_SPIKE_THRESHOLD", 100):
                with patch.object(hard_gate_module, "RedisClientSingleton") as mock_singleton:
                    mock_singleton.get_client.return_value = mock_redis
                    middleware = HardGateMiddleware(app=MagicMock())
                    with patch.object(middleware, "_check_yara", return_value=None):
                        asyncio.get_event_loop().run_until_complete(
                            middleware.dispatch(mock_request, fake_call_next)
                        )

    detections = mock_request.state.detections
    assert len(detections) == 1
    d = detections[0]
    assert d["type"] == "ddos_spike"
    assert d["status_code"] == 429
    assert d["score"] == 1.0
    assert d["source"] == "hard_gate"


def test_spike_below_threshold_passes():
    """IP below HARD_GATE_SPIKE_THRESHOLD must reach call_next with no spike detection."""
    call_next_called: list[bool] = []

    async def fake_call_next(req: Request) -> Response:
        call_next_called.append(True)
        return Response(status_code=200)

    mock_redis = _make_pipe_mock(count=50)
    mock_request = _make_mock_request(ip="8.8.8.8")
    mock_request.state.detections = []

    with patch.object(hard_gate_module, "_BLOCKED_IPS", frozenset()):
        with patch.object(hard_gate_module, "_BLOCKED_ASNS", frozenset()):
            with patch.object(hard_gate_module, "_SPIKE_THRESHOLD", 100):
                with patch.object(hard_gate_module, "RedisClientSingleton") as mock_singleton:
                    mock_singleton.get_client.return_value = mock_redis
                    middleware = HardGateMiddleware(app=MagicMock())
                    with patch.object(middleware, "_check_yara", return_value=None):
                        asyncio.get_event_loop().run_until_complete(
                            middleware.dispatch(mock_request, fake_call_next)
                        )

    assert call_next_called, "Route must execute when spike is below threshold"
    assert mock_request.state.detections == [], "No detections expected below threshold"


def test_spike_redis_unavailable_fails_open():
    """When Redis is unavailable the spike check must be skipped (fail-open)."""
    call_next_called: list[bool] = []

    async def fake_call_next(req: Request) -> Response:
        call_next_called.append(True)
        return Response(status_code=200)

    mock_request = _make_mock_request(ip="7.7.7.7")
    mock_request.state.detections = []

    with patch.object(hard_gate_module, "_BLOCKED_IPS", frozenset()):
        with patch.object(hard_gate_module, "_BLOCKED_ASNS", frozenset()):
            with patch.object(hard_gate_module, "RedisClientSingleton") as mock_singleton:
                mock_singleton.get_client.return_value = None  # Redis unavailable
                middleware = HardGateMiddleware(app=MagicMock())
                with patch.object(middleware, "_check_yara", return_value=None):
                    asyncio.get_event_loop().run_until_complete(
                        middleware.dispatch(mock_request, fake_call_next)
                    )

    assert call_next_called, "Spike check must fail open when Redis is unavailable"
    assert mock_request.state.detections == []
