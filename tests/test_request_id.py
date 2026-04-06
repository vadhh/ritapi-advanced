"""Tests for RequestIDMiddleware."""
import asyncio
import uuid
from unittest.mock import MagicMock

from fastapi import Request
from starlette.responses import Response

from app.middlewares.request_id import RequestIDMiddleware


def test_x_request_id_header_present_on_response(client):
    """Every response must carry an X-Request-ID header."""
    resp = client.get("/healthz")
    assert "x-request-id" in resp.headers or "X-Request-ID" in resp.headers


def test_x_request_id_is_valid_uuid4(client):
    """X-Request-ID value must be a valid UUID4."""
    resp = client.get("/healthz")
    raw = resp.headers.get("x-request-id") or resp.headers.get("X-Request-ID")
    assert raw is not None, "X-Request-ID header missing"
    parsed = uuid.UUID(raw, version=4)
    assert str(parsed) == raw, f"Expected canonical UUID4 format, got {raw!r}"


def test_x_request_id_unique_per_request(client):
    """Each request must receive a distinct X-Request-ID."""
    ids = {
        (resp.headers.get("x-request-id") or resp.headers.get("X-Request-ID"))
        for resp in [client.get("/healthz"), client.get("/healthz"), client.get("/healthz")]
    }
    assert len(ids) == 3, "X-Request-ID must be unique per request"


def test_request_state_request_id_matches_header():
    """request.state.request_id must equal the X-Request-ID response header value."""
    captured: list[str] = []

    async def fake_call_next(req: Request) -> Response:
        captured.append(req.state.request_id)
        return Response(status_code=200)

    middleware = RequestIDMiddleware(app=MagicMock())
    mock_request = MagicMock(spec=Request)
    mock_request.state = MagicMock()

    response = asyncio.get_event_loop().run_until_complete(
        middleware.dispatch(mock_request, fake_call_next)
    )

    assert len(captured) == 1, "call_next must be called exactly once"
    header_value = response.headers.get("x-request-id") or response.headers.get("X-Request-ID")
    assert header_value == captured[0], (
        f"Header {header_value!r} != request.state.request_id {captured[0]!r}"
    )
