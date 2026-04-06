"""
Tests for latency_ms field in log_decision().

Verifies:
- latency_ms is present in every log line
- latency_ms is a non-negative float when request.state.started_at is set
- latency_ms is null (None/JSON null) when started_at is absent or non-numeric
"""
import json
import time
from unittest.mock import MagicMock

from app.security.logger import log_decision


def _decision():
    return {"action": "block", "reason": "test", "trigger_type": "test_type"}


def _base_mock():
    """Return a minimal mock request whose MagicMock state has no real started_at."""
    mock = MagicMock()
    mock.client.host = "1.2.3.4"
    mock.url.path = "/test"
    mock.method = "GET"
    mock.state = MagicMock()
    mock.state.request_id = "test-req-id"
    mock.state.detections = []
    return mock


def test_latency_ms_field_present(capsys):
    """log_decision() output must include a latency_ms key."""
    mock_request = _base_mock()
    mock_request.state.started_at = time.monotonic()
    log_decision(mock_request, _decision())
    record = json.loads(capsys.readouterr().out)
    assert "latency_ms" in record, "latency_ms field must be present in log output"


def test_latency_ms_is_number_for_normal_request(capsys):
    """latency_ms must be a non-negative float for a request with started_at set."""
    mock_request = _base_mock()
    mock_request.state.started_at = time.monotonic() - 0.010  # 10 ms in the past
    log_decision(mock_request, _decision())
    record = json.loads(capsys.readouterr().out)
    assert isinstance(record["latency_ms"], (int, float)), (
        f"Expected numeric latency_ms, got {record['latency_ms']!r}"
    )
    assert record["latency_ms"] >= 0, "latency_ms must not be negative"


def test_latency_ms_is_null_when_started_at_missing(capsys):
    """latency_ms must be null when request.state.started_at is not a numeric type.

    MagicMock auto-creates attributes, so getattr(mock.state, 'started_at', None)
    returns a MagicMock — which is not an int/float.  The implementation must treat
    this as 'not set' and emit null rather than raising.
    """
    mock_request = _base_mock()
    # Do NOT set started_at — MagicMock returns a MagicMock for it, not a float
    log_decision(mock_request, _decision())
    record = json.loads(capsys.readouterr().out)
    assert record["latency_ms"] is None, (
        f"Expected null latency_ms when started_at is missing/non-numeric, "
        f"got {record['latency_ms']!r}"
    )


def test_latency_ms_does_not_raise_when_started_at_is_string(capsys):
    """log_decision must never raise even when started_at is a garbage value."""
    mock_request = _base_mock()
    mock_request.state.started_at = "not-a-float"
    log_decision(mock_request, _decision())
    record = json.loads(capsys.readouterr().out)
    assert record["latency_ms"] is None


def test_latency_ms_value_is_reasonable(capsys):
    """latency_ms for a request started 50 ms ago must be close to 50 ms."""
    mock_request = _base_mock()
    mock_request.state.started_at = time.monotonic() - 0.050  # 50 ms ago
    log_decision(mock_request, _decision())
    record = json.loads(capsys.readouterr().out)
    assert 40 <= record["latency_ms"] <= 500, (
        f"latency_ms {record['latency_ms']} is outside expected range for a 50ms-old request"
    )
