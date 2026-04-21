"""Tests for L-3: REDIS_FAIL_MODE=closed behaviour."""
import os
from unittest.mock import patch

import pytest

UA = "pytest-test-client/1.0"


# ── is_fail_closed() helper ────────────────────────────────────────────────

def test_is_fail_closed_returns_false_by_default():
    from app.utils.redis_client import is_fail_closed
    with patch("app.utils.redis_client._FAIL_MODE", "open"):
        assert is_fail_closed() is False


def test_is_fail_closed_returns_true_when_set_to_closed():
    from app.utils.redis_client import is_fail_closed
    with patch("app.utils.redis_client._FAIL_MODE", "closed"):
        assert is_fail_closed() is True


def test_is_fail_closed_case_insensitive():
    from app.utils.redis_client import is_fail_closed
    with patch("app.utils.redis_client._FAIL_MODE", "CLOSED"):
        assert is_fail_closed() is True


def test_is_fail_closed_rejects_unknown_values():
    from app.utils.redis_client import is_fail_closed
    with patch("app.utils.redis_client._FAIL_MODE", "strict"):
        assert is_fail_closed() is False
