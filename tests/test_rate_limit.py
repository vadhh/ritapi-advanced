"""
Tests for rate limiting middleware.

Note: conftest sets RATE_LIMIT_REQUESTS=20 so rate limit fires before
exfiltration's bulk_access threshold (50). Tests use /dashboard (not /healthz,
which is in the rate limit skip list).
"""
import os

UA = "pytest-test-client/1.0"

# Read the actual configured limit (set in conftest to 20)
_RATE_LIMIT = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))


def test_rate_limit_triggers_429(client, auth_headers, redis):
    """Exceed per-IP rate limit on a rate-limited path and expect 429."""
    headers = {**auth_headers}
    hit_429 = False
    # /dashboard is rate-limited (not in _SKIP_PREFIXES)
    for _ in range(_RATE_LIMIT + 5):
        resp = client.get("/dashboard", headers=headers)
        if resp.status_code == 429:
            hit_429 = True
            break
    assert hit_429, f"Rate limiter did not trigger 429 after {_RATE_LIMIT} requests"


def test_rate_limit_response_format(client, auth_headers, redis):
    """429 response has the expected JSON error structure."""
    headers = {**auth_headers}
    last_resp = None
    for _ in range(_RATE_LIMIT + 2):
        last_resp = client.get("/dashboard", headers=headers)
        if last_resp.status_code == 429:
            break
    assert last_resp is not None and last_resp.status_code == 429
    data = last_resp.json()
    assert "error" in data
    assert "detail" in data


def test_api_key_rate_limit(client, redis):
    """Per-API-key rate limit is enforced on /dashboard."""
    from app.auth.api_key_handler import issue_api_key
    raw_key = issue_api_key("rate-test-svc", "VIEWER")
    headers = {"X-API-Key": raw_key, "User-Agent": UA}

    hit_429 = False
    for _ in range(_RATE_LIMIT + 5):
        resp = client.get("/dashboard", headers=headers)
        if resp.status_code == 429:
            hit_429 = True
            break
    assert hit_429, "API key rate limit did not trigger"
