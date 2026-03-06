"""
Bot detection tests.

Unit tests call _detect() directly against Redis to verify each rule triggers
correctly. Integration tests exercise the middleware stack end-to-end using
X-Forwarded-For headers to avoid the testclient bypass IP.

Bot detection bypass IPs (from conftest): 127.0.0.1, ::1, testclient.
Integration tests use 10.99.bot.X IPs which are NOT bypassed.
"""
import pytest

from app.middlewares.bot_detection import (
    BLOCK_THRESHOLD,
    RULES,
    _accumulate_risk,
    _detect,
    _is_suspicious_ua,
)

# Unique IP prefix for bot detection tests — not in bypass list
_IP = "10.99.bot.{}"
_UA = "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/109.0"


# ---------------------------------------------------------------------------
# Unit tests — _is_suspicious_ua
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ua,expected", [
    ("sqlmap/1.7.8", True),
    ("python-requests/2.31.0", True),
    ("Nikto/2.1.6", True),
    ("masscan/1.3.2", True),
    ("curl/8.0.0", True),
    ("wget/1.21", True),
    ("go-http-client/2.0", True),
    ("Mozilla/5.0 (Windows NT 10.0) Firefox/109.0", False),
    ("PostmanRuntime/7.32.0", False),
    ("", False),
])
def test_suspicious_ua_detection(ua, expected):
    assert _is_suspicious_ua(ua) == expected


# ---------------------------------------------------------------------------
# Unit tests — _detect() for each rule
# ---------------------------------------------------------------------------

def test_no_user_agent(redis):
    hits = _detect(redis, _IP.format(1), "GET", "/api", "", 0, 200)
    assert any(h[0] == "NO_USER_AGENT" for h in hits)


def test_no_user_agent_score(redis):
    hits = _detect(redis, _IP.format(2), "GET", "/api", "", 0, 200)
    score = next(s for n, s in hits if n == "NO_USER_AGENT")
    assert score == RULES["NO_USER_AGENT"]["score"]


def test_suspicious_user_agent(redis):
    hits = _detect(redis, _IP.format(3), "GET", "/api", "sqlmap/1.7", 0, 200)
    assert any(h[0] == "SUSPICIOUS_USER_AGENT" for h in hits)


def test_suspicious_method(redis):
    hits = _detect(redis, _IP.format(4), "TRACE", "/api", _UA, 0, 200)
    assert any(h[0] == "SUSPICIOUS_METHOD" for h in hits)


def test_connect_method_suspicious(redis):
    hits = _detect(redis, _IP.format(5), "CONNECT", "/api", _UA, 0, 200)
    assert any(h[0] == "SUSPICIOUS_METHOD" for h in hits)


def test_standard_methods_not_suspicious(redis):
    for method in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        hits = _detect(redis, _IP.format(6), method, "/api", _UA, 0, 200)
        assert not any(h[0] == "SUSPICIOUS_METHOD" for h in hits), \
            f"{method} should not trigger SUSPICIOUS_METHOD"


def test_large_payload(redis):
    threshold = RULES["LARGE_PAYLOAD"]["threshold"]
    hits = _detect(redis, _IP.format(7), "POST", "/api", _UA, threshold + 1, 200)
    assert any(h[0] == "LARGE_PAYLOAD" for h in hits)


def test_large_payload_at_threshold_not_triggered(redis):
    threshold = RULES["LARGE_PAYLOAD"]["threshold"]
    hits = _detect(redis, _IP.format(8), "POST", "/api", _UA, threshold, 200)
    assert not any(h[0] == "LARGE_PAYLOAD" for h in hits)


def test_rapid_fire(redis):
    ip = _IP.format(9)
    threshold = RULES["RAPID_FIRE"]["threshold"]
    for _ in range(threshold):
        _detect(redis, ip, "GET", "/api", _UA, 0, 200)
    hits = _detect(redis, ip, "GET", "/api", _UA, 0, 200)
    assert any(h[0] == "RAPID_FIRE" for h in hits)


def test_burst_traffic(redis):
    ip = _IP.format(10)
    threshold = RULES["BURST_TRAFFIC"]["threshold"]
    for _ in range(threshold):
        _detect(redis, ip, "GET", "/api", _UA, 0, 200)
    hits = _detect(redis, ip, "GET", "/api", _UA, 0, 200)
    assert any(h[0] == "BURST_TRAFFIC" for h in hits)


def test_endpoint_scanning(redis):
    ip = _IP.format(11)
    threshold = RULES["ENDPOINT_SCANNING"]["threshold"]
    for i in range(threshold):
        _detect(redis, ip, "GET", f"/api/ep/{i}", _UA, 0, 200)
    hits = _detect(redis, ip, "GET", "/api/ep/new", _UA, 0, 200)
    assert any(h[0] == "ENDPOINT_SCANNING" for h in hits)


def test_excessive_post(redis):
    ip = _IP.format(12)
    threshold = RULES["EXCESSIVE_POST"]["threshold"]
    for _ in range(threshold):
        _detect(redis, ip, "POST", "/api", _UA, 0, 200)
    hits = _detect(redis, ip, "POST", "/api", _UA, 0, 200)
    assert any(h[0] == "EXCESSIVE_POST" for h in hits)


def test_repeated_404(redis):
    ip = _IP.format(13)
    threshold = RULES["REPEATED_404"]["threshold"]
    for _ in range(threshold):
        _detect(redis, ip, "GET", "/missing", _UA, 0, 404)
    hits = _detect(redis, ip, "GET", "/missing", _UA, 0, 404)
    assert any(h[0] == "REPEATED_404" for h in hits)


def test_repeated_401(redis):
    ip = _IP.format(14)
    threshold = RULES["REPEATED_401"]["threshold"]
    for _ in range(threshold):
        _detect(redis, ip, "GET", "/api", _UA, 0, 401)
    hits = _detect(redis, ip, "GET", "/api", _UA, 0, 401)
    assert any(h[0] == "REPEATED_401" for h in hits)


def test_repeated_403(redis):
    ip = _IP.format(15)
    threshold = RULES["REPEATED_403"]["threshold"]
    for _ in range(threshold):
        _detect(redis, ip, "GET", "/api", _UA, 0, 403)
    hits = _detect(redis, ip, "GET", "/api", _UA, 0, 403)
    assert any(h[0] == "REPEATED_403" for h in hits)


def test_consecutive_errors(redis):
    ip = _IP.format(16)
    count = RULES["CONSECUTIVE_ERRORS"]["count"]
    for _ in range(count):
        _detect(redis, ip, "GET", "/api", _UA, 0, 500)
    hits = _detect(redis, ip, "GET", "/api", _UA, 0, 500)
    assert any(h[0] == "CONSECUTIVE_ERRORS" for h in hits)


def test_consecutive_errors_reset_on_success(redis):
    ip = _IP.format(17)
    # Build up 3 consecutive errors (below count=5)
    for _ in range(3):
        _detect(redis, ip, "GET", "/api", _UA, 0, 500)
    # A successful response resets the streak
    _detect(redis, ip, "GET", "/api", _UA, 0, 200)
    # Now 4 more errors — should NOT hit CONSECUTIVE_ERRORS (counter reset to 0+4=4 < 5)
    for _ in range(4):
        hits = _detect(redis, ip, "GET", "/api", _UA, 0, 500)
    assert not any(h[0] == "CONSECUTIVE_ERRORS" for h in hits)


def test_high_error_rate(redis):
    ip = _IP.format(18)
    min_req = RULES["HIGH_ERROR_RATE"]["min_requests"]
    # Send min_requests, all errors → error rate = 1.0 > 0.5 threshold
    for _ in range(min_req):
        _detect(redis, ip, "GET", "/api", _UA, 0, 500)
    hits = _detect(redis, ip, "GET", "/api", _UA, 0, 500)
    assert any(h[0] == "HIGH_ERROR_RATE" for h in hits)


def test_high_error_rate_below_threshold(redis):
    ip = _IP.format(19)
    min_req = RULES["HIGH_ERROR_RATE"]["min_requests"]
    # Send half successes, half errors → rate = 0.5, not > 0.5
    for _ in range(min_req // 2):
        _detect(redis, ip, "GET", "/api", _UA, 0, 200)
    for _ in range(min_req // 2):
        _detect(redis, ip, "GET", "/api", _UA, 0, 500)
    hits = _detect(redis, ip, "GET", "/api", _UA, 0, 200)
    assert not any(h[0] == "HIGH_ERROR_RATE" for h in hits)


# ---------------------------------------------------------------------------
# Unit tests — _accumulate_risk
# ---------------------------------------------------------------------------

def test_accumulate_risk_blocks_at_threshold(redis):
    ip = _IP.format(20)
    result = _accumulate_risk(redis, ip, BLOCK_THRESHOLD)
    assert result >= BLOCK_THRESHOLD


def test_accumulate_risk_capped_at_100(redis):
    ip = _IP.format(21)
    result = _accumulate_risk(redis, ip, 200)
    assert result == 100


def test_accumulate_risk_accumulates(redis):
    ip = _IP.format(22)
    _accumulate_risk(redis, ip, 30)
    result = _accumulate_risk(redis, ip, 30)
    assert result == 60


# ---------------------------------------------------------------------------
# Integration tests — middleware end-to-end (non-bypass IPs via X-Forwarded-For)
# ---------------------------------------------------------------------------

def test_suspicious_method_blocks_via_middleware(client, redis):
    """TRACE → SUSPICIOUS_METHOD (score=70) → cumulative ≥ 70 → 403."""
    resp = client.request(
        "TRACE", "/healthz",
        headers={"X-Forwarded-For": "10.99.bot.100", "User-Agent": _UA},
    )
    assert resp.status_code == 403
    assert "Automated" in resp.json().get("detail", "")


def test_large_payload_header_blocks_via_middleware(client, redis):
    """Content-Length > 10000 → LARGE_PAYLOAD (score=70) → cumulative ≥ 70 → 403."""
    resp = client.get(
        "/healthz",
        headers={
            "X-Forwarded-For": "10.99.bot.101",
            "User-Agent": _UA,
            "Content-Length": "15000",
        },
    )
    assert resp.status_code == 403


def test_no_ua_accumulates_to_block(client, redis):
    """Suspicious-UA requests accumulate risk: 60+60=120 ≥ 70 → blocked on second."""
    headers = {"X-Forwarded-For": "10.99.bot.102", "User-Agent": "sqlmap/1.7"}
    # First request: cumulative=60, not yet blocked
    client.get("/healthz", headers=headers)
    # Second request: cumulative=120 ≥ 70, blocked
    resp = client.get("/healthz", headers=headers)
    assert resp.status_code == 403


def test_clean_request_not_blocked(client, redis):
    """Legitimate request from non-bypass IP is not blocked."""
    resp = client.get(
        "/healthz",
        headers={"X-Forwarded-For": "10.99.bot.200", "User-Agent": _UA},
    )
    assert resp.status_code == 200
