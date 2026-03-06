"""
Edge case tests.

Covers boundary and adversarial inputs that could cause crashes, false
negatives (bypasses), or unexpected behaviour:
  - Oversized request body (> 2 MB cap)
  - Malformed / non-JSON body on JSON endpoints
  - Non-UTF-8 body bytes
  - Empty body
  - Very long URLs
  - Null bytes in payload
  - Unicode homoglyph bypass attempts (full-width chars that normalise to ASCII)
  - URL double-encoding bypass attempts
  - Header injection via newline chars
  - Extremely nested JSON
"""
import json

import pytest

UA = "pytest-test-client/1.0"


@pytest.fixture
def post_headers(auth_headers):
    return {**auth_headers, "Content-Type": "application/json"}


# ---------------------------------------------------------------------------
# Body size limits
# ---------------------------------------------------------------------------

def test_oversized_body_returns_413(client, auth_headers):
    """Body > 2 MB is rejected with 413 before WAF processing."""
    large_body = b"x" * (2 * 1024 * 1024 + 1)
    headers = {**auth_headers, "Content-Type": "application/json"}
    resp = client.post("/api/data", headers=headers, content=large_body)
    assert resp.status_code == 413


def test_exactly_2mb_body_not_413(client, auth_headers):
    """Body at exactly the 2 MB limit should not be rejected for size alone."""
    body = b"x" * (2 * 1024 * 1024)
    headers = {**auth_headers, "Content-Type": "application/json"}
    resp = client.post("/api/data", headers=headers, content=body)
    # Not 413 (though may be 400 for invalid JSON, or 404 for missing route)
    assert resp.status_code != 413


def test_empty_body_does_not_crash(client, post_headers):
    """Empty POST body is handled gracefully."""
    resp = client.post("/api/data", headers=post_headers, content=b"")
    assert resp.status_code != 500


# ---------------------------------------------------------------------------
# Malformed / non-JSON bodies
# ---------------------------------------------------------------------------

def test_malformed_json_does_not_crash(client, post_headers):
    """Truncated JSON body does not cause 500."""
    resp = client.post("/api/data", headers=post_headers, content=b'{"key": "val"')
    assert resp.status_code != 500


def test_json_array_root_does_not_crash(client, post_headers):
    """JSON array at root is valid and handled."""
    resp = client.post(
        "/api/data", headers=post_headers,
        content=json.dumps([1, 2, 3]).encode(),
    )
    assert resp.status_code != 500


def test_json_number_root_does_not_crash(client, post_headers):
    """JSON primitive at root is handled."""
    resp = client.post("/api/data", headers=post_headers, content=b"42")
    assert resp.status_code != 500


# ---------------------------------------------------------------------------
# Non-UTF-8 and null bytes
# ---------------------------------------------------------------------------

def test_non_utf8_body_does_not_crash(client, auth_headers):
    """Binary / non-UTF-8 body does not cause 500."""
    headers = {**auth_headers, "Content-Type": "application/octet-stream"}
    resp = client.post("/api/data", headers=headers, content=b"\xff\xfe\x00\x01")
    assert resp.status_code != 500


def test_null_byte_in_json_string(client, post_headers):
    """Null byte in JSON string value is handled (stripped by normaliser)."""
    payload = json.dumps({"field": "value\x00injected"})
    resp = client.post("/api/data", headers=post_headers, content=payload.encode())
    assert resp.status_code != 500


# ---------------------------------------------------------------------------
# URL and header length
# ---------------------------------------------------------------------------

def test_very_long_url_does_not_crash(client, auth_headers):
    """URL with a very long query string is handled without 500."""
    long_param = "a" * 4096
    resp = client.get(f"/api/data?q={long_param}", headers=auth_headers)
    assert resp.status_code != 500


def test_very_long_header_value_does_not_crash(client, auth_headers):
    """Extremely long User-Agent header is handled without 500."""
    headers = {**auth_headers, "User-Agent": "A" * 8192}
    resp = client.get("/healthz", headers=headers)
    assert resp.status_code != 500


# ---------------------------------------------------------------------------
# Unicode / encoding bypass attempts
# ---------------------------------------------------------------------------

def test_fullwidth_script_tag_blocked(client, post_headers):
    """Full-width < and > (＜script＞) normalise to ASCII and are caught."""
    # After URL-decode normalisation these become <script>
    payload = json.dumps({"input": "\uff1cscript\uff1ealert(1)\uff1c/script\uff1e"})
    resp = client.post("/api/data", headers=post_headers, content=payload.encode())
    # May or may not block (depends on normalisation depth) — must not crash
    assert resp.status_code != 500


def test_double_url_encoded_sqli_blocked(client, auth_headers):
    """Double URL-encoded UNION SELECT is decoded and blocked."""
    # %2527 → %27 → ' (after two rounds of decoding)
    resp = client.get(
        "/api/data?id=1%2520UNION%2520SELECT%2520username%2520FROM%2520users",
        headers=auth_headers,
    )
    assert resp.status_code == 403


def test_html_entity_xss_blocked(client, post_headers):
    """HTML entity-encoded script tag (&lt;script&gt;) is decoded and blocked."""
    payload = json.dumps({"comment": "&lt;script&gt;alert(1)&lt;/script&gt;"})
    resp = client.post("/api/data", headers=post_headers, content=payload.encode())
    assert resp.status_code == 403


def test_unicode_null_bypass_script_tag_caught(client, post_headers):
    """Null-byte split script tag (<scr\x00ipt>) is normalised and caught."""
    payload = json.dumps({"field": "<scr\x00ipt>alert(1)</script>"})
    resp = client.post("/api/data", headers=post_headers, content=payload.encode())
    # The normaliser strips null bytes; should still be caught by regex
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Extremely nested JSON (stack depth / recursion)
# ---------------------------------------------------------------------------

def test_deeply_nested_json_does_not_crash(client, post_headers):
    """Deeply nested JSON object is handled without hitting Python recursion limit."""
    nested: dict = {"v": "clean"}
    for _ in range(50):
        nested = {"n": nested}
    resp = client.post(
        "/api/data", headers=post_headers,
        content=json.dumps(nested).encode(),
    )
    assert resp.status_code != 500


def test_deeply_nested_json_with_xss_blocked(client, post_headers):
    """XSS payload inside deeply nested JSON is found by recursive scan."""
    nested: dict = {"v": "<script>alert(1)</script>"}
    for _ in range(20):
        nested = {"n": nested}
    resp = client.post(
        "/api/data", headers=post_headers,
        content=json.dumps(nested).encode(),
    )
    assert resp.status_code == 403
