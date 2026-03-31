"""
Tests for injection detection (WAF) middleware.
"""
import inspect
import json

import pytest

from app.middlewares.injection_detection import InjectionDetectionMiddleware

UA = "pytest-test-client/1.0"


@pytest.fixture
def json_post(client, auth_headers):
    """Helper: POST JSON with auth to /healthz (proxied as a no-op target)."""
    def _post(payload: dict):
        headers = {**auth_headers, "Content-Type": "application/json"}
        # Use a non-existing route — injection detection runs before 404
        return client.post("/api/data", headers=headers, content=json.dumps(payload))
    return _post


# --- XSS ---

def test_xss_script_tag_blocked(client, auth_headers):
    headers = {**auth_headers, "Content-Type": "application/json"}
    resp = client.post(
        "/api/data", headers=headers,
        content=json.dumps({"comment": "<script>alert(1)</script>"}),
    )
    assert resp.status_code == 403
    assert "xss" in resp.json().get("detail", "").lower()


def test_xss_event_handler_blocked(client, auth_headers):
    headers = {**auth_headers, "Content-Type": "application/json"}
    resp = client.post(
        "/api/data", headers=headers,
        content=json.dumps({"name": "user\" onerror=alert(1)"}),
    )
    assert resp.status_code == 403


def test_xss_javascript_protocol_in_url_blocked(client, auth_headers):
    resp = client.get(
        "/api/data?redirect=javascript:alert(1)",
        headers=auth_headers,
    )
    assert resp.status_code == 403


# --- SQL injection ---

def test_sqli_union_select_blocked(client, auth_headers):
    headers = {**auth_headers, "Content-Type": "application/json"}
    resp = client.post(
        "/api/data", headers=headers,
        content=json.dumps({"search": "1 UNION SELECT username,password FROM users--"}),
    )
    assert resp.status_code == 403


def test_sqli_drop_table_blocked(client, auth_headers):
    headers = {**auth_headers, "Content-Type": "application/json"}
    resp = client.post(
        "/api/data", headers=headers,
        content=json.dumps({"q": "'; DROP TABLE users; --"}),
    )
    assert resp.status_code == 403


def test_sqli_sleep_blind_blocked(client, auth_headers):
    headers = {**auth_headers, "Content-Type": "application/json"}
    resp = client.post(
        "/api/data", headers=headers,
        content=json.dumps({"id": "1; SELECT SLEEP(5)"}),
    )
    assert resp.status_code == 403


# --- Command injection ---

def test_cmdi_pipe_blocked(client, auth_headers):
    headers = {**auth_headers, "Content-Type": "application/json"}
    resp = client.post(
        "/api/data", headers=headers,
        content=json.dumps({"filename": "test.txt | cat /etc/passwd"}),
    )
    assert resp.status_code == 403


def test_cmdi_subshell_blocked(client, auth_headers):
    headers = {**auth_headers, "Content-Type": "application/json"}
    resp = client.post(
        "/api/data", headers=headers,
        content=json.dumps({"input": "$(whoami)"}),
    )
    assert resp.status_code == 403


# --- Path traversal ---

def test_path_traversal_blocked(client, auth_headers):
    resp = client.get("/api/files?path=../../etc/passwd", headers=auth_headers)
    assert resp.status_code == 403


# --- Scanner user-agent ---

def test_scanner_ua_sqlmap_blocked(client, auth_headers):
    headers = {**auth_headers, "User-Agent": "sqlmap/1.7"}
    resp = client.get("/api/data", headers=headers)
    assert resp.status_code == 403


def test_scanner_ua_nikto_blocked(client, auth_headers):
    headers = {**auth_headers, "User-Agent": "Nikto/2.1.6"}
    resp = client.get("/api/data", headers=headers)
    assert resp.status_code == 403


# --- Clean requests should not be blocked ---

def test_clean_json_not_blocked(client, auth_headers):
    headers = {**auth_headers, "Content-Type": "application/json"}
    resp = client.post(
        "/api/data", headers=headers,
        content=json.dumps({"username": "alice", "email": "alice@example.com"}),
    )
    # Should not be 403 (WAF passes); 404 because route doesn't exist
    assert resp.status_code != 403


def test_nested_xss_in_json_blocked(client, auth_headers):
    """XSS in deeply nested JSON field should be caught."""
    headers = {**auth_headers, "Content-Type": "application/json"}
    payload = {"data": {"nested": {"field": "<script>alert('xss')</script>"}}}
    resp = client.post("/api/data", headers=headers, content=json.dumps(payload))
    assert resp.status_code == 403


def test_injection_writes_to_state_detections():
    """InjectionDetectionMiddleware must write to request.state.detections."""
    source = inspect.getsource(InjectionDetectionMiddleware.dispatch)
    assert "request.state.detections" in source, (
        "InjectionDetectionMiddleware must write to request.state.detections"
    )
