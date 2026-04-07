"""
Tests for strict tenant mode enforcement.

Tenant verification is always active — there is no toggle.  Every credential
must carry a tenant claim and it must match the X-Target-ID header.
"""
import asyncio
from unittest.mock import MagicMock

from fastapi import Request
from starlette.responses import JSONResponse as StarletteJSONResponse

from app.middlewares.auth import AuthMiddleware
from app.middlewares.detection_schema import ensure_detections_container


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _make_req(claimed_tenant: str, token_claims: dict | None = None):
    req = MagicMock(spec=Request)
    req.headers.get.return_value = "1.2.3.4"
    req.client.host = "1.2.3.4"
    req.url.path = "/api/v1/resource"
    req.method = "GET"
    req.state = MagicMock()
    req.state.claimed_tenant_id = claimed_tenant
    req.state.block = False
    req.state.detections = []
    req.state.route = None
    req.state.policy = None
    req.state.claims = None
    ensure_detections_container(req)
    return req


def _dispatch(req, token_claims):
    from unittest.mock import patch

    async def fake_next(r):
        return StarletteJSONResponse({"ok": True}, status_code=200)

    mw = AuthMiddleware(app=MagicMock())
    with patch("app.middlewares.auth.verify_token", return_value=token_claims):
        with patch("app.middlewares.auth.get_token_from_request",
                   return_value="fake-token" if token_claims else None):
            with patch("app.middlewares.auth.validate_api_key", return_value=None):
                return _run(mw.dispatch(req, fake_next))


# ── Test 1: credential with matching tenant passes ────────────────────────────
def test_bound_token_passes_when_tenant_matches():
    req = _make_req("acme")
    _dispatch(req, token_claims={"sub": "alice", "role": "VIEWER", "tid": "acme"})

    auth_failures = [d for d in req.state.detections if d.get("type") == "auth_failure"]
    assert len(auth_failures) == 0, "Matching tenant must not produce auth_failure"
    assert req.state.tenant_id == "acme"
    assert req.state.tenant_verified is True


# ── Test 2: legacy token (no tid claim) is always rejected ───────────────────
def test_legacy_token_always_blocked():
    req = _make_req("acme")
    _dispatch(req, token_claims={"sub": "alice", "role": "VIEWER"})  # no "tid"

    auth_failures = [d for d in req.state.detections if d.get("type") == "auth_failure"]
    assert len(auth_failures) == 1, "Unbound credential must produce auth_failure"
    assert auth_failures[0]["metadata"].get("auth_method") == "jwt"


# ── Test 3: mismatched tenant is always blocked ───────────────────────────────
def test_mismatched_tenant_always_blocked():
    req = _make_req("tenant-b")  # claimed = tenant-b
    _dispatch(req, token_claims={"sub": "alice", "role": "VIEWER", "tid": "tenant-a"})

    auth_failures = [d for d in req.state.detections if d.get("type") == "auth_failure"]
    assert len(auth_failures) == 1, "Tenant mismatch must produce auth_failure"
    meta = auth_failures[0]["metadata"]
    assert meta["credential_tenant"] == "tenant-a"
    assert meta["claimed_tenant"] == "tenant-b"


# ── Test 4: legacy request.state.block emits deprecation warning ──────────────
def test_legacy_block_flag_emits_warning(caplog):
    import importlib
    import logging

    import app.middlewares.decision_engine as de_mod
    importlib.reload(de_mod)

    engine = de_mod.DecisionEngineMiddleware(app=MagicMock())

    mock_request = MagicMock()
    mock_request.method = "GET"
    mock_request.url.path = "/test"

    with caplog.at_level(logging.WARNING, logger="app.middlewares.decision_engine"):
        engine._warn_legacy_block(mock_request)

    assert any(
        "DEPRECATED" in r.message or "legacy" in r.message.lower()
        for r in caplog.records
    )
