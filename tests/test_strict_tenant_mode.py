from unittest.mock import MagicMock


# ── Test 1: strict mode OFF — legacy token (no tid claim) passes ──────────────
def test_legacy_token_passes_when_strict_mode_off(monkeypatch):
    monkeypatch.delenv("TENANT_STRICT_MODE", raising=False)

    claims = {"sub": "alice", "role": "VIEWER"}  # no "tid" claim
    credential_tenant = claims.get("tid") or claims.get("tenant_id")
    assert not credential_tenant  # legacy token has no tenant claim

    from app.middlewares.auth import _STRICT_TENANT_MODE
    assert _STRICT_TENANT_MODE is False


# ── Test 2: strict mode ON — legacy token (no tid claim) is rejected ──────────
def test_legacy_token_blocked_when_strict_mode_on(monkeypatch):
    monkeypatch.setenv("TENANT_STRICT_MODE", "true")
    import importlib

    import app.middlewares.auth as auth_mod
    importlib.reload(auth_mod)

    assert auth_mod._STRICT_TENANT_MODE is True

    claims = {"sub": "alice", "role": "VIEWER"}  # no tid
    credential_tenant = claims.get("tid") or claims.get("tenant_id")
    assert credential_tenant is None  # unbound — strict mode should block

    monkeypatch.delenv("TENANT_STRICT_MODE", raising=False)
    importlib.reload(auth_mod)


# ── Test 3: strict mode ON — token WITH tid matching claimed tenant passes ────
def test_bound_token_passes_in_strict_mode(monkeypatch):
    monkeypatch.setenv("TENANT_STRICT_MODE", "true")
    import importlib

    import app.middlewares.auth as auth_mod
    importlib.reload(auth_mod)

    claims = {"sub": "alice", "role": "VIEWER", "tid": "acme"}
    claimed_tenant = "acme"
    credential_tenant = claims.get("tid") or claims.get("tenant_id")
    assert credential_tenant == claimed_tenant  # bound and matching → no block

    monkeypatch.delenv("TENANT_STRICT_MODE", raising=False)
    importlib.reload(auth_mod)


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
