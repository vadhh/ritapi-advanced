"""
Runtime proof — strict tenant mode.

Three cases using the full middleware stack via TestClient:

  Test 1 — Valid tenant:   matching header + credential → 200, backend runs
  Test 2 — Mismatch:       header=tenant-a, credential=tenant-b → 403, no backend
  Test 3 — Missing tenant: credential has no tid claim → 403, no backend

Run with:
    pytest tests/test_strict_tenant_runtime_proof.py -v -s
"""
import pytest
from fastapi.testclient import TestClient

from app.auth.jwt_handler import create_access_token
from app.main import app

UA = "pytest-test-client/1.0"


@pytest.fixture(scope="module")
def tc():
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


# ── Test 1: valid tenant — header matches credential ──────────────────────────
def test_case1_valid_tenant_allowed(tc, capsys):
    token = create_access_token("alice", "VIEWER", tenant_id="acme")
    resp = tc.get(
        "/probe",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Target-ID": "acme",
            "User-Agent": UA,
        },
    )
    captured = capsys.readouterr()
    print("\n" + "=" * 60)
    print("CASE 1 — Valid tenant")
    print("  X-Target-ID       : acme")
    print("  credential tid    : acme")
    print(f"  HTTP status       : {resp.status_code}")
    print(f"  Response body     : {resp.json()}")
    print(f"  stdout captured   : {captured.out.strip()!r}")

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.json()}"
    assert "BACKEND EXECUTED" in captured.out, "Backend must run for valid tenant"


# ── Test 2: tenant mismatch — header != credential ────────────────────────────
def test_case2_tenant_mismatch_blocked(tc, capsys):
    token = create_access_token("alice", "VIEWER", tenant_id="tenant-b")
    resp = tc.get(
        "/probe",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Target-ID": "tenant-a",
            "User-Agent": UA,
        },
    )
    captured = capsys.readouterr()
    print("\n" + "=" * 60)
    print("CASE 2 — Tenant mismatch")
    print("  X-Target-ID       : tenant-a")
    print("  credential tid    : tenant-b")
    print(f"  HTTP status       : {resp.status_code}")
    print(f"  Response body     : {resp.json()}")
    print(f"  stdout captured   : {captured.out.strip()!r}")

    assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.json()}"
    assert "BACKEND EXECUTED" not in captured.out, "Backend must NOT run on mismatch"


# ── Test 3: missing tenant claim — unbound credential ─────────────────────────
def test_case3_no_tenant_claim_blocked(tc, capsys):
    # Issue a token without a tenant claim by bypassing create_access_token
    # and encoding the payload directly (no "tid" field).
    import os
    from datetime import UTC, datetime, timedelta

    from jose import jwt as jose_jwt
    secret = os.environ["SECRET_KEY"]
    payload = {
        "sub": "alice",
        "role": "VIEWER",
        "exp": datetime.now(UTC) + timedelta(minutes=60),
    }
    token = jose_jwt.encode(payload, secret, algorithm="HS256")

    resp = tc.get(
        "/probe",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Target-ID": "acme",
            "User-Agent": UA,
        },
    )
    captured = capsys.readouterr()
    print("\n" + "=" * 60)
    print("CASE 3 — Missing tenant claim in credential")
    print("  X-Target-ID       : acme")
    print("  credential tid    : (none — unbound token)")
    print(f"  HTTP status       : {resp.status_code}")
    print(f"  Response body     : {resp.json()}")
    print(f"  stdout captured   : {captured.out.strip()!r}")

    assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.json()}"
    assert "BACKEND EXECUTED" not in captured.out, "Backend must NOT run for unbound credential"
