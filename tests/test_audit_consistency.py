"""
Audit consistency tests:
1. injection_detection must not call log_security_event directly for payload_too_large
2. DecisionActions must have on_payload_too_large field
3. Dead log_request() must be removed from utils/logging.py
4. log_admin_event() must exist and emit structured JSON
5. admin.py must call log_admin_event
"""
import inspect
import json


def test_injection_detection_no_direct_log_security_event():
    """payload_too_large must use append_detection, not call log_security_event directly."""
    import app.middlewares.injection_detection as mod
    src = inspect.getsource(mod)
    assert "log_security_event" not in src, (
        "injection_detection still calls log_security_event directly — "
        "migrate payload_too_large to append_detection"
    )


def test_payload_too_large_in_decision_actions():
    """DecisionActions must have on_payload_too_large field defaulting to 'block'."""
    from app.policies.service import DecisionActions
    da = DecisionActions()
    assert hasattr(da, "on_payload_too_large"), (
        "DecisionActions missing on_payload_too_large field"
    )
    assert da.on_payload_too_large == "block"


def test_log_request_removed_from_logging():
    """Dead log_request() must be removed from utils/logging.py."""
    import app.utils.logging as log_mod
    assert not hasattr(log_mod, "log_request"), (
        "log_request() is dead code — remove it from app/utils/logging.py"
    )


def test_log_admin_event_exists_and_is_structured(capsys):
    """log_admin_event() must emit structured JSON to stdout."""
    import app.utils.logging as log_mod
    assert hasattr(log_mod, "log_admin_event"), (
        "log_admin_event() is missing from app/utils/logging.py"
    )
    log_mod.log_admin_event(
        action="token_issued",
        subject="alice",
        role="VIEWER",
        issuer="__admin_secret__",
        tenant_id="acme",
        request_id="req-abc-123",
    )
    captured = capsys.readouterr()
    event = json.loads(captured.out.strip())
    assert event["event_type"] == "admin_action"
    assert event["action"] == "token_issued"
    assert event["subject"] == "alice"
    assert event["tenant_id"] == "acme"
    assert event["request_id"] == "req-abc-123"
    assert "timestamp" in event


def test_admin_calls_log_admin_event():
    """admin.py must import and call log_admin_event for audit events."""
    import app.web.admin as admin_mod
    src = inspect.getsource(admin_mod)
    assert "log_admin_event" in src, (
        "admin.py must import and call log_admin_event"
    )
