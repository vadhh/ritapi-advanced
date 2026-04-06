import json
import logging
from datetime import UTC, datetime

logger = logging.getLogger(__name__)


def log_admin_event(
    *,
    action: str,
    subject: str,
    issuer: str,
    role: str | None = None,
    tenant_id: str = "default",
    request_id: str | None = None,
    metadata: dict | None = None,
) -> None:
    """Emit a structured JSON admin audit event to stdout.

    action: token_issued | apikey_issued | apikey_rotated | apikey_revoked
    """
    entry: dict = {
        "event_type": "admin_action",
        "timestamp": datetime.now(UTC).isoformat(),
        "action": action,
        "subject": subject,
        "role": role,
        "issuer": issuer,
        "tenant_id": tenant_id,
        "request_id": request_id,
    }
    if metadata:
        entry.update(metadata)
    print(json.dumps(entry), flush=True)
