import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

_LOG_PATH: str = os.getenv("LOG_PATH", "/var/log/ritapi_advanced.jsonl")


def _ensure_log_file(path: str) -> bool:
    """Create parent directories and the log file if they do not exist.
    Returns False if the path is not writable."""
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.touch(exist_ok=True)
        return True
    except OSError as e:
        logger.warning("Cannot create log file at %s: %s — falling back to stderr", path, e)
        return False


def log_request(
    *,
    client_ip: str,
    path: str,
    method: str,
    action: str,           # "allow" | "block" | "monitor"
    detection_type: str,   # e.g. "rate_limit", "xss", "sqli", "bot", "none"
    score: float = 0.0,
    reasons: str = "",
) -> None:
    """
    Append one JSONL entry to LOG_PATH.

    All writes are best-effort — a logging failure will never raise to the caller.
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client_ip": client_ip,
        "path": path,
        "method": method,
        "action": action,
        "detection_type": detection_type,
        "score": round(score, 4),
        "reasons": reasons,
    }

    try:
        line = json.dumps(entry, ensure_ascii=False)
        path_ok = _ensure_log_file(_LOG_PATH)
        if path_ok:
            with open(_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        else:
            # Fallback: emit to stderr via logging
            logger.warning("RITAPI_LOG %s", line)
    except Exception as e:
        logger.error("log_request failed: %s", e)
