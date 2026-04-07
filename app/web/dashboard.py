"""
RitAPI Advanced — Security Dashboard

Routes:
  GET  /dashboard          → HTML page (served from template)
  GET  /dashboard/events   → JSON: last N entries from JSONL log
  GET  /dashboard/stats    → JSON: aggregate counts + Redis key stats
  GET  /dashboard/status   → JSON: service health (Redis, YARA)
"""
import hmac
import json
import logging
import os
from collections import Counter
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from app.utils.redis_client import RedisClientSingleton
from app.utils.yara_scanner import get_yara_scanner

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])
templates = Jinja2Templates(directory="app/web/templates")

_LOG_PATH = os.getenv("LOG_PATH", "/var/log/ritapi_advanced.jsonl")
_DEFAULT_TAIL = 200  # lines to read from end of log

# Optional dashboard access token. If set, all /dashboard routes require
# Authorization: Bearer <DASHBOARD_TOKEN>.  Leave unset to keep dashboard open.
_DASHBOARD_TOKEN: str | None = os.getenv("DASHBOARD_TOKEN")


def _require_dashboard_access(request: Request) -> None:
    """Dependency: enforce DASHBOARD_TOKEN if configured."""
    if _DASHBOARD_TOKEN is None:
        return  # open access — DASHBOARD_TOKEN not set
    auth = request.headers.get("authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    if not hmac.compare_digest(token, _DASHBOARD_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Dashboard access requires a valid DASHBOARD_TOKEN.",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tail_jsonl(path: str, n: int) -> list[dict]:
    """Read the last n lines of a JSONL file without loading the whole file.

    Uses an expanding-chunk reverse reader so truncation never silently drops
    lines regardless of actual line length.  Doubles the read window until n
    complete lines are found or the entire file has been consumed.
    """
    p = Path(path)
    if not p.exists():
        return []

    try:
        with p.open("rb") as f:
            f.seek(0, 2)
            file_size = f.tell()
            if file_size == 0:
                return []

            chunk_size = max(8192, n * 512)  # start at 8 KB or 512 B/line estimate
            offset = file_size

            while True:
                offset = max(0, offset - chunk_size)
                f.seek(offset)
                raw = f.read().decode("utf-8", errors="replace")
                lines = [ln for ln in raw.splitlines() if ln.strip()]

                # If we've read the whole file OR have enough lines, stop
                if offset == 0 or len(lines) >= n + 1:
                    break
                # Double the window and retry
                chunk_size *= 2

        tail = lines[-n:]
        result = []
        for line in reversed(tail):  # newest first
            try:
                result.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return result
    except Exception as e:
        logger.error("Failed to read log: %s", e)
        return []


def _redis_stats() -> dict[str, Any]:
    redis = RedisClientSingleton.get_client()
    if redis is None:
        return {"connected": False, "rate_limited_ips": 0, "bot_risk_ips": 0, "api_keys": 0}

    try:
        # Use SCAN instead of KEYS to avoid blocking Redis on large keyspaces (R2-M-1)
        rate_count = sum(1 for _ in redis.scan_iter("ritapi:*:rate:ip:*"))
        bot_count = sum(1 for _ in redis.scan_iter("ritapi:*:bot:risk:*"))
        api_key_count = sum(1 for _ in redis.scan_iter("ritapi:apikey:*"))
        return {
            "connected": True,
            "rate_limited_ips": rate_count,
            "bot_risk_ips": bot_count,
            "api_keys": api_key_count,
        }
    except Exception as e:
        logger.error("Redis stats error: %s", e)
        return {"connected": False, "rate_limited_ips": 0, "bot_risk_ips": 0, "api_keys": 0}


def _aggregate(events: list[dict]) -> dict[str, Any]:
    actions = Counter(e.get("action", "unknown") for e in events)
    detection_types = Counter(e.get("detection_type", "none") for e in events)
    top_ips = (
        Counter(e.get("client_ip", "") for e in events if e.get("action") == "block")
        .most_common(5)
    )

    return {
        "total": len(events),
        "blocked": actions.get("block", 0),
        "monitored": actions.get("monitor", 0),
        "allowed": actions.get("allow", 0),
        "by_detection_type": dict(detection_types.most_common(10)),
        "top_blocked_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("", response_class=HTMLResponse)
async def dashboard_page(request: Request, _: None = Depends(_require_dashboard_access)):
    return templates.TemplateResponse(request, "dashboard.html")


@router.get("/events")
async def dashboard_events(limit: int = 100, _: None = Depends(_require_dashboard_access)):
    events = _tail_jsonl(_LOG_PATH, max(1, min(limit, 500)))
    return JSONResponse({"events": events, "total": len(events)})


@router.get("/stats")
async def dashboard_stats(_: None = Depends(_require_dashboard_access)):
    events = _tail_jsonl(_LOG_PATH, _DEFAULT_TAIL)
    agg = _aggregate(events)
    redis_info = _redis_stats()
    return JSONResponse({**agg, "redis": redis_info})


@router.get("/status")
async def dashboard_status(_: None = Depends(_require_dashboard_access)):
    redis = RedisClientSingleton.get_client()
    redis_ok = False
    if redis:
        try:
            redis.ping()
            redis_ok = True
        except Exception:  # noqa: S110 — Redis ping is a best-effort liveness check
            pass

    scanner = get_yara_scanner()

    log_path = Path(_LOG_PATH)

    return JSONResponse({
        "service": "ritapi-advanced",
        "redis": "ok" if redis_ok else "unavailable",
        "yara": "loaded" if scanner.rules_loaded else "no_rules",
        "log_file": "ok" if log_path.exists() else "missing",
        "log_path": _LOG_PATH,
    })
