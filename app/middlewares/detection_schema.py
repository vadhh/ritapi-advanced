"""Helpers for writing and reading unified detection objects on request.state."""

from __future__ import annotations

from typing import Any


def _coerce_score(score: Any) -> float:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return 0.0
    if value < 0:
        return 0.0
    if value > 1:
        return 1.0
    return value


def _severity_from_score(score: float) -> str:
    if score >= 0.9:
        return "critical"
    if score >= 0.7:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


def ensure_detections_container(request) -> list[dict[str, Any]]:
    detections = getattr(request.state, "detections", None)
    if isinstance(detections, list):
        return detections
    request.state.detections = []
    return request.state.detections


def append_detection(
    request,
    *,
    detection_type: str,
    score: float,
    reason: str,
    status_code: int,
    source: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    normalized_score = _coerce_score(score)
    detection = {
        "type": detection_type,
        "score": normalized_score,
        "severity": _severity_from_score(normalized_score),
        "reason": reason,
        "status_code": int(status_code),
        "source": source,
        "metadata": metadata or {},
    }
    ensure_detections_container(request).append(detection)
    return detection


def normalize_detection(raw: dict[str, Any]) -> dict[str, Any]:
    detection_type = str(raw.get("type") or raw.get("detection_type") or "unknown")
    reason = str(raw.get("reason") or raw.get("details") or "")
    status_code = raw.get("status_code", 403)
    try:
        status_code = int(status_code)
    except (TypeError, ValueError):
        status_code = 403
    score = _coerce_score(raw.get("score", 0.0))
    source = str(raw.get("source") or "unknown")
    metadata = raw.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}

    return {
        "type": detection_type,
        "score": score,
        "severity": str(raw.get("severity") or _severity_from_score(score)),
        "reason": reason,
        "status_code": status_code,
        "source": source,
        "metadata": metadata,
    }
