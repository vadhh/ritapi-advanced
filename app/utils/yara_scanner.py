"""
YARA scanner utility for HTTP payload inspection.

Ported from minifw-ai-standalone/app/minifw_ai/utils/yara_scanner.py.
Changes from source:
  - Env var: MINIFW_YARA_RULES → YARA_RULES_DIR
  - Removed gambling/DNS-specific comments; targeted at HTTP attack payloads
  - Module-level singleton via get_yara_scanner()
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    yara = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


@dataclass
class YARAMatch:
    rule: str
    namespace: str
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    strings: list[tuple] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "namespace": self.namespace,
            "tags": self.tags,
            "meta": self.meta,
            "match_count": len(self.strings),
            "timestamp": self.timestamp,
        }

    def get_severity(self) -> str:
        return self.meta.get("severity", "medium")

    def get_category(self) -> str:
        return self.meta.get("category", "unknown")


class YARAScanner:
    """
    YARA-based HTTP payload scanner.

    Scans request bodies and headers against compiled YARA rules.
    Gracefully no-ops when yara-python is not installed or no rules are found.
    """

    def __init__(
        self,
        rules_dir: str | None = None,
        max_scan_size: int = 2 * 1024 * 1024,  # 2 MB — matches PRD body limit
    ):
        self.max_scan_size = max_scan_size
        self.compiled_rules: Any | None = None
        self.rules_loaded = False
        self.total_scans = 0
        self.total_matches = 0
        self.scans_by_category: dict[str, int] = {}

        if not YARA_AVAILABLE:
            logger.warning("yara-python not installed — YARA scanning disabled.")
            return

        if rules_dir is None:
            rules_dir = os.getenv("YARA_RULES_DIR", "/opt/ritapi_advanced/yara_rules")

        self.rules_dir = Path(rules_dir)

        if self.rules_dir.exists():
            try:
                self.compile_rules()
            except Exception as e:
                logger.warning("Failed to load YARA rules from %s: %s", self.rules_dir, e)

    def compile_rules(self, rules_dir: str | None = None) -> bool:
        if not YARA_AVAILABLE:
            return False

        if rules_dir:
            self.rules_dir = Path(rules_dir)

        if not self.rules_dir.exists():
            raise FileNotFoundError(f"YARA rules directory not found: {self.rules_dir}")

        rule_files = list(self.rules_dir.glob("**/*.yar")) + list(self.rules_dir.glob("**/*.yara"))

        if not rule_files:
            logger.warning("No .yar/.yara files found in %s", self.rules_dir)
            return False

        # One namespace per file — use filename stem so all files are included
        rule_dict: dict[str, str] = {}
        for rule_file in rule_files:
            ns = rule_file.stem  # e.g. "sqli", "xss", "shell_injection"
            if ns not in rule_dict:
                rule_dict[ns] = str(rule_file)

        self.compiled_rules = yara.compile(filepaths=rule_dict)
        self.rules_loaded = True
        logger.info("YARA: compiled %d namespace(s) from %s", len(rule_dict), self.rules_dir)
        return True

    def scan_payload(self, payload: bytes | str, timeout: int = 30) -> list[YARAMatch]:
        if not self.rules_loaded:
            return []

        if isinstance(payload, str):
            payload = payload.encode("utf-8", errors="ignore")

        if len(payload) > self.max_scan_size:
            logger.debug("YARA: payload too large (%d bytes), skipping", len(payload))
            return []

        try:
            raw_matches = self.compiled_rules.match(data=payload, timeout=timeout)
        except Exception as e:
            logger.error("YARA scan error: %s", e)
            return []

        results: list[YARAMatch] = []
        for m in raw_matches:
            strings: list[tuple] = []
            for s in (m.strings or []):
                if hasattr(s, "instances"):
                    for i in s.instances:
                        strings.append((
                            i.offset, s.identifier,
                            i.matched_data.decode("utf-8", errors="ignore"),
                        ))
                elif isinstance(s, tuple) and len(s) >= 3:
                    strings.append((s[0], s[1], s[2].decode("utf-8", errors="ignore")))

            match = YARAMatch(
                rule=m.rule,
                namespace=m.namespace,
                tags=list(m.tags) if m.tags else [],
                meta=dict(m.meta) if m.meta else {},
                strings=strings,
            )
            results.append(match)
            cat = match.get_category()
            self.scans_by_category[cat] = self.scans_by_category.get(cat, 0) + 1

        self.total_scans += 1
        self.total_matches += len(results)

        if results:
            logger.info("YARA: %d match(es) in %d-byte payload", len(results), len(payload))

        return results

    def get_stats(self) -> dict:
        return {
            "rules_loaded": self.rules_loaded,
            "rules_dir": str(getattr(self, "rules_dir", "n/a")),
            "total_scans": self.total_scans,
            "total_matches": self.total_matches,
            "match_rate": self.total_matches / self.total_scans if self.total_scans else 0.0,
            "scans_by_category": self.scans_by_category,
        }

    def reset_stats(self) -> None:
        self.total_scans = 0
        self.total_matches = 0
        self.scans_by_category = {}


_scanner_instance: YARAScanner | None = None


def get_yara_scanner(rules_dir: str | None = None, force_reload: bool = False) -> YARAScanner:
    global _scanner_instance
    if _scanner_instance is None or force_reload:
        _scanner_instance = YARAScanner(rules_dir=rules_dir)
    return _scanner_instance
