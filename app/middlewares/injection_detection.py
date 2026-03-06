"""
Injection Detection Middleware — regex + YARA

Regex patterns ported from _archive/ritapi_v/ritapi/utils/waf.py (full production WAF).
YARA scan is attempted after regex; silently skipped if scanner not loaded.
"""
import html
import logging
import re
from urllib.parse import unquote

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.utils.logging import log_request
from app.utils.metrics import injection_blocks, requests_total, threat_score

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# WAF patterns (ported from _archive/ritapi_v/ritapi/utils/waf.py)
# ---------------------------------------------------------------------------

XSS_PATTERNS = [
    re.compile(r"(?i)<\s*script.*?>.*?<\s*/\s*script\s*>"),
    re.compile(r"(?i)<\s*script[^>]*>"),
    re.compile(r"(?i)\bon\w+\s*="),
    re.compile(r"(?i)onerror\s*="),
    re.compile(r"(?i)onload\s*="),
    re.compile(r"(?i)onmouseover\s*="),
    re.compile(r"(?i)javascript\s*:"),
    re.compile(r"(?i)vbscript\s*:"),
    re.compile(r"(?i)data\s*:text/html"),
    re.compile(r"(?i)<iframe[^>]*"),
    re.compile(r"(?i)<img\s+.*?onerror\s*="),
    re.compile(r"(?i)<svg[^>]*onload"),
    re.compile(r"(?i)<body[^>]*onload"),
    re.compile(r"(?i)<object[^>]*>"),
    re.compile(r"(?i)<embed[^>]*>"),
    re.compile(r"(?i)<applet[^>]*>"),
    re.compile(r"(?i)<meta[^>]*http-equiv"),
    re.compile(r"(?i)<link[^>]*href"),
    re.compile(r"(?i)<base[^>]*href"),
]

SQLI_PATTERNS = [
    re.compile(r"(?i)(union\s+select)"),
    re.compile(r"(?i)(select\s+.{1,100}\s+from)"),
    re.compile(r"(?i)(insert\s+into)"),
    re.compile(r"(?i)(delete\s+from)"),
    re.compile(r"(?i)(drop\s+table)"),
    re.compile(r"(?i)(drop\s+database)"),
    re.compile(r"(?i)(update\s+.+\s+set)"),
    re.compile(r"--[^\n]*"),
    re.compile(r"/\*.*?\*/"),
    re.compile(r"#[^\n]*"),
    re.compile(r"(?i)(\bor\b\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?)"),
    re.compile(r"(?i)(\band\b\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?)"),
    re.compile(r"(?i)(\bor\b\s+1\s*=\s*1)"),
    re.compile(r"(?i)('\s*or\s*')"),
    re.compile(r"(?i)('\s*or\s+1\s*=\s*1)"),
    re.compile(r"(?i)(sleep\s*\()"),
    re.compile(r"(?i)(waitfor\s+delay)"),
    re.compile(r"(?i)(benchmark\s*\()"),
    re.compile(r"(?i)(;\s*drop)"),
    re.compile(r"(?i)(;\s*delete)"),
    re.compile(r"(?i)(;\s*update)"),
    re.compile(r"(?i)(0x[0-9a-f]{2,})"),
]

CMDI_PATTERNS = [
    re.compile(r";\s*(ls|cat|wget|curl|nc|bash|sh|chmod|rm|cp|mv|touch|echo|pwd|whoami|id|uname)"),
    re.compile(r"\|\s*(ls|cat|wget|curl|nc|bash|sh|chmod|rm|cp|mv|touch|echo|pwd|whoami|id|uname)"),
    re.compile(r"&&\s*(ls|cat|wget|curl|nc|bash|sh|chmod|rm|cp|mv|touch|echo|pwd|whoami|id|uname)"),
    re.compile(r"\|\|\s*(ls|cat|wget|curl|nc|bash|sh|chmod|rm|cp|mv|touch|echo|pwd|whoami|id|uname)"),
    re.compile(r"\$\([^)]+\)"),
    re.compile(r"`[^`]+`"),
    re.compile(r"\$\{[^}]+\}"),
    re.compile(r"(?i)\b(bash|sh|zsh|dash)\b\s+-c"),
    re.compile(r"(?i)/bin/(ba)?sh"),
    re.compile(r"(?i)\b(wget|curl)\b\s+http"),
    re.compile(r"(?i)\b(nc|netcat)\b\s+"),
    re.compile(r"(?i)(cat\s+/etc/passwd)"),
    re.compile(r"(?i)(cat\s+/etc/shadow)"),
    re.compile(r"(?i)(cat\s+/etc/hosts)"),
    re.compile(r"(?i)\b(whoami|id|uname|pwd|hostname)\b"),
]

PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./"),
    re.compile(r"\.\./\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"%2e%2e/"),
    re.compile(r"%2e%2e%2f"),
    re.compile(r"%5c%5c"),
    re.compile(r"\.\.\;"),
    re.compile(r"\.\.%2f"),
    re.compile(r"%252e%252e"),
    re.compile(r"(?i)/etc/passwd"),
    re.compile(r"(?i)/etc/shadow"),
    re.compile(r"(?i)/etc/hosts"),
    re.compile(r"(?i)windows/system32"),
    re.compile(r"(?i)boot\.ini"),
]

LDAP_PATTERNS = [
    re.compile(r"\*\)"),
    re.compile(r"\(\|"),
    re.compile(r"\(&"),
    re.compile(r"(?i)(objectclass=\*)"),
]

SCANNER_UA_PATTERNS = [
    re.compile(r"(?i)(sqlmap)"),
    re.compile(r"(?i)(nikto)"),
    re.compile(r"(?i)\b(nmap)\b"),
    re.compile(r"(?i)(nessus)"),
    re.compile(r"(?i)(acunetix)"),
    re.compile(r"(?i)(w3af)"),
    re.compile(r"(?i)\b(burp|burp\s+suite)\b"),
    re.compile(r"(?i)(owasp|zap)"),
    re.compile(r"(?i)(metasploit)"),
    re.compile(r"(?i)(havij)"),
    re.compile(r"(?i)(pangolin)"),
    re.compile(r"(?i)(webinspect)"),
    re.compile(r"(?i)(appscan)"),
    re.compile(r"(?i)(python-urllib)"),
    re.compile(r"(?i)(python-requests)"),
    re.compile(r"(?i)curl/[0-7]\."),
]

_PATTERN_MAP = [
    ("xss", XSS_PATTERNS),
    ("sqli", SQLI_PATTERNS),
    ("cmdi", CMDI_PATTERNS),
    ("path_traversal", PATH_TRAVERSAL_PATTERNS),
    ("ldap", LDAP_PATTERNS),
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize(value: str) -> str:
    value = html.unescape(value)
    prev, iterations = "", 0
    while prev != value and iterations < 3:
        prev = value
        try:
            value = unquote(value)
        except Exception:
            break
        iterations += 1
    return value.replace("\\", "").replace("\x00", "").strip()


def _scan_value(key: str, value: str) -> tuple[bool, str, str]:
    """Return (matched, category, snippet). Scanner UA checked on user_agent key only."""
    if not isinstance(value, str):
        try:
            value = str(value)
        except Exception:
            return False, "", ""

    normalized = _normalize(value)
    candidates = [value, normalized, normalized.lower()]

    if key == "user_agent":
        for candidate in candidates:
            for p in SCANNER_UA_PATTERNS:
                if m := p.search(candidate):
                    return True, "scanner_ua", candidate[max(0, m.start() - 20): m.end() + 20]

    for candidate in candidates:
        for category, patterns in _PATTERN_MAP:
            for p in patterns:
                if m := p.search(candidate):
                    return True, category, candidate[max(0, m.start() - 40): m.end() + 40]

    return False, "", ""


def _scan_recursive(data, key_path: str = "") -> tuple[bool, str, str]:
    if isinstance(data, dict):
        for key, value in data.items():
            full_key = f"{key_path}.{key}" if key_path else key
            if isinstance(value, (dict, list)):
                hit, cat, snippet = _scan_recursive(value, full_key)
            else:
                hit, cat, snippet = _scan_value(key, str(value) if value is not None else "")
            if hit:
                return hit, cat, snippet
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            full_key = f"{key_path}[{idx}]"
            if isinstance(item, (dict, list)):
                hit, cat, snippet = _scan_recursive(item, full_key)
            else:
                hit, cat, snippet = _scan_value(key_path, str(item) if item is not None else "")
            if hit:
                return hit, cat, snippet
    else:
        return _scan_value(key_path, str(data) if data is not None else "")
    return False, "", ""


MAX_BODY = 2 * 1024 * 1024  # 2 MB — per PRD


class InjectionDetectionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        client_ip = (
            (request.headers.get("x-forwarded-for", "").split(",")[0].strip())
            or (request.client.host if request.client else "")
        )

        # --- 1. Scanner user-agent check ---
        ua = request.headers.get("user-agent", "")
        hit, category, snippet = _scan_value("user_agent", ua)
        if hit:
            self._log_and_block(client_ip, request, category, snippet)
            return self._blocked_response(category)

        # --- 2. URL / query string check ---
        raw_url = str(request.url)
        hit, category, snippet = _scan_value("url", raw_url)
        if hit:
            self._log_and_block(client_ip, request, category, snippet)
            return self._blocked_response(category)

        # --- 3. Request body check (POST / PUT / PATCH only) ---
        if request.method in ("POST", "PUT", "PATCH"):
            body = await request.body()

            if len(body) > MAX_BODY:
                log_request(
                    client_ip=client_ip,
                    path=request.url.path,
                    method=request.method,
                    action="block",
                    detection_type="payload_too_large",
                    score=0.5,
                    reasons=f"Body size {len(body)} exceeds {MAX_BODY} bytes",
                )
                return JSONResponse({"error": "Request body too large."}, status_code=413)

            body_text = body.decode("utf-8", errors="replace")

            # Plain text scan
            hit, category, snippet = _scan_value("body", body_text)
            if hit:
                self._log_and_block(client_ip, request, category, snippet)
                return self._blocked_response(category)

            # JSON recursive scan
            import json
            try:
                payload = json.loads(body_text)
                if isinstance(payload, (dict, list)):
                    hit, category, snippet = _scan_recursive(payload)
                    if hit:
                        self._log_and_block(client_ip, request, category, snippet)
                        return self._blocked_response(category)
            except (json.JSONDecodeError, ValueError):
                pass  # not JSON — plain text scan above is sufficient

            # --- 4. YARA scan (best-effort) ---
            try:
                from app.utils.yara_scanner import get_yara_scanner
                scanner = get_yara_scanner()
                if scanner.rules_loaded:
                    matches = scanner.scan_payload(body)
                    if matches:
                        top = matches[0]
                        self._log_and_block(client_ip, request, f"yara:{top.rule}", top.rule)
                        return self._blocked_response("yara")
            except Exception as e:
                logger.debug("YARA scan skipped: %s", e)

        return await call_next(request)

    @staticmethod
    def _log_and_block(client_ip: str, request: Request, category: str, snippet: str) -> None:
        logger.warning("Injection blocked [%s] from %s on %s — %s", category, client_ip, request.url.path, snippet[:80])
        log_request(
            client_ip=client_ip,
            path=request.url.path,
            method=request.method,
            action="block",
            detection_type=category,
            score=1.0,
            reasons=f"Pattern matched: {snippet[:120]}",
        )
        injection_blocks.labels(category=category).inc()
        requests_total.labels(method=request.method, action="block", detection_type=category).inc()
        threat_score.observe(1.0)

    @staticmethod
    def _blocked_response(category: str) -> JSONResponse:
        return JSONResponse(
            {"error": "Blocked by RitAPI", "detail": f"Malicious pattern detected ({category})"},
            status_code=403,
        )
