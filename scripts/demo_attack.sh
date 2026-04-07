#!/usr/bin/env bash
# scripts/demo_attack.sh — live attack suite for RitAPI Advanced
#
# Fires 6 scenarios that exercise every protection layer.
# Re-runnable standalone once the stack is up:
#   docker compose -f docker/demo.yml up -d
#   ./scripts/demo_attack.sh
#
# Environment overrides:
#   RITAPI_BASE_URL   (default: http://localhost:8001)
#   ADMIN_SECRET      (default: demo-admin-ritapi-2024)
#   CONTAINER_APP     (default: ritapi-demo-app)

set -uo pipefail

BASE_URL="${RITAPI_BASE_URL:-http://localhost:8001}"
ADMIN_SECRET="${ADMIN_SECRET:-demo-admin-ritapi-2024}"
CONTAINER_APP="${CONTAINER_APP:-ritapi-demo-app}"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

PASS=0; FAIL=0

_banner() {
    echo ""
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║  $1${NC}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
}

_expect() {
    local label="$1" expected="$2" actual="$3" detail="${4:-}"
    if [ "$actual" = "$expected" ]; then
        echo -e "  ${GREEN}✓ PASS${NC}  ${BOLD}$label${NC} → HTTP $actual"
        PASS=$((PASS+1))
    else
        echo -e "  ${RED}✗ FAIL${NC}  ${BOLD}$label${NC} → expected $expected, got $actual"
        [ -n "$detail" ] && echo -e "         ${DIM}$detail${NC}"
        FAIL=$((FAIL+1))
    fi
}

_fire() {
    # Usage: _fire [curl args...]
    # Returns HTTP status code; response body → /tmp/_demo_body.json
    curl -s -o /tmp/_demo_body.json -w "%{http_code}" "$@"
}

_body() { cat /tmp/_demo_body.json 2>/dev/null; }

_pause() { echo -e "  ${DIM}⏸  $*${NC}"; sleep "${DEMO_PAUSE:-1}"; }

# ── 0. Token setup ─────────────────────────────────────────────────────────────
_banner "TOKEN SETUP"

_issue_token() {
    local subject="$1" role="$2" tenant="$3"
    curl -s -X POST "$BASE_URL/admin/token" \
        -H "Content-Type: application/json" \
        -H "X-Admin-Secret: $ADMIN_SECRET" \
        -d "{\"subject\":\"$subject\",\"role\":\"$role\",\"tenant_id\":\"$tenant\"}" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('access_token',''))"
}

echo -e "  ${DIM}Issuing demo tokens via admin API...${NC}"
TOKEN_ACME=$(_issue_token "demo-acme"    "VIEWER" "acme")
TOKEN_DEFAULT=$(_issue_token "demo-default" "VIEWER" "default")

if [ -z "$TOKEN_ACME" ] || [ -z "$TOKEN_DEFAULT" ]; then
    echo -e "  ${RED}✗ Token issuance failed — is the stack running?${NC}"
    echo "    Start with: docker compose -f docker/demo.yml up -d"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} Tokens issued: ${BOLD}acme${NC}, ${BOLD}default${NC}"

# Issue a token bound to 'corp' tenant — used with X-Target-ID: acme to show mismatch block.
# (Same enforcement path as a no-tid legacy token: credential tenant != claimed tenant → 403)
TOKEN_WRONG_TENANT=$(_issue_token "demo-corp" "VIEWER" "corp")
echo -e "  ${GREEN}✓${NC} Mismatched tenant token issued (corp, will be sent claiming acme)"

sleep 1

# ═══════════════════════════════════════════════════════════════════════════════
# ACT 1 — BASELINE: valid request reaches the backend
# ═══════════════════════════════════════════════════════════════════════════════
_banner "ACT 1 — BASELINE (valid credential + matching tenant)"
echo -e "  ${DIM}Token bound to tenant 'acme' | X-Target-ID: acme${NC}"
_pause "Firing clean request..."

STATUS=$(_fire "$BASE_URL/probe" \
    -H "Authorization: Bearer $TOKEN_ACME" \
    -H "X-Target-ID: acme")
_expect "Clean pass-through" "200" "$STATUS" "$(_body)"
echo -e "  ${DIM}Response: $(_body)${NC}"

# ═══════════════════════════════════════════════════════════════════════════════
# ACT 2 — TENANT SECURITY: mismatch and unbound credential
# ═══════════════════════════════════════════════════════════════════════════════
_banner "ACT 2 — TENANT ISOLATION"

echo -e "  ${DIM}[2a] Token bound to 'acme', header claims 'corp' — should block${NC}"
_pause "Firing tenant mismatch..."
STATUS=$(_fire "$BASE_URL/probe" \
    -H "Authorization: Bearer $TOKEN_ACME" \
    -H "X-Target-ID: corp")
_expect "Tenant mismatch → block" "403" "$STATUS"
echo -e "  ${DIM}Detail: $(python3 -c "import json,sys; d=json.load(open('/tmp/_demo_body.json')); print(d.get('detail',''))" 2>/dev/null)${NC}"

_pause

echo -e "  ${DIM}[2b] Token bound to 'corp', header claims 'acme' — second mismatch variant${NC}"
_pause "Firing second tenant mismatch..."
STATUS=$(_fire "$BASE_URL/probe" \
    -H "Authorization: Bearer $TOKEN_WRONG_TENANT" \
    -H "X-Target-ID: acme")
_expect "Wrong tenant token → block" "403" "$STATUS"
echo -e "  ${DIM}Detail: $(python3 -c "import json,sys; d=json.load(open('/tmp/_demo_body.json')); print(d.get('detail',''))" 2>/dev/null)${NC}"

# ═══════════════════════════════════════════════════════════════════════════════
# ACT 3 — INJECTION WAF: SQLi and XSS in URL
# ═══════════════════════════════════════════════════════════════════════════════
_banner "ACT 3 — INJECTION WAF (SQL injection + XSS)"

echo -e "  ${DIM}[3a] SQLi pattern in query string${NC}"
_pause "Firing SQL injection..."
# UNION SELECT NULL -- URL-encoded (%20 for spaces, no ambiguous + decoding)
STATUS=$(_fire "$BASE_URL/probe?q=1%20UNION%20SELECT%20NULL--" \
    -H "Authorization: Bearer $TOKEN_DEFAULT" \
    -H "X-Target-ID: default")
_expect "SQLi URL → block" "403" "$STATUS"

_pause

echo -e "  ${DIM}[3b] XSS payload in query string${NC}"
_pause "Firing XSS injection..."
# <script>alert(1)</script> URL-encoded
STATUS=$(_fire "$BASE_URL/probe?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E" \
    -H "Authorization: Bearer $TOKEN_DEFAULT" \
    -H "X-Target-ID: default")
_expect "XSS URL → block" "403" "$STATUS"

echo -e "  ${DIM}[3c] Command injection in query string${NC}"
_pause "Firing command injection..."
# ; cat /etc/passwd URL-encoded
STATUS=$(_fire "$BASE_URL/probe?q=%3B+cat+%2Fetc%2Fpasswd" \
    -H "Authorization: Bearer $TOKEN_DEFAULT" \
    -H "X-Target-ID: default")
_expect "CMDi URL → block" "403" "$STATUS"

# ═══════════════════════════════════════════════════════════════════════════════
# ACT 4 — BOT DETECTION: scanner user-agent
# ═══════════════════════════════════════════════════════════════════════════════
_banner "ACT 4 — BOT DETECTION (scanner user-agent)"
echo -e "  ${DIM}User-Agent: sqlmap/1.7.8 — known scanner fingerprint${NC}"

# Fire a few requests so bot detection accumulates enough signal to block.
# The default policy action for bot detections is 'block' after threshold.
_pause "Firing bot requests (3 needed to accumulate risk score)..."
for i in 1 2 3; do
    S=$(_fire "$BASE_URL/probe" \
        -H "Authorization: Bearer $TOKEN_DEFAULT" \
        -H "X-Target-ID: default" \
        -H "User-Agent: sqlmap/1.7.8" \
        -H "X-Forwarded-For: 10.99.demo.bot.1")
    echo -e "    ${DIM}Request $i → HTTP $S${NC}"
    sleep 0.3
done

# Final request — should be blocked at this point
STATUS=$(_fire "$BASE_URL/probe" \
    -H "Authorization: Bearer $TOKEN_DEFAULT" \
    -H "X-Target-ID: default" \
    -H "User-Agent: sqlmap/1.7.8" \
    -H "X-Forwarded-For: 10.99.demo.bot.1")
_expect "Scanner UA → block" "403" "$STATUS"

# ═══════════════════════════════════════════════════════════════════════════════
# ACT 5 — RATE LIMITING: burst 10 req/30s limit
# Uses /dashboard (no auth required, default policy → block on breach)
# ═══════════════════════════════════════════════════════════════════════════════
_banner "ACT 5 — RATE LIMITING (${RATE_LIMIT:-10} req / 30s)"
echo -e "  ${DIM}Firing 12 rapid requests from the same IP — limit is 10${NC}"

LAST_STATUS=""
for i in $(seq 1 12); do
    LAST_STATUS=$(_fire "$BASE_URL/dashboard" \
        -H "X-Forwarded-For: 10.99.demo.rate.1")
    printf "    ${DIM}%2d/12 → HTTP %s${NC}\n" "$i" "$LAST_STATUS"
done

_expect "Burst limit → 429" "429" "$LAST_STATUS"
echo -e "  ${DIM}Response: $(_body)${NC}"

# ═══════════════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║  DEMO SUMMARY${NC}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
echo -e "  ${GREEN}Passed: $PASS${NC}  ${RED}Failed: $FAIL${NC}"
echo ""
echo -e "  ${BOLD}SIEM events (live):${NC}"
echo -e "    ${DIM}docker compose -f docker/demo.yml logs --no-log-prefix app 2>/dev/null | grep '\"event_type\"' | tail -8 | python3 -m json.tool${NC}"
echo ""
echo -e "  ${BOLD}Dashboard:${NC}  ${CYAN}http://localhost:8001/dashboard${NC}"
echo -e "  ${BOLD}Metrics:${NC}    ${CYAN}http://localhost:8001/metrics${NC}"
echo ""

[ "$FAIL" -gt 0 ] && exit 1 || exit 0
