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
# ACT 3 — INJECTION WAF  (each sub-type uses a distinct attacker IP)
# ═══════════════════════════════════════════════════════════════════════════════
_banner "ACT 3 — INJECTION WAF"

echo -e "  ${DIM}[3a] UNION-based SQL injection — attacker 10.0.attack.1${NC}"
_pause "Firing SQLi..."
STATUS=$(_fire "$BASE_URL/probe?id=1%20UNION%20SELECT%20NULL%2CNULL%2CNULL--" \
    -H "Authorization: Bearer $TOKEN_DEFAULT" \
    -H "X-Target-ID: default" \
    -H "X-Forwarded-For: 10.0.attack.1")
_expect "SQLi UNION SELECT → block" "403" "$STATUS"
echo -e "  ${DIM}Reason: $(python3 -c "import json; d=json.load(open('/tmp/_demo_body.json')); print(d.get('detail',''))" 2>/dev/null)${NC}"

_pause

echo -e "  ${DIM}[3b] Stored XSS — attacker 10.0.attack.2${NC}"
_pause "Firing XSS..."
STATUS=$(_fire "$BASE_URL/probe?name=%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E" \
    -H "Authorization: Bearer $TOKEN_DEFAULT" \
    -H "X-Target-ID: default" \
    -H "X-Forwarded-For: 10.0.attack.2")
_expect "XSS → block" "403" "$STATUS"
echo -e "  ${DIM}Reason: $(python3 -c "import json; d=json.load(open('/tmp/_demo_body.json')); print(d.get('detail',''))" 2>/dev/null)${NC}"

_pause

echo -e "  ${DIM}[3c] Command injection — attacker 10.0.attack.3${NC}"
_pause "Firing CMDi..."
STATUS=$(_fire "$BASE_URL/probe?file=%2Fetc%2Fpasswd%3B%20id%3B%20whoami" \
    -H "Authorization: Bearer $TOKEN_DEFAULT" \
    -H "X-Target-ID: default" \
    -H "X-Forwarded-For: 10.0.attack.3")
_expect "CMDi → block" "403" "$STATUS"

_pause

echo -e "  ${DIM}[3d] Path traversal — attacker 10.0.attack.4${NC}"
_pause "Firing path traversal..."
STATUS=$(_fire "$BASE_URL/probe?path=..%2F..%2F..%2Fetc%2Fshadow" \
    -H "Authorization: Bearer $TOKEN_DEFAULT" \
    -H "X-Target-ID: default" \
    -H "X-Forwarded-For: 10.0.attack.4")
_expect "Path traversal → block" "403" "$STATUS"

_pause

echo -e "  ${DIM}[3e] POST body SQL injection — attacker 10.0.attack.5${NC}"
_pause "Firing SQLi in POST body..."
STATUS=$(_fire -X POST "$BASE_URL/probe" \
    -H "Authorization: Bearer $TOKEN_DEFAULT" \
    -H "X-Target-ID: default" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 10.0.attack.5" \
    -d '{"username":"admin'\''--","password":"anything"}')
_expect "SQLi POST body → block" "403" "$STATUS"

# ═══════════════════════════════════════════════════════════════════════════════
# ACT 4 — BOT DETECTION  (two different scanner signatures)
# ═══════════════════════════════════════════════════════════════════════════════
_banner "ACT 4 — BOT DETECTION (scanner fingerprints)"

echo -e "  ${DIM}[4a] sqlmap — attacker 10.0.bot.1${NC}"
_pause "Firing sqlmap UA (accumulating risk)..."
for i in 1 2 3 4; do
    S=$(_fire "$BASE_URL/probe" \
        -H "Authorization: Bearer $TOKEN_DEFAULT" \
        -H "X-Target-ID: default" \
        -H "User-Agent: sqlmap/1.7.8#stable" \
        -H "X-Forwarded-For: 10.0.bot.1")
    printf "    ${DIM}%d → HTTP %s${NC}\n" "$i" "$S"
    sleep 0.2
done
_expect "sqlmap UA → block" "403" "$S"

_pause

echo -e "  ${DIM}[4b] Nikto scanner — attacker 10.0.bot.2${NC}"
_pause "Firing Nikto UA..."
for i in 1 2 3 4; do
    S=$(_fire "$BASE_URL/probe" \
        -H "Authorization: Bearer $TOKEN_DEFAULT" \
        -H "X-Target-ID: default" \
        -H "User-Agent: Nikto/2.1.6" \
        -H "X-Forwarded-For: 10.0.bot.2")
    printf "    ${DIM}%d → HTTP %s${NC}\n" "$i" "$S"
    sleep 0.2
done
_expect "Nikto UA → block" "403" "$S"

# ═══════════════════════════════════════════════════════════════════════════════
# ACT 5 — RATE LIMITING  (burst from a dedicated attacker IP)
# Uses /dashboard (no auth, default policy → block on breach)
# ═══════════════════════════════════════════════════════════════════════════════
_banner "ACT 5 — RATE LIMITING (${RATE_LIMIT:-50} req / 60s)"
echo -e "  ${DIM}Firing 55 rapid requests from 10.0.flood.1 — limit is 50${NC}"

LAST_STATUS=""; SHOWN_429=0
for i in $(seq 1 55); do
    LAST_STATUS=$(_fire "$BASE_URL/dashboard" \
        -H "X-Forwarded-For: 10.0.flood.1")
    if [ "$LAST_STATUS" = "429" ] && [ "$SHOWN_429" -eq 0 ]; then
        printf "    ${DIM}%2d/55 → HTTP %s  ◄ BLOCKED${NC}\n" "$i" "$LAST_STATUS"
        SHOWN_429=1
    elif [ "$LAST_STATUS" != "429" ]; then
        printf "    ${DIM}%2d/55 → HTTP %s${NC}\n" "$i" "$LAST_STATUS"
    fi
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
