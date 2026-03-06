#!/usr/bin/env bash
# scripts/smoke_test.sh — Post-deploy validation for RitAPI Advanced
#
# Validates all critical paths against a running instance.
# Exits non-zero on any failure (suitable for CI/CD gate).
#
# Usage:
#   bash scripts/smoke_test.sh [BASE_URL] [ADMIN_SECRET]
#
# Examples:
#   bash scripts/smoke_test.sh http://localhost
#   bash scripts/smoke_test.sh https://staging.example.com "$ADMIN_SECRET"
#
# Environment variables (override positional args):
#   SMOKE_BASE_URL    — base URL (default: http://localhost)
#   SMOKE_ADMIN_SECRET — admin secret for token endpoint

set -euo pipefail

BASE_URL="${1:-${SMOKE_BASE_URL:-http://localhost}}"
ADMIN_SECRET="${2:-${SMOKE_ADMIN_SECRET:-}}"

PASS=0
FAIL=0
SKIP=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

green="\033[0;32m"
red="\033[0;31m"
yellow="\033[0;33m"
reset="\033[0m"

pass() { echo -e "${green}  PASS${reset}  $1"; ((PASS++)); }
fail() { echo -e "${red}  FAIL${reset}  $1"; ((FAIL++)); }
skip() { echo -e "${yellow}  SKIP${reset}  $1 (reason: $2)"; ((SKIP++)); }

# check URL STATUS [BODY_PATTERN] [EXTRA_CURL_ARGS...]
# Returns pass/fail based on HTTP status code match.
check() {
    local label="$1"
    local expected_status="$2"
    local url="$3"
    shift 3
    local extra_args=("$@")

    local response
    response=$(curl -sk -o /tmp/smoke_body -w "%{http_code}" \
        --max-time 10 "${extra_args[@]}" "$url" 2>/dev/null || echo "000")

    if [[ "$response" == "$expected_status" ]]; then
        pass "$label [HTTP $response]"
    else
        fail "$label — expected HTTP $expected_status, got $response"
        cat /tmp/smoke_body 2>/dev/null | head -5 || true
    fi
}

echo ""
echo "RitAPI Advanced — Smoke Test"
echo "Target: $BASE_URL"
echo "========================================"

# ---------------------------------------------------------------------------
# 1. Health / bypass endpoints (no auth needed)
# ---------------------------------------------------------------------------
echo ""
echo "--- Bypass Endpoints ---"

check "/healthz returns 200" 200 "$BASE_URL/healthz"
check "/metrics returns 200" 200 "$BASE_URL/metrics"

# ---------------------------------------------------------------------------
# 2. Dashboard (no auth — bypass prefix)
# ---------------------------------------------------------------------------
echo ""
echo "--- Dashboard ---"

check "/dashboard returns 200" 200 "$BASE_URL/dashboard"
check "/dashboard/stats returns 200" 200 "$BASE_URL/dashboard/stats"
check "/dashboard/status returns 200" 200 "$BASE_URL/dashboard/status"

# ---------------------------------------------------------------------------
# 3. Auth enforcement — unauthenticated requests to protected routes → 401
# ---------------------------------------------------------------------------
echo ""
echo "--- Auth Enforcement ---"

check "/api/resource 401 without auth" 401 "$BASE_URL/api/resource"

# ---------------------------------------------------------------------------
# 4. Admin bootstrap and JWT issuance
# ---------------------------------------------------------------------------
echo ""
echo "--- Admin / JWT ---"

if [[ -z "$ADMIN_SECRET" ]]; then
    skip "Admin token issuance" "SMOKE_ADMIN_SECRET not set"
    JWT=""
else
    TOKEN_RESP=$(curl -sk -o /tmp/smoke_token -w "%{http_code}" \
        --max-time 10 \
        -X POST "$BASE_URL/admin/token" \
        -H "X-Admin-Secret: $ADMIN_SECRET" \
        -H "Content-Type: application/json" \
        -d '{"sub":"smoke-test","role":"VIEWER"}' 2>/dev/null || echo "000")

    if [[ "$TOKEN_RESP" == "200" ]]; then
        pass "POST /admin/token [HTTP 200]"
        JWT=$(python3 -c "import json,sys; print(json.load(open('/tmp/smoke_token'))['access_token'])" 2>/dev/null || echo "")
    else
        fail "POST /admin/token — expected 200, got $TOKEN_RESP"
        JWT=""
    fi
fi

# ---------------------------------------------------------------------------
# 5. Authenticated requests with JWT
# ---------------------------------------------------------------------------
echo ""
echo "--- JWT Auth ---"

if [[ -z "$JWT" ]]; then
    skip "JWT-authenticated requests" "no JWT (admin secret not provided or token failed)"
else
    check "GET /api/resource with JWT → 404 (auth passed)" 404 \
        "$BASE_URL/api/resource" \
        -H "Authorization: Bearer $JWT"

    check "GET /dashboard/stats with JWT → 200" 200 \
        "$BASE_URL/dashboard/stats" \
        -H "Authorization: Bearer $JWT"
fi

# ---------------------------------------------------------------------------
# 6. WAF — injection payloads are blocked
# ---------------------------------------------------------------------------
echo ""
echo "--- WAF Blocking ---"

check "XSS script tag → 403" 403 \
    "$BASE_URL/api/data" \
    -X POST \
    -H "Content-Type: application/json" \
    -d '{"input":"<script>alert(1)</script>"}'

check "SQLi UNION SELECT → 403" 403 \
    "$BASE_URL/api/data?id=1%20UNION%20SELECT%20username%20FROM%20users"

check "Path traversal → 403" 403 \
    "$BASE_URL/api/data?path=../../etc/passwd"

# ---------------------------------------------------------------------------
# 7. Rate limiter
# ---------------------------------------------------------------------------
echo ""
echo "--- Rate Limiter ---"

# Hit a non-bypass endpoint rapidly; at least one should be 429 within 150 hits
RATE_BLOCKED=false
for i in $(seq 1 150); do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
        "$BASE_URL/api/resource" 2>/dev/null || echo "000")
    if [[ "$STATUS" == "429" ]]; then
        RATE_BLOCKED=true
        break
    fi
done

if $RATE_BLOCKED; then
    pass "Rate limiter returns 429 under load"
else
    fail "Rate limiter never returned 429 after 150 requests to /api/resource"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "========================================"
echo -e "Results: ${green}${PASS} passed${reset}  ${red}${FAIL} failed${reset}  ${yellow}${SKIP} skipped${reset}"
echo ""

if (( FAIL > 0 )); then
    echo -e "${red}Smoke test FAILED — $FAIL check(s) did not pass.${reset}"
    exit 1
else
    echo -e "${green}Smoke test PASSED.${reset}"
    exit 0
fi
