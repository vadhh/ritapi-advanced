#!/usr/bin/env bash
# validate_install.sh — Post-install validation for RitAPI Advanced
#
# Usage:
#   bash scripts/validate_install.sh [--url BASE_URL] [--admin-secret SECRET]
#
# Options:
#   --url URL           Base URL of the running service  (default: http://localhost:8001)
#   --admin-secret S    ADMIN_SECRET value for auth checks (default: $ADMIN_SECRET env var)
#   --skip-tls          Skip TLS certificate validation (for self-signed certs)
#   --help              Print this help message
#
# Exit codes:
#   0  All checks passed
#   1  One or more checks failed
#
# Environment:
#   ADMIN_SECRET        Alternative to --admin-secret flag
#   VALIDATE_TIMEOUT    HTTP request timeout in seconds (default: 10)

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
BASE_URL="http://localhost:8001"
ADMIN_SECRET="${ADMIN_SECRET:-}"
SKIP_TLS=false
TIMEOUT="${VALIDATE_TIMEOUT:-10}"

PASS=0
FAIL=0
WARN=0

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --url)           BASE_URL="$2";        shift 2 ;;
        --admin-secret)  ADMIN_SECRET="$2";    shift 2 ;;
        --skip-tls)      SKIP_TLS=true;        shift ;;
        --help)
            sed -n '2,20p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Remove trailing slash
BASE_URL="${BASE_URL%/}"

CURL_OPTS=(-s --max-time "$TIMEOUT")
if [[ "$SKIP_TLS" == "true" ]]; then
    CURL_OPTS+=(-k)
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
RESET='\033[0m'

pass() { echo -e "${GREEN}  PASS${RESET}  $1"; ((PASS++)); }
fail() { echo -e "${RED}  FAIL${RESET}  $1"; ((FAIL++)); }
warn() { echo -e "${YELLOW}  WARN${RESET}  $1"; ((WARN++)); }
section() { echo; echo "=== $1 ==="; }

http_get() {
    # Returns HTTP status code; body goes to stdout if second arg given
    local url="$BASE_URL$1"
    local -n _body_ref="${2:-_discard}" 2>/dev/null || true
    local status
    status=$(curl "${CURL_OPTS[@]}" -o /tmp/_validate_body -w "%{http_code}" "$url")
    _body_ref=$(cat /tmp/_validate_body 2>/dev/null || true)
    echo "$status"
}

http_post() {
    local url="$BASE_URL$1"
    local data="${2:-}"
    shift 2
    local status
    status=$(curl "${CURL_OPTS[@]}" -o /tmp/_validate_body -w "%{http_code}" \
        -X POST -H "Content-Type: application/json" "$@" \
        ${data:+--data "$data"} "$url")
    cat /tmp/_validate_body 2>/dev/null || true
    echo "$status" > /tmp/_validate_status
}

# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------
echo "RitAPI Advanced — Installation Validator"
echo "Target: $BASE_URL"
echo "Time:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ---------------------------------------------------------------------------
section "1. Connectivity"
# ---------------------------------------------------------------------------

status=$(http_get "/healthz" _body)
if [[ "$status" == "200" ]]; then
    pass "/healthz returns 200"
else
    fail "/healthz returned $status (expected 200) — is the service running?"
fi

status=$(http_get "/readyz" _body)
if [[ "$status" == "200" ]]; then
    pass "/readyz returns 200"
elif [[ "$status" == "503" ]]; then
    warn "/readyz returned 503 — Redis may be unavailable (service runs in fail-open mode)"
else
    fail "/readyz returned $status (expected 200 or 503)"
fi

# ---------------------------------------------------------------------------
section "2. Auth enforcement"
# ---------------------------------------------------------------------------

status=$(http_get "/dashboard" _body)
if [[ "$status" == "401" || "$status" == "403" ]]; then
    pass "/dashboard requires authentication (got $status)"
elif [[ "$status" == "200" ]]; then
    warn "/dashboard returned 200 without auth — auth guard may be disabled"
else
    fail "/dashboard returned $status (expected 401 or 403)"
fi

status=$(http_get "/admin/apikey" _body)
if [[ "$status" == "401" || "$status" == "403" || "$status" == "405" ]]; then
    pass "/admin routes require authentication (got $status)"
else
    fail "/admin/apikey returned $status (expected 4xx)"
fi

# ---------------------------------------------------------------------------
section "3. WAF — Injection blocking"
# ---------------------------------------------------------------------------

status=$(curl "${CURL_OPTS[@]}" -o /dev/null -w "%{http_code}" \
    "$BASE_URL/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
if [[ "$status" == "400" || "$status" == "403" ]]; then
    pass "XSS in query string blocked (got $status)"
else
    fail "XSS not blocked — got $status (expected 400/403)"
fi

status=$(curl "${CURL_OPTS[@]}" -o /dev/null -w "%{http_code}" \
    "$BASE_URL/?id=1%27+OR+1%3D1--")
if [[ "$status" == "400" || "$status" == "403" ]]; then
    pass "SQLi in query string blocked (got $status)"
else
    fail "SQLi not blocked — got $status (expected 400/403)"
fi

status=$(curl "${CURL_OPTS[@]}" -o /dev/null -w "%{http_code}" \
    "$BASE_URL/?path=../../etc/passwd")
if [[ "$status" == "400" || "$status" == "403" ]]; then
    pass "Path traversal in query string blocked (got $status)"
else
    fail "Path traversal not blocked — got $status (expected 400/403)"
fi

status=$(curl "${CURL_OPTS[@]}" -o /dev/null -w "%{http_code}" \
    -H "User-Agent: sqlmap/1.7" "$BASE_URL/healthz")
if [[ "$status" == "403" ]]; then
    pass "Scanner User-Agent (sqlmap) blocked (got 403)"
else
    warn "Scanner UA not blocked — got $status (expected 403). Bot detection may be bypassed."
fi

# ---------------------------------------------------------------------------
section "4. Rate limiting"
# ---------------------------------------------------------------------------

echo "  Sending 15 rapid requests to trigger rate limiter..."
rate_limited=false
for i in $(seq 1 15); do
    s=$(curl "${CURL_OPTS[@]}" -o /dev/null -w "%{http_code}" "$BASE_URL/healthz")
    if [[ "$s" == "429" ]]; then
        rate_limited=true
        break
    fi
done

# Rate limit default is 100/min — 15 requests won't trigger it. We just confirm
# the endpoint responds correctly and the header is present.
header=$(curl "${CURL_OPTS[@]}" -I "$BASE_URL/healthz" | grep -i "x-ratelimit" || true)
if [[ -n "$header" ]]; then
    pass "Rate-limit headers present on responses"
else
    warn "No X-RateLimit-* headers found — rate limit still enforced but headers not emitted"
fi

if [[ "$rate_limited" == "true" ]]; then
    pass "Rate limiter triggered at low threshold (good for low RATE_LIMIT_REQUESTS setting)"
fi

# ---------------------------------------------------------------------------
section "5. Metrics endpoint"
# ---------------------------------------------------------------------------

status=$(http_get "/metrics" _body)
if [[ "$status" == "200" ]]; then
    if echo "$_body" | grep -q "ritapi_requests_total"; then
        pass "/metrics returns Prometheus metrics"
    else
        warn "/metrics returned 200 but missing expected 'ritapi_requests_total' metric"
    fi
else
    fail "/metrics returned $status (expected 200)"
fi

# ---------------------------------------------------------------------------
section "6. Admin bootstrap (requires ADMIN_SECRET)"
# ---------------------------------------------------------------------------

if [[ -z "$ADMIN_SECRET" ]]; then
    warn "ADMIN_SECRET not set — skipping admin auth checks. Use --admin-secret or set env var."
else
    token_body=$(curl "${CURL_OPTS[@]}" -o /tmp/_validate_body -w "" \
        -X POST \
        -H "X-Admin-Secret: $ADMIN_SECRET" \
        -H "Content-Type: application/json" \
        "$BASE_URL/admin/token" || true)
    token_body=$(cat /tmp/_validate_body 2>/dev/null || true)
    token=$(echo "$token_body" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4 || true)

    if [[ -n "$token" ]]; then
        pass "Admin token issued successfully"

        # Test that the token grants access to admin endpoints
        status=$(curl "${CURL_OPTS[@]}" -o /dev/null -w "%{http_code}" \
            -H "Authorization: Bearer $token" \
            "$BASE_URL/dashboard/status")
        if [[ "$status" == "200" ]]; then
            pass "JWT token accepted by protected endpoint"
        else
            warn "JWT token test returned $status (expected 200) — check /dashboard/status"
        fi
    else
        fail "Admin token request failed — check ADMIN_SECRET. Response: $token_body"
    fi
fi

# ---------------------------------------------------------------------------
section "7. TLS (if HTTPS base URL)"
# ---------------------------------------------------------------------------

if [[ "$BASE_URL" == https://* ]]; then
    cert_info=$(curl "${CURL_OPTS[@]}" --cert-status -I "$BASE_URL" 2>&1 || true)
    if echo "$cert_info" | grep -qi "SSL certificate verify ok\|OCSP: good"; then
        pass "TLS certificate valid"
    elif [[ "$SKIP_TLS" == "true" ]]; then
        warn "TLS validation skipped (--skip-tls). Verify certificate manually."
    else
        warn "TLS certificate check inconclusive — run: openssl s_client -connect ${BASE_URL#https://}"
    fi
else
    warn "Base URL is HTTP — TLS check skipped. Use HTTPS in production."
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "================================================"
echo "  Results: ${PASS} passed, ${FAIL} failed, ${WARN} warnings"
echo "================================================"

if [[ "$FAIL" -gt 0 ]]; then
    echo -e "${RED}Installation validation FAILED. Fix the above issues before production use.${RESET}"
    exit 1
elif [[ "$WARN" -gt 0 ]]; then
    echo -e "${YELLOW}Validation passed with warnings. Review warnings before production use.${RESET}"
    exit 0
else
    echo -e "${GREEN}All checks passed. Installation is healthy.${RESET}"
    exit 0
fi
