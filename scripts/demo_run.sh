#!/usr/bin/env bash
# scripts/demo_run.sh — one-command demo launcher
#
# Builds and starts the demo stack, waits for health, then runs the attack suite.
# SIEM events stream live in a second terminal via:
#   docker compose -f docker/demo.yml logs -f app
#
# Usage:
#   ./scripts/demo_run.sh
#   ./scripts/demo_run.sh --no-build   # skip image rebuild

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker/demo.yml"
BASE_URL="${RITAPI_BASE_URL:-http://localhost:8001}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
BOLD='\033[1m'; NC='\033[0m'

_info()  { echo -e "${CYAN}[demo]${NC} $*"; }
_ok()    { echo -e "${GREEN}[demo]${NC} $*"; }
_warn()  { echo -e "${YELLOW}[demo]${NC} $*"; }
_fatal() { echo -e "${RED}[demo] FATAL:${NC} $*" >&2; exit 1; }

# ── Dependency check ──────────────────────────────────────────────────────────
for cmd in docker curl python3; do
    command -v "$cmd" >/dev/null 2>&1 || _fatal "'$cmd' is required but not found."
done
docker compose version >/dev/null 2>&1 || _fatal "'docker compose' plugin required (v2)."

# ── Start stack ───────────────────────────────────────────────────────────────
BUILD_FLAG="--build"
[[ "${1:-}" == "--no-build" ]] && BUILD_FLAG=""

_info "Starting demo stack (this may take a minute on first run)..."
docker compose -f "$COMPOSE_FILE" up -d $BUILD_FLAG

echo ""
_warn "SIEM events stream live — open a second terminal and run:"
echo -e "    ${BOLD}docker compose -f docker/demo.yml logs -f app${NC}"
echo ""
read -r -p "Press ENTER when you have the log terminal open, or wait 5s..." -t 5 || true
echo ""

# ── Wait for app health ───────────────────────────────────────────────────────
_info "Waiting for app to be healthy..."
ATTEMPTS=0
until curl -sf "$BASE_URL/healthz" >/dev/null 2>&1; do
    ATTEMPTS=$((ATTEMPTS+1))
    if [ $ATTEMPTS -ge 30 ]; then
        _fatal "App did not become healthy after 30 attempts. Check: docker compose -f docker/demo.yml logs app"
    fi
    sleep 2
done
_ok "App is healthy at $BASE_URL"

# ── Run attacks ───────────────────────────────────────────────────────────────
exec "$REPO_ROOT/scripts/demo_attack.sh"
