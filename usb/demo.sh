#!/usr/bin/env bash
# RitAPI Advanced — USB Demo Launcher
# Run: bash demo.sh
# Requires: Docker + Docker Compose v2, curl, python3

set -euo pipefail

USB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_IMAGE="ritapi-advanced-app:demo"
REDIS_IMAGE="redis:7-alpine"
IMAGE_TAR="${USB_DIR}/images/ritapi-advanced.tar"
COMPOSE_FILE="${USB_DIR}/docker/demo.yml"
BASE_URL="${RITAPI_BASE_URL:-http://localhost:8001}"

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${CYAN}[demo]${NC} $*"; }
ok()   { echo -e "${GREEN}[demo]${NC} $*"; }
warn() { echo -e "${YELLOW}[demo]${NC} $*"; }
die()  { echo -e "${RED}[demo] ERROR:${NC} $*" >&2; exit 1; }

# ── Prerequisites ─────────────────────────────────────────────────────────────

for cmd in docker curl python3; do
    command -v "$cmd" >/dev/null 2>&1 || die "'$cmd' is required but not found."
done
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 required (docker compose)"
docker info >/dev/null 2>&1 || die "Docker daemon is not running. On Windows: open Docker Desktop. On Linux: sudo systemctl start docker"

[[ -f "$COMPOSE_FILE" ]] || die "Compose file not found: ${COMPOSE_FILE} — is the USB copy complete?"

# ── Load images if not present ────────────────────────────────────────────────

if ! docker image inspect "$APP_IMAGE" >/dev/null 2>&1 || \
   ! docker image inspect "$REDIS_IMAGE" >/dev/null 2>&1; then
    log "Images not found — loading from USB (~1-2 minutes, one-time)..."
    [[ -f "$IMAGE_TAR" ]] || die "Image archive not found: ${IMAGE_TAR}"
    docker load -i "$IMAGE_TAR"
    ok "Images loaded."
else
    log "Images already loaded — skipping docker load."
fi

# ── Start stack ───────────────────────────────────────────────────────────────

trap 'echo ""; echo "  To stop: bash \"${USB_DIR}/stop.sh\""' EXIT

echo ""
echo -e "  ${BOLD}${CYAN}●  RitAPI Advanced Demo${NC}"
echo "  ─────────────────────────────────────────────────────"
echo -e "  Dashboard : ${CYAN}http://localhost:8001/dashboard${NC}"
echo -e "  Metrics   : ${CYAN}http://localhost:8001/metrics${NC}"
echo ""

log "Starting demo stack..."
docker compose -f "$COMPOSE_FILE" --project-directory "$USB_DIR" up -d

echo ""
warn "SIEM events stream live — open a second terminal and run:"
echo -e "    ${BOLD}docker compose -f \"${COMPOSE_FILE}\" logs -f app${NC}"
echo ""

# ── Wait for health ───────────────────────────────────────────────────────────

log "Waiting for app to be healthy..."
ATTEMPTS=0
until curl -sf "$BASE_URL/healthz" >/dev/null 2>&1; do
    ATTEMPTS=$((ATTEMPTS+1))
    if [[ $ATTEMPTS -ge 30 ]]; then
        die "App did not become healthy after 30 attempts. Check: docker compose -f \"${COMPOSE_FILE}\" logs app"
    fi
    sleep 2
done
ok "App is healthy at $BASE_URL"
echo ""

# ── Run attacks ───────────────────────────────────────────────────────────────

exec "${USB_DIR}/scripts/demo_attack.sh"
