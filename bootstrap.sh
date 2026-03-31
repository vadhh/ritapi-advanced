#!/usr/bin/env bash
# bootstrap.sh — RitAPI Advanced installer
#
# One-liner (interactive):
#   curl -sSL https://raw.githubusercontent.com/vadhh/ritapi-advanced/main/bootstrap.sh | bash
#
# Non-interactive (all secrets auto-generated, no prompts):
#   curl -sSL .../bootstrap.sh | bash -s -- --auto
#
# Upgrade existing install (pull latest image, restart):
#   curl -sSL .../bootstrap.sh | bash -s -- --upgrade
#
# Uninstall:
#   curl -sSL .../bootstrap.sh | bash -s -- --uninstall
#
# Pin a specific version:
#   curl -sSL .../bootstrap.sh | bash -s -- --version v1.2.2
#
# Clone-then-run (avoids curl|bash):
#   git clone https://github.com/vadhh/ritapi-advanced
#   cd ritapi-advanced && bash bootstrap.sh

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
REPO_RAW="https://raw.githubusercontent.com/vadhh/ritapi-advanced/main"
REPO_URL="https://github.com/vadhh/ritapi-advanced"
COMPOSE_FILE="docker-compose.yml"
ENV_FILE=".env"
DEFAULT_PORT="8001"
HEALTH_RETRIES=24
HEALTH_WAIT=5

# ---------------------------------------------------------------------------
# Colours (disabled when not a terminal)
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; NC=''
fi

info()    { echo -e "${CYAN}▶  $*${NC}"; }
success() { echo -e "${GREEN}✓  $*${NC}"; }
warn()    { echo -e "${YELLOW}⚠  $*${NC}"; }
die()     { echo -e "${RED}✗  $*${NC}" >&2; exit 1; }
step()    { echo -e "\n${BOLD}$*${NC}"; echo "────────────────────────────────────────────"; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
MODE="install"        # install | upgrade | uninstall
AUTO=false            # skip all prompts, auto-generate everything
PINNED_VERSION=""     # empty = latest

while [[ $# -gt 0 ]]; do
    case "$1" in
        --auto)           AUTO=true ;;
        --upgrade)        MODE="upgrade" ;;
        --uninstall)      MODE="uninstall" ;;
        --version)        PINNED_VERSION="$2"; shift ;;
        --version=*)      PINNED_VERSION="${1#*=}" ;;
        --help|-h)
            echo "Usage: bash bootstrap.sh [--auto] [--upgrade] [--uninstall] [--version v1.2.2]"
            exit 0 ;;
        *) warn "Unknown flag: $1" ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# When stdin is a pipe (curl|bash), redirect prompts to /dev/tty
# so the user can still type interactively.
# ---------------------------------------------------------------------------
if [[ ! -t 0 ]] && [[ "$AUTO" == false ]]; then
    if [[ -e /dev/tty ]]; then
        exec < /dev/tty
    else
        warn "No terminal detected — switching to --auto mode."
        AUTO=true
    fi
fi

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
banner() {
    echo ""
    echo -e "${BOLD}${CYAN}╔════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║     RitAPI Advanced — Installer            ║${NC}"
    echo -e "${BOLD}${CYAN}╚════════════════════════════════════════════╝${NC}"
    echo ""
}

# ---------------------------------------------------------------------------
# Prereq checks
# ---------------------------------------------------------------------------
check_prereqs() {
    step "Checking prerequisites"

    command -v docker >/dev/null 2>&1 \
        || die "Docker not found. Install: https://docs.docker.com/get-docker/"

    if docker compose version >/dev/null 2>&1; then
        COMPOSE_CMD="docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        COMPOSE_CMD="docker-compose"
    else
        die "Docker Compose not found. Install: https://docs.docker.com/compose/install/"
    fi

    command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 \
        || die "curl or wget is required."

    success "Docker OK  ($( docker --version | head -1 ))"
    success "Compose OK (using: $COMPOSE_CMD)"
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
gen_secret() {
    # 64-char hex — works with openssl or python3
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    else
        python3 -c "import secrets; print(secrets.token_hex(32))"
    fi
}

fetch_url() {
    local url="$1" dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$dest"
    else
        wget -qO "$dest" "$url"
    fi
}

prompt() {
    # prompt <variable_name> <prompt_text> <default>
    local var="$1" text="$2" default="$3"
    if [[ "$AUTO" == true ]]; then
        printf -v "$var" '%s' "$default"
        return
    fi
    local input
    read -rp "  ${text} [${default:0:8}…]: " input
    printf -v "$var" '%s' "${input:-$default}"
}

prompt_plain() {
    # prompt_plain <variable_name> <prompt_text> <default>
    local var="$1" text="$2" default="$3"
    if [[ "$AUTO" == true ]]; then
        printf -v "$var" '%s' "$default"
        return
    fi
    local input
    read -rp "  ${text} [${default}]: " input
    printf -v "$var" '%s' "${input:-$default}"
}

# ---------------------------------------------------------------------------
# Download docker-compose.yml
# ---------------------------------------------------------------------------
fetch_compose() {
    step "Fetching compose file"
    local url
    if [[ -n "$PINNED_VERSION" ]]; then
        url="https://raw.githubusercontent.com/vadhh/ritapi-advanced/${PINNED_VERSION}/${COMPOSE_FILE}"
    else
        url="${REPO_RAW}/${COMPOSE_FILE}"
    fi

    if [[ -f "$COMPOSE_FILE" ]] && [[ "$MODE" != "upgrade" ]]; then
        info "Found existing $COMPOSE_FILE — skipping download."
    else
        info "Downloading $COMPOSE_FILE${PINNED_VERSION:+ @ $PINNED_VERSION}..."
        fetch_url "$url" "$COMPOSE_FILE"
        success "Downloaded $COMPOSE_FILE"
    fi
}

# ---------------------------------------------------------------------------
# Configure .env
# ---------------------------------------------------------------------------
configure_env() {
    step "Configuration"

    if [[ -f "$ENV_FILE" ]]; then
        warn ".env already exists — keeping existing configuration."
        warn "To reconfigure: rm .env && bash bootstrap.sh"
        return
    fi

    [[ "$AUTO" == true ]] && info "Auto mode — generating all secrets."

    local SECRET_KEY ADMIN_SECRET REDIS_PASSWORD DASHBOARD_TOKEN PORT

    prompt       SECRET_KEY     "SECRET_KEY   (JWT signing key)"  "$(gen_secret)"
    prompt       ADMIN_SECRET   "ADMIN_SECRET (admin bootstrap)"  "$(gen_secret)"
    prompt       REDIS_PASSWORD "REDIS_PASSWORD"                  "$(gen_secret | cut -c1-32)"
    prompt_plain DASHBOARD_TOKEN "DASHBOARD_TOKEN (blank = open)" ""
    prompt_plain PORT            "Expose on port"                  "$DEFAULT_PORT"

    cat > "$ENV_FILE" <<EOF
# RitAPI Advanced — generated by bootstrap.sh $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# KEEP THIS FILE SECRET — do not commit it to version control.

SECRET_KEY=${SECRET_KEY}
ADMIN_SECRET=${ADMIN_SECRET}
REDIS_PASSWORD=${REDIS_PASSWORD}
DASHBOARD_TOKEN=${DASHBOARD_TOKEN}

PORT=${PORT}
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=60
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60
EOF
    chmod 600 "$ENV_FILE"
    success ".env written (mode 600)"

    echo ""
    echo -e "${YELLOW}  ┌─ Save these — they will NOT be shown again ─────────┐${NC}"
    echo -e "${YELLOW}  │  ADMIN_SECRET   = ${ADMIN_SECRET}  │${NC}"
    [[ -n "$DASHBOARD_TOKEN" ]] && \
    echo -e "${YELLOW}  │  DASHBOARD_TOKEN = ${DASHBOARD_TOKEN}  │${NC}"
    echo -e "${YELLOW}  └──────────────────────────────────────────────────────┘${NC}"
    echo ""
}

# ---------------------------------------------------------------------------
# Pull image
# ---------------------------------------------------------------------------
pull_image() {
    step "Pulling image"
    local image="ghcr.io/vadhh/ritapi-advanced"
    local tag="${PINNED_VERSION:-latest}"
    info "Pulling ${image}:${tag}..."

    if [[ -n "$PINNED_VERSION" ]]; then
        # Temporarily patch compose to use pinned tag
        sed -i.bak "s|ritapi-advanced:latest|ritapi-advanced:${PINNED_VERSION}|g" "$COMPOSE_FILE" \
            && rm -f "${COMPOSE_FILE}.bak"
    fi

    $COMPOSE_CMD pull app
    success "Image ready"
}

# ---------------------------------------------------------------------------
# Start / restart
# ---------------------------------------------------------------------------
start_services() {
    step "Starting services"
    $COMPOSE_CMD up -d --remove-orphans
    success "Services started"
}

# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
wait_healthy() {
    step "Waiting for healthy state"
    # Load PORT from .env if available
    local port
    port=$(grep -E "^PORT=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 || echo "$DEFAULT_PORT")
    local url="http://localhost:${port}/healthz"

    echo -n "  "
    for i in $(seq 1 $HEALTH_RETRIES); do
        local status
        status=$(curl -sf "$url" 2>/dev/null \
            | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" \
            2>/dev/null || true)
        if [[ "$status" == "ok" ]]; then
            echo ""
            success "RitAPI Advanced is healthy at $url"
            return
        fi
        echo -n "."
        sleep $HEALTH_WAIT
    done
    echo ""
    warn "Health check timed out after $((HEALTH_RETRIES * HEALTH_WAIT))s."
    warn "Check logs: $COMPOSE_CMD logs app"
    warn "Check status: $COMPOSE_CMD ps"
}

# ---------------------------------------------------------------------------
# Completion summary
# ---------------------------------------------------------------------------
print_summary() {
    local port
    port=$(grep -E "^PORT=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 || echo "$DEFAULT_PORT")

    echo ""
    echo -e "${BOLD}${GREEN}╔════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${GREEN}║        Installation complete! 🚀           ║${NC}"
    echo -e "${BOLD}${GREEN}╚════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BOLD}  Endpoints${NC}"
    echo "    Health     http://localhost:${port}/healthz"
    echo "    API docs   http://localhost:${port}/docs"
    echo "    Dashboard  http://localhost:${port}/dashboard"
    echo "    Metrics    http://localhost:${port}/metrics"
    echo ""
    echo -e "${BOLD}  First — get an admin token${NC}"
    echo "    source .env"
    echo "    curl -X POST http://localhost:${port}/admin/token \\"
    echo "      -H \"X-Admin-Secret: \$ADMIN_SECRET\""
    echo ""
    echo -e "${BOLD}  Then — issue an API key for your client${NC}"
    echo "    curl -X POST http://localhost:${port}/admin/apikey \\"
    echo "      -H \"X-Admin-Secret: \$ADMIN_SECRET\" \\"
    echo "      -H \"Content-Type: application/json\" \\"
    echo "      -d '{\"subject\": \"myapp\", \"role\": \"VIEWER\"}'"
    echo ""
    echo -e "${BOLD}  Day-to-day commands${NC}"
    echo "    $COMPOSE_CMD logs -f app           # live logs"
    echo "    $COMPOSE_CMD ps                    # service status"
    echo "    $COMPOSE_CMD down                  # stop"
    echo "    bash bootstrap.sh --upgrade        # upgrade to latest"
    echo "    bash bootstrap.sh --uninstall      # remove everything"
    echo ""
    echo "  Full manual: ${REPO_URL}/blob/main/docs/MANUAL.md"
    echo ""
}

# ---------------------------------------------------------------------------
# Upgrade
# ---------------------------------------------------------------------------
do_upgrade() {
    step "Upgrading RitAPI Advanced"
    [[ -f "$COMPOSE_FILE" ]] || die "No $COMPOSE_FILE found. Run bootstrap.sh without --upgrade first."
    info "Pulling latest image..."
    $COMPOSE_CMD pull app
    info "Restarting app container..."
    $COMPOSE_CMD up -d --no-deps app
    wait_healthy
    success "Upgrade complete"
    local port
    port=$(grep -E "^PORT=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 || echo "$DEFAULT_PORT")
    echo ""
    echo "  Running version: $($COMPOSE_CMD exec app python3 -c 'from app import __version__; print(__version__)' 2>/dev/null || echo 'unknown')"
    echo ""
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
do_uninstall() {
    step "Uninstalling RitAPI Advanced"
    warn "This will stop and remove all containers and volumes."
    if [[ "$AUTO" == false ]]; then
        read -rp "  Continue? [y/N]: " confirm
        [[ "$confirm" =~ ^[Yy]$ ]] || { info "Cancelled."; exit 0; }
    fi
    [[ -f "$COMPOSE_FILE" ]] && $COMPOSE_CMD down -v --remove-orphans
    success "Containers and volumes removed"
    info "The .env file and $COMPOSE_FILE were left in place."
    info "Remove them manually if no longer needed."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
banner
check_prereqs

case "$MODE" in
    install)
        fetch_compose
        configure_env
        pull_image
        start_services
        wait_healthy
        print_summary
        ;;
    upgrade)
        fetch_compose
        do_upgrade
        ;;
    uninstall)
        do_uninstall
        ;;
esac
