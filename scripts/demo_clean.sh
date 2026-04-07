#!/usr/bin/env bash
# scripts/demo_clean.sh — reset demo state between runs
#
# Flushes Redis db 1 (all rate/bot/throttle/exfil counters).
# Does NOT bring containers down — the demo stack stays running.
#
# Usage:
#   ./scripts/demo_clean.sh          # flush only
#   ./scripts/demo_clean.sh --down   # flush + bring containers down

set -euo pipefail

CYAN='\033[0;36m'; GREEN='\033[0;32m'; NC='\033[0m'
_info() { echo -e "${CYAN}[clean]${NC} $*"; }
_ok()   { echo -e "${GREEN}[clean]${NC} $*"; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker/demo.yml"

# ── Flush Redis db 1 ──────────────────────────────────────────────────────────
_info "Flushing Redis db 1 (all demo counters)..."
docker exec ritapi-demo-redis redis-cli -n 1 FLUSHDB
_ok "Redis db 1 cleared — counters reset"

# ── Optional teardown ─────────────────────────────────────────────────────────
if [[ "${1:-}" == "--down" ]]; then
    _info "Bringing demo stack down..."
    docker compose -f "$COMPOSE_FILE" down
    _ok "Stack stopped"
fi

echo ""
echo "  Run again:  ./scripts/demo_attack.sh"
echo "  Full reset: ./scripts/demo_run.sh"
