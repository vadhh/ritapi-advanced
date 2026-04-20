#!/usr/bin/env bash
# RitAPI Advanced USB Demo — Stop
# Run: bash stop.sh

set -euo pipefail

USB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${USB_DIR}/docker/demo.yml"

docker compose -f "$COMPOSE_FILE" --project-directory "$USB_DIR" down
echo ""
echo "  Demo stopped."
echo "  To restart: bash demo.sh"
