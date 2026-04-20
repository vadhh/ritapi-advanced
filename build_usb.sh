#!/usr/bin/env bash
# build_usb.sh
# Stages a self-contained USB demo kit for RitAPI Advanced.
#
# Usage:
#   bash build_usb.sh              # → dist/ritapi-usb-v2.2.0/
#   bash build_usb.sh 2.3.0        # → dist/ritapi-usb-v2.3.0/
#
# After this script completes, copy dist/ritapi-usb-vX.Y.Z/
# to the root of a formatted USB drive (FAT32 or exFAT, 8GB+).

set -euo pipefail

VERSION="${1:-2.2.0}"
PACKAGE_NAME="ritapi-usb-v${VERSION}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGE_DIR="${SCRIPT_DIR}/dist/${PACKAGE_NAME}"

APP_IMAGE="ritapi-advanced-app:demo"
REDIS_IMAGE="redis:7-alpine"
IMAGE_TAR_NAME="ritapi-advanced.tar"

log()  { echo "[build_usb] $*"; }
die()  { echo "[build_usb] ERROR: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not found"; }

need docker
need cp
need mkdir

docker compose version >/dev/null 2>&1 || die "Docker Compose v2 required"

cd "$SCRIPT_DIR"

[[ -f docker/demo.yml         ]] || die "docker/demo.yml not found — run from repo root"
[[ -f docker/demo.usb.yml     ]] || die "docker/demo.usb.yml not found — run Task 2 first"
[[ -f docker/Dockerfile       ]] || die "Dockerfile not found"
[[ -f .env.demo               ]] || die ".env.demo not found"
[[ -f usb/demo.sh             ]] || die "usb/demo.sh not found — run Task 3 first"
[[ -f usb/stop.sh             ]] || die "usb/stop.sh not found — run Task 4 first"
[[ -f usb/README.txt          ]] || die "usb/README.txt not found — run Task 5 first"
[[ -f scripts/demo_attack.sh  ]] || die "scripts/demo_attack.sh not found"
[[ -f scripts/demo_clean.sh   ]] || die "scripts/demo_clean.sh not found"

# ── Pull redis image (needed for docker save) ─────────────────────────────────

log "Pulling redis:7-alpine (needed for bundling)..."
docker pull redis:7-alpine

# ── Build app image ───────────────────────────────────────────────────────────

log "Building app image..."
docker compose -f docker/demo.yml build

log "Tagging app image as ${APP_IMAGE}..."
docker tag ritapi-advanced-app "$APP_IMAGE"
log "  app → ${APP_IMAGE}"

# ── Save images to tar ────────────────────────────────────────────────────────

log "Saving images to tar (app + redis, ~500MB–1GB)..."
mkdir -p "${SCRIPT_DIR}/dist"
TMP_TAR="${SCRIPT_DIR}/dist/${IMAGE_TAR_NAME}"
docker save "$APP_IMAGE" "$REDIS_IMAGE" -o "$TMP_TAR"
TAR_SIZE=$(du -sh "$TMP_TAR" | cut -f1)
log "  Saved: ${TMP_TAR} (${TAR_SIZE})"

# ── Stage USB layout ──────────────────────────────────────────────────────────

log "Staging USB layout to ${STAGE_DIR}"
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

# Launcher, stop, README
cp usb/demo.sh    "${STAGE_DIR}/demo.sh"
cp usb/stop.sh    "${STAGE_DIR}/stop.sh"
cp usb/README.txt "${STAGE_DIR}/README.txt"
chmod +x "${STAGE_DIR}/demo.sh" "${STAGE_DIR}/stop.sh"

# .env.demo (demo credentials — safe to distribute)
cp .env.demo "${STAGE_DIR}/.env.demo"

# Docker compose — USB variant copied as demo.yml so scripts work unchanged
mkdir -p "${STAGE_DIR}/docker"
cp docker/demo.usb.yml "${STAGE_DIR}/docker/demo.yml"

# Attack + clean scripts (work unchanged — resolve paths via BASH_SOURCE[0])
mkdir -p "${STAGE_DIR}/scripts"
cp scripts/demo_attack.sh "${STAGE_DIR}/scripts/demo_attack.sh"
cp scripts/demo_clean.sh  "${STAGE_DIR}/scripts/demo_clean.sh"
chmod +x "${STAGE_DIR}/scripts/demo_attack.sh" "${STAGE_DIR}/scripts/demo_clean.sh"

# Images tar
mkdir -p "${STAGE_DIR}/images"
mv "$TMP_TAR" "${STAGE_DIR}/images/${IMAGE_TAR_NAME}"

# ── Summary ───────────────────────────────────────────────────────────────────

TOTAL_SIZE=$(du -sh "$STAGE_DIR" | cut -f1)

log ""
log "Done."
log "  Staged : ${STAGE_DIR}"
log "  Size   : ${TOTAL_SIZE}"
log ""
log "Next step: copy ${STAGE_DIR}/* to the root of a formatted USB drive."
log ""
log "  Example (Linux — replace <label> with your USB label):"
log "    cp -r ${STAGE_DIR}/. /media/\$USER/<label>/"
log ""
log "  Example (WSL — USB mounted at /mnt/e):"
log "    cp -r ${STAGE_DIR}/. /mnt/e/"
log ""
log "Sales team runs: bash demo.sh"
