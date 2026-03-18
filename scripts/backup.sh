#!/usr/bin/env bash
# backup.sh — RitAPI Advanced backup script
#
# Creates a timestamped backup of:
#   1. PostgreSQL database (pg_dump)
#   2. /etc/ritapi-advanced/ configuration
#   3. /etc/ritapi/ routing & policy configs (if present)
#   4. Application logs
#
# Usage:
#   sudo ./scripts/backup.sh [backup_dir]
#
# Default backup dir: /var/backups/ritapi

set -euo pipefail

BACKUP_ROOT="${1:-/var/backups/ritapi}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"

# Database config (override via env vars)
DB_NAME="${RITAPI_DB_NAME:-ritapi}"
DB_USER="${RITAPI_DB_USER:-ritapi}"
DB_HOST="${RITAPI_DB_HOST:-localhost}"
DB_PORT="${RITAPI_DB_PORT:-5432}"

LOG_DIR="/var/log/ritapi"
CONFIG_DIRS=("/etc/ritapi-advanced" "/etc/ritapi")

echo "=== RitAPI Backup — ${TIMESTAMP} ==="

mkdir -p "${BACKUP_DIR}"

# --- 1. PostgreSQL dump ---
echo "[1/4] Dumping PostgreSQL database '${DB_NAME}'..."
if command -v pg_dump &>/dev/null; then
    pg_dump -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -Fc \
        "${DB_NAME}" > "${BACKUP_DIR}/db_${DB_NAME}.dump" 2>/dev/null && \
        echo "      Database dump: OK" || \
        echo "      Database dump: SKIPPED (connection failed — is PostgreSQL running?)"
else
    echo "      Database dump: SKIPPED (pg_dump not found)"
fi

# --- 2. Configuration backup ---
echo "[2/4] Backing up configuration..."
for dir in "${CONFIG_DIRS[@]}"; do
    if [ -d "${dir}" ]; then
        target="${BACKUP_DIR}/config$(echo "${dir}" | tr '/' '_')"
        cp -a "${dir}" "${target}"
        echo "      ${dir}: OK"
    else
        echo "      ${dir}: SKIPPED (not found)"
    fi
done

# --- 3. Log backup ---
echo "[3/4] Backing up logs..."
if [ -d "${LOG_DIR}" ]; then
    tar czf "${BACKUP_DIR}/logs.tar.gz" -C "$(dirname "${LOG_DIR}")" "$(basename "${LOG_DIR}")"
    echo "      Logs: OK"
else
    echo "      Logs: SKIPPED (${LOG_DIR} not found)"
fi

# --- 4. Metadata ---
echo "[4/4] Writing backup metadata..."
cat > "${BACKUP_DIR}/metadata.json" <<METAEOF
{
    "timestamp": "${TIMESTAMP}",
    "hostname": "$(hostname)",
    "db_name": "${DB_NAME}",
    "db_host": "${DB_HOST}",
    "backup_dir": "${BACKUP_DIR}",
    "contents": [
        "db_${DB_NAME}.dump",
        "config_etc_ritapi-advanced/",
        "config_etc_ritapi/",
        "logs.tar.gz"
    ]
}
METAEOF

# --- Retention: keep last 30 backups ---
BACKUP_COUNT=$(find "${BACKUP_ROOT}" -mindepth 1 -maxdepth 1 -type d | wc -l)
if [ "${BACKUP_COUNT}" -gt 30 ]; then
    echo "Pruning old backups (keeping last 30)..."
    find "${BACKUP_ROOT}" -mindepth 1 -maxdepth 1 -type d | sort | head -n -30 | xargs rm -rf
fi

echo ""
echo "Backup complete: ${BACKUP_DIR}"
du -sh "${BACKUP_DIR}"
