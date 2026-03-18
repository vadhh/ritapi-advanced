#!/usr/bin/env bash
# restore.sh — RitAPI Advanced restore script
#
# Restores from a backup created by backup.sh:
#   1. PostgreSQL database (pg_restore)
#   2. /etc/ritapi-advanced/ configuration
#   3. /etc/ritapi/ routing & policy configs
#   4. Application logs (optional)
#
# Usage:
#   sudo ./scripts/restore.sh /var/backups/ritapi/20260318_120000
#   sudo ./scripts/restore.sh /var/backups/ritapi/20260318_120000 --skip-logs

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <backup_dir> [--skip-logs]"
    echo "Example: $0 /var/backups/ritapi/20260318_120000"
    exit 1
fi

BACKUP_DIR="$1"
SKIP_LOGS="${2:-}"

# Database config (override via env vars)
DB_NAME="${RITAPI_DB_NAME:-ritapi}"
DB_USER="${RITAPI_DB_USER:-ritapi}"
DB_HOST="${RITAPI_DB_HOST:-localhost}"
DB_PORT="${RITAPI_DB_PORT:-5432}"

LOG_DIR="/var/log/ritapi"

if [ ! -d "${BACKUP_DIR}" ]; then
    echo "ERROR: Backup directory not found: ${BACKUP_DIR}"
    exit 1
fi

echo "=== RitAPI Restore from ${BACKUP_DIR} ==="

if [ -f "${BACKUP_DIR}/metadata.json" ]; then
    echo "Backup metadata:"
    cat "${BACKUP_DIR}/metadata.json"
    echo ""
fi

# --- Confirmation ---
read -rp "This will overwrite current config and database. Continue? [y/N] " confirm
if [[ "${confirm}" != [yY] ]]; then
    echo "Restore cancelled."
    exit 0
fi

# --- 1. Stop service ---
echo "[1/5] Stopping RitAPI service..."
systemctl stop ritapi-advanced 2>/dev/null || echo "      Service not running (OK)"

# --- 2. Restore database ---
DUMP_FILE="${BACKUP_DIR}/db_${DB_NAME}.dump"
echo "[2/5] Restoring PostgreSQL database..."
if [ -f "${DUMP_FILE}" ]; then
    if command -v pg_restore &>/dev/null; then
        pg_restore -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" \
            -d "${DB_NAME}" --clean --if-exists "${DUMP_FILE}" 2>/dev/null && \
            echo "      Database restore: OK" || \
            echo "      Database restore: FAILED (check PostgreSQL connectivity)"
    else
        echo "      Database restore: SKIPPED (pg_restore not found)"
    fi
else
    echo "      Database restore: SKIPPED (no dump file in backup)"
fi

# --- 3. Restore configuration ---
echo "[3/5] Restoring configuration..."
for config_backup in "${BACKUP_DIR}"/config_etc_*; do
    if [ -d "${config_backup}" ]; then
        # Derive original path from backup dir name
        orig_path="/$(basename "${config_backup}" | sed 's/^config_//' | tr '_' '/')"
        mkdir -p "${orig_path}"
        cp -a "${config_backup}/." "${orig_path}/"
        echo "      Restored: ${orig_path}"
    fi
done

# --- 4. Restore logs (optional) ---
echo "[4/5] Restoring logs..."
if [ "${SKIP_LOGS}" = "--skip-logs" ]; then
    echo "      Logs: SKIPPED (--skip-logs)"
elif [ -f "${BACKUP_DIR}/logs.tar.gz" ]; then
    mkdir -p "${LOG_DIR}"
    tar xzf "${BACKUP_DIR}/logs.tar.gz" -C "$(dirname "${LOG_DIR}")"
    echo "      Logs: OK"
else
    echo "      Logs: SKIPPED (no logs archive in backup)"
fi

# --- 5. Restart service ---
echo "[5/5] Starting RitAPI service..."
systemctl start ritapi-advanced 2>/dev/null && \
    echo "      Service started: OK" || \
    echo "      Service start: FAILED (check systemctl status ritapi-advanced)"

echo ""
echo "Restore complete."
