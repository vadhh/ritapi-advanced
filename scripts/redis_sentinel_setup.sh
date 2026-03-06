#!/usr/bin/env bash
# redis_sentinel_setup.sh — Bootstrap a 1-primary + 2-replica + 3-sentinel
#                           Redis HA cluster using Docker Compose.
#
# For production, replace Docker with managed Redis (AWS ElastiCache,
# Redis Cloud, etc.) and point REDIS_SENTINEL_HOSTS at the sentinel endpoints.
#
# Usage:
#   ./scripts/redis_sentinel_setup.sh [start|stop|status]

set -euo pipefail

CMD="${1:-start}"
COMPOSE_FILE="$(dirname "$0")/../docker/redis-sentinel.yml"

case "$CMD" in
    start)
        echo "[sentinel] Starting Redis HA cluster..."
        docker compose -f "$COMPOSE_FILE" up -d
        echo "[sentinel] Waiting for sentinel election..."
        sleep 5
        echo "[sentinel] Cluster status:"
        docker exec ritapi-sentinel-1 redis-cli -p 26379 sentinel masters
        echo ""
        echo "[sentinel] Add these to your .env:"
        echo "  REDIS_SENTINEL_HOSTS=127.0.0.1:26379,127.0.0.1:26380,127.0.0.1:26381"
        echo "  REDIS_SENTINEL_SERVICE=mymaster"
        echo "  REDIS_SENTINEL_DB=1"
        echo "  # Remove or leave blank: REDIS_URL"
        ;;
    stop)
        docker compose -f "$COMPOSE_FILE" down
        echo "[sentinel] Stopped."
        ;;
    status)
        docker compose -f "$COMPOSE_FILE" ps
        ;;
    *)
        echo "Usage: $0 [start|stop|status]"
        exit 1
        ;;
esac
