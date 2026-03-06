#!/usr/bin/env bash
# gen_cert.sh — Generate TLS certificates for RitAPI Advanced
#
# Usage:
#   ./scripts/gen_cert.sh [DOMAIN]
#
# Modes:
#   No domain (or domain = "self-signed"):
#     Generates a self-signed certificate. For development / internal use only.
#     Output: /etc/ssl/certs/ritapi.crt, /etc/ssl/private/ritapi.key
#
#   Domain provided (e.g., api.example.com):
#     Uses Certbot (Let's Encrypt) to issue a production certificate.
#     Nginx must be running and port 80 open to the internet.
#     Output: Certbot manages paths automatically; nginx.conf is updated.
#
# Requirements:
#   - openssl (always needed)
#   - certbot (production mode only): apt install certbot python3-certbot-nginx

set -euo pipefail

DOMAIN="${1:-self-signed}"
CERT_DIR="/etc/ssl/certs"
KEY_DIR="/etc/ssl/private"
CERT_FILE="${CERT_DIR}/ritapi.crt"
KEY_FILE="${KEY_DIR}/ritapi.key"

# Ensure directories exist with correct permissions
sudo mkdir -p "$CERT_DIR" "$KEY_DIR"
sudo chmod 700 "$KEY_DIR"

# ---------------------------------------------------------------------------
# Self-signed (development)
# ---------------------------------------------------------------------------
if [[ "$DOMAIN" == "self-signed" ]]; then
    echo "[gen_cert] Generating self-signed certificate..."

    SUBJ="/C=US/ST=Dev/L=Dev/O=RitAPI/OU=Security/CN=ritapi-dev"

    sudo openssl req \
        -x509 \
        -newkey rsa:4096 \
        -keyout "$KEY_FILE" \
        -out "$CERT_FILE" \
        -days 365 \
        -nodes \
        -subj "$SUBJ" \
        -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"

    sudo chmod 600 "$KEY_FILE"
    sudo chmod 644 "$CERT_FILE"

    echo "[gen_cert] Done."
    echo "  Certificate : $CERT_FILE"
    echo "  Private key : $KEY_FILE"
    echo "  Expires in  : 365 days"
    echo ""
    echo "  WARNING: Self-signed certificate. Browsers will show a security"
    echo "  warning. Do NOT use this in production — use a real domain and"
    echo "  run: ./scripts/gen_cert.sh your.domain.com"
    exit 0
fi

# ---------------------------------------------------------------------------
# Let's Encrypt / Certbot (production)
# ---------------------------------------------------------------------------
echo "[gen_cert] Requesting Let's Encrypt certificate for: $DOMAIN"

if ! command -v certbot &>/dev/null; then
    echo "[gen_cert] ERROR: certbot not found."
    echo "  Install: sudo apt install certbot python3-certbot-nginx"
    exit 1
fi

# Use the Nginx plugin — it temporarily modifies nginx config, completes the
# ACME HTTP-01 challenge, then restores config and reloads Nginx.
sudo certbot --nginx \
    -d "$DOMAIN" \
    --non-interactive \
    --agree-tos \
    --email "admin@${DOMAIN}" \
    --redirect

echo "[gen_cert] Let's Encrypt certificate issued for $DOMAIN."
echo ""
echo "  Certbot auto-renew cron is installed at: /etc/cron.d/certbot"
echo "  Test renewal: sudo certbot renew --dry-run"
echo ""
echo "  Update nginx.conf to point to Certbot's managed paths:"
echo "    ssl_certificate     /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;"
echo "    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;"
