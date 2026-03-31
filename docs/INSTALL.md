# Installation Guide — RitAPI Advanced

## Requirements

| Requirement | Minimum | Recommended |
|---|---|---|
| CPU | 1 vCPU | 2 vCPU |
| RAM | 256 MB | 512 MB |
| Disk | 1 GB | 5 GB (logs + Redis data) |
| Redis | 6.x | 7.x |
| Python | 3.11 | 3.12 |
| OS | Any Linux | Ubuntu 22.04 / Debian 12 |

YARA is required for injection detection. The Docker image builds it from source. For bare-metal, install `libyara-dev` (Debian/Ubuntu) or `yara-devel` (RHEL/Fedora) before `pip install`.

---

## Option A — Bare Metal

### 1. System dependencies

```bash
# Debian / Ubuntu
sudo apt-get update && sudo apt-get install -y \
    python3.12 python3.12-venv python3-pip \
    libyara-dev gcc redis-server

# RHEL / Fedora
sudo dnf install -y python3.12 python3-pip yara-devel gcc redis
sudo systemctl enable --now redis
```

### 2. Application setup

```bash
git clone https://github.com/vadhh/ritapi-advance.git /opt/ritapi-advanced
cd /opt/ritapi-advanced

python3.12 -m venv .venv
source .venv/bin/activate
pip install --require-hashes -r requirements.lock
```

### 3. Environment configuration

```bash
cp .env.staging .env
# Edit .env — fill in SECRET_KEY, ADMIN_SECRET, REDIS_PASSWORD
# See CONFIGURATION.md for all variables and their valid values.
python -c "import secrets; print(secrets.token_hex(32))"  # generate keys
```

Minimum required values:
```
SECRET_KEY=<64-char hex>
ADMIN_SECRET=<strong random string>
REDIS_URL=redis://:yourpassword@127.0.0.1:6379/1
REDIS_PASSWORD=yourpassword
```

### 4. YARA rules

Rules ship in `rules/`. The path is controlled by `YARA_RULES_DIR` (default `/app/rules`). For bare-metal, update `.env`:

```
YARA_RULES_DIR=/opt/ritapi-advanced/rules
```

### 5. TLS (production)

```bash
# Self-signed (dev/staging only)
bash scripts/gen_cert.sh self-signed

# Let's Encrypt (production)
bash scripts/gen_cert.sh certbot ritapi.example.com admin@example.com
```

### 6. Start

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8001 \
    --workers 2 --log-level warning
```

For production, use a process supervisor (systemd or supervisord):

```ini
# /etc/systemd/system/ritapi-advanced.service
[Unit]
Description=RitAPI Advanced
After=network.target redis.service

[Service]
User=ritapi
WorkingDirectory=/opt/ritapi-advanced
EnvironmentFile=/opt/ritapi-advanced/.env
ExecStart=/opt/ritapi-advanced/.venv/bin/uvicorn app.main:app \
    --host 0.0.0.0 --port 8001 --workers 2 --log-level warning
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ritapi-advanced
```

### 7. Validate

```bash
SMOKE_BASE_URL=http://localhost:8001 bash scripts/smoke_test.sh
# or use the full validator:
bash scripts/validate_install.sh
```

---

## Option B — Docker Compose

### 1. Prerequisites

- Docker ≥ 24 with Compose plugin (`docker compose version`)
- 2 GB free disk

### 2. Configure secrets

```bash
cp .env.staging .env.staging.local
# Fill in SECRET_KEY, ADMIN_SECRET, REDIS_PASSWORD
```

`.env.staging.local` is gitignored. Never commit real values.

### 3. Start the stack

```bash
docker compose -f docker/app.yml --env-file .env.staging.local up -d
```

Services started:
- `redis` — Redis 7 Alpine on internal network, password-protected, data persisted to `redis_data` volume
- `app` — RitAPI Advanced on port 8001 (internal), log volume mounted
- `nginx` — Reverse proxy, ports 80 and 443, forwards to `app:8001`

### 4. TLS certificates

Place your certificates in `certs/` before starting nginx, or run:

```bash
bash scripts/gen_cert.sh self-signed        # dev
bash scripts/gen_cert.sh certbot ritapi.example.com admin@example.com  # prod
```

### 5. Validate

```bash
SMOKE_BASE_URL=http://localhost bash scripts/smoke_test.sh
bash scripts/validate_install.sh --url http://localhost
```

### Useful commands

```bash
# View logs
docker compose -f docker/app.yml logs -f app

# Restart app only (after config change)
docker compose -f docker/app.yml restart app

# Stop everything (data preserved in volumes)
docker compose -f docker/app.yml down

# Destroy including volumes (data lost)
docker compose -f docker/app.yml down -v
```

---

## Option C — Kubernetes (Helm)

### 1. Prerequisites

- Kubernetes ≥ 1.25
- Helm ≥ 3.12
- An Ingress controller (nginx-ingress recommended)
- cert-manager (optional, for automatic TLS)
- A namespace to deploy into

```bash
kubectl create namespace ritapi
```

### 2. Pull the chart

The chart lives in `helm/ritapi-advanced/` in this repository. For a remote registry install, package it first:

```bash
helm package helm/ritapi-advanced
helm install ritapi-advanced ./ritapi-advanced-1.0.0.tgz -n ritapi -f my-values.yaml
```

Or install directly from the local directory:

```bash
helm install ritapi-advanced helm/ritapi-advanced -n ritapi -f my-values.yaml
```

### 3. Create a values override file

```yaml
# my-values.yaml
replicaCount: 2

image:
  repository: ghcr.io/vadhh/ritapi-advance
  tag: "1.0.0"

secrets:
  secretKey: "<64-char hex>"
  adminSecret: "<strong random>"
  redisPassword: "<redis password>"

redis:
  bundled: true          # set false for external Redis in production
  persistence:
    enabled: true
    size: 5Gi

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: ritapi.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: ritapi-tls
      hosts:
        - ritapi.example.com

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70

resources:
  requests:
    cpu: 200m
    memory: 256Mi
  limits:
    cpu: 1000m
    memory: 512Mi
```

**Production external Redis** — disable bundled and point at your managed Redis:

```yaml
redis:
  bundled: false
  externalUrl: "redis://:yourpassword@redis.internal:6379/1"
secrets:
  redisPassword: "yourpassword"
```

**Using an external secrets manager** (e.g. Vault, AWS Secrets Manager, ESO):
Create the `ritapi-advanced` Secret manually and set `secrets.secretKey/adminSecret/redisPassword` to empty strings — the Helm secret template only renders if the values are non-empty, so your external secret takes precedence.

### 4. Install / upgrade

```bash
# First install
helm install ritapi-advanced helm/ritapi-advanced \
    -n ritapi \
    -f my-values.yaml \
    --wait --timeout 120s

# Check rollout
kubectl rollout status deployment/ritapi-advanced -n ritapi

# Validate
kubectl port-forward svc/ritapi-advanced 8001:80 -n ritapi &
bash scripts/validate_install.sh --url http://localhost:8001
```

### 5. Prometheus scraping

Pods are annotated for auto-discovery:

```yaml
prometheus.io/scrape: "true"
prometheus.io/path: /metrics
prometheus.io/port: "8001"
```

If using the Prometheus Operator, add a `ServiceMonitor`:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: ritapi-advanced
  namespace: ritapi
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: ritapi-advanced
  endpoints:
    - port: http
      path: /metrics
      interval: 30s
```

---

## Upgrade Guide

### Docker Compose

```bash
# Pull new image
docker compose -f docker/app.yml pull app

# Rolling restart (zero-downtime if running multiple replicas behind nginx upstream)
docker compose -f docker/app.yml up -d --no-deps app
```

### Kubernetes / Helm

```bash
# Update chart version or image tag in my-values.yaml, then:
helm upgrade ritapi-advanced helm/ritapi-advanced \
    -n ritapi \
    -f my-values.yaml \
    --wait --timeout 120s

# Rollback if needed
helm rollback ritapi-advanced -n ritapi
```

Helm triggers a rolling update automatically when the `checksum/config` or `checksum/secret` annotations change (any config or secret edit causes pods to cycle).

### Redis schema

There are no breaking Redis key changes between patch versions (x.x.0 → x.x.1). Minor version upgrades (x.0.0 → x.1.0) will note any key renames in `CHANGELOG.md`. Flush only the affected namespace:

```bash
# Example: flush only rate-limit keys (safe, they auto-rebuild)
redis-cli -a "$REDIS_PASSWORD" --scan --pattern "ratelimit:*" | xargs redis-cli -a "$REDIS_PASSWORD" del
```

### Bare metal

```bash
cd /opt/ritapi-advanced
git pull origin main
source .venv/bin/activate
pip install --require-hashes -r requirements.lock
sudo systemctl restart ritapi-advanced
bash scripts/validate_install.sh
```

---

## First Login

Once the service is running, obtain a SUPER_ADMIN JWT:

```bash
curl -s -X POST http://localhost:8001/admin/token \
    -H "X-Admin-Secret: $ADMIN_SECRET" \
    -H "Content-Type: application/json" | jq .
```

Response:

```json
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

Use this token to issue API keys for downstream clients:

```bash
curl -s -X POST http://localhost:8001/admin/apikey \
    -H "Authorization: Bearer eyJ..." \
    -H "Content-Type: application/json" \
    -d '{"subject": "my-service", "role": "OPERATOR", "ttl_days": 90}' | jq .
```

---

## Next Steps

- See `CONFIGURATION.md` for the complete environment variable reference.
- See `PENTEST.md` for known limitations and open findings.
- See `docker/grafana/dashboard.json` to import the Grafana dashboard.
- Run `bash scripts/validate_install.sh --help` for validation options.
