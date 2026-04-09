# Operations Runbook — RitAPI Advanced

Version: 1.0.0 | Last updated: 2026-03-07

This runbook covers on-call procedures for all production deployment targets (bare metal, Docker Compose, Kubernetes). Prometheus alert names reference `docker/prometheus/alerts.yaml`.

---

## Table of Contents

1. [Service Restart](#1-service-restart)
2. [Redis Failover](#2-redis-failover)
3. [TLS Certificate Renewal](#3-tls-certificate-renewal)
4. [YARA Rule Update](#4-yara-rule-update)
5. [Rate Limit Tuning](#5-rate-limit-tuning)
6. [WAF Tuning](#6-waf-tuning)
7. [API Key Rotation Policy](#7-api-key-rotation-policy)
8. [Log Management](#8-log-management)
9. [Escalation Path](#9-escalation-path)

---

## 1. Service Restart

**Triggers:** `RitAPIDown`, manual maintenance, config change.

### Bare metal (systemd)

```bash
sudo systemctl status ritapi-advanced          # check current state
sudo systemctl restart ritapi-advanced
sudo systemctl status ritapi-advanced          # confirm running
bash scripts/validate_install.sh               # validate
```

If the service fails to start, check logs:

```bash
sudo journalctl -u ritapi-advanced -n 100 --no-pager
```

### Docker Compose

```bash
docker compose -f docker/app.yml ps
docker compose -f docker/app.yml restart app
docker compose -f docker/app.yml logs --tail 50 app
bash scripts/validate_install.sh --url http://localhost
```

### Kubernetes

```bash
kubectl rollout restart deployment/ritapi-advanced -n ritapi
kubectl rollout status deployment/ritapi-advanced -n ritapi --timeout=120s
bash scripts/validate_install.sh --url https://ritapi.example.com
```

---

## 2. Redis Failover

**Triggers:** `RitAPIRedisDisconnected`, Redis host failure.

**Impact while Redis is down:** The service runs in **fail-open** mode:
- Rate limiting: disabled (all requests pass through)
- Bot detection: disabled
- Exfiltration detection: disabled
- JWT validation: still enforced (stateless)
- API key validation: **fails open** (keys cannot be checked; reject or allow depends on `REDIS_FAIL_OPEN` — currently fail-open)

### Verify Redis status

```bash
# Bare metal / Docker
redis-cli -h 127.0.0.1 -p 6379 -a "$REDIS_PASSWORD" ping

# Kubernetes
kubectl exec -it deploy/ritapi-advanced-redis -n ritapi -- \
    redis-cli -a "$REDIS_PASSWORD" ping
```

### Restart Redis (Docker Compose)

```bash
docker compose -f docker/app.yml restart redis
docker compose -f docker/app.yml logs --tail 30 redis
```

### Switch to Sentinel HA

If running the Sentinel stack (`docker/redis-sentinel.yml`):

```bash
bash scripts/redis_sentinel_setup.sh start
# Then update .env:
#   REDIS_SENTINEL_HOSTS=sentinel1:26379,sentinel2:26379,sentinel3:26379
#   REDIS_SENTINEL_MASTER=mymaster
# Restart the app to pick up the new config
```

### Manual Redis key flush (emergency only)

Only flush namespaces that are safe to rebuild automatically:

```bash
REDIS_PASSWORD="yourpassword"

# Flush rate-limit keys (auto-rebuild within one window)
redis-cli -a "$REDIS_PASSWORD" --scan --pattern "ratelimit:*" \
    | xargs -r redis-cli -a "$REDIS_PASSWORD" del

# Flush bot-detection state (resets all risk accumulators)
redis-cli -a "$REDIS_PASSWORD" --scan --pattern "bot:*" \
    | xargs -r redis-cli -a "$REDIS_PASSWORD" del

# Do NOT flush apikey:* without a backup — that deletes all issued API keys
```

### After recovery

1. Verify `ritapi_redis_connected` gauge returns to 1 within 30 seconds.
2. Run `bash scripts/validate_install.sh`.
3. Check JSONL logs for any requests that passed without rate-limit/bot checks during the outage window.

---

## 3. TLS Certificate Renewal

**Triggers:** Certificate expiry alert from monitoring, scheduled renewal (Let's Encrypt: every 60–90 days).

### Let's Encrypt (certbot)

```bash
# Renew (non-interactive; certbot handles webroot/standalone)
sudo certbot renew --quiet

# If renewal fails, force:
sudo certbot renew --force-renewal

# Reload Nginx to pick up new cert (no downtime)
sudo nginx -t && sudo nginx -s reload
# Docker:
docker compose -f docker/app.yml exec nginx nginx -s reload
# Kubernetes: cert-manager rotates automatically; no action needed if using cert-manager
```

### Self-signed (dev/staging)

```bash
bash scripts/gen_cert.sh self-signed
# Then reload Nginx:
sudo nginx -s reload
```

### Verify certificate

```bash
echo | openssl s_client -connect ritapi.example.com:443 2>/dev/null \
    | openssl x509 -noout -dates
# notAfter should be >30 days away
```

### Certificate expiry monitoring

Add a Prometheus blackbox-exporter probe or a simple cron check:

```bash
# Add to /etc/cron.d/ritapi-cert-check
0 8 * * * root bash -c \
  'days=$(( ($(date -d "$(openssl s_client -connect ritapi.example.com:443 </dev/null 2>/dev/null | openssl x509 -noout -enddate | cut -d= -f2)" +%s) - $(date +%s)) / 86400 )); [ $days -lt 30 ] && echo "CERT EXPIRES IN $days DAYS" | mail -s "RitAPI cert expiry warning" ops@example.com'
```

---

## 4. YARA Rule Update

**Goal:** Add, update, or remove `.yar` rule files without downtime.

### Workflow

1. **Write and test the new rule locally:**

   ```bash
   # Create or edit a rule file
   vim rules/my_new_rule.yar

   # Test the rule compiles:
   python3 -c "
   import yara
   rules = yara.compile(filepath='rules/my_new_rule.yar')
   print('Compiled OK')
   "
   ```

2. **Test against sample payloads:**

   ```bash
   # Run the YARA unit tests to ensure no regressions
   python -m pytest tests/test_yara.py -v

   # All 162 tests must still pass
   python -m pytest tests/ -q
   ```

3. **Stage the change:**

   ```bash
   git add rules/my_new_rule.yar
   git commit -m "feat(yara): add rule for <attack-type>"
   git push origin main
   # CI will run the full test suite
   ```

4. **Deploy without downtime:**

   Rules are loaded at startup via `YARAScanner.compile_rules()`. A rolling restart is required for changes to take effect.

   ```bash
   # Bare metal
   sudo systemctl reload-or-restart ritapi-advanced

   # Docker Compose (zero-downtime if >1 replica behind Nginx upstream)
   docker compose -f docker/app.yml up -d --no-deps app

   # Kubernetes (rolling update — 0 downtime with replicaCount ≥ 2)
   kubectl rollout restart deployment/ritapi-advanced -n ritapi
   kubectl rollout status deployment/ritapi-advanced -n ritapi
   ```

5. **Verify:** Hit a payload that should match the new rule and confirm HTTP 400/403.

### Rule file naming

Each `.yar` file is compiled with its filename stem as the namespace (e.g., `rules/cmd_injection.yar` → namespace `cmd_injection`). Avoid duplicate rule names within the same file. Rule names must be unique across all files.

### Remove a rule

Delete the `.yar` file, commit, and rolling-restart. The scanner will silently stop matching removed rules at next startup.

---

## 5. Rate Limit Tuning

**Triggers:** `RitAPIRateLimitSurge`, `RitAPIAuthFailureCritical`, legitimate traffic growth.

### Increase threshold (for traffic growth)

```bash
# Bare metal / Docker — edit .env and restart
RATE_LIMIT_REQUESTS=200   # was 100
RATE_LIMIT_WINDOW=60

sudo systemctl restart ritapi-advanced
# or:
docker compose -f docker/app.yml up -d --no-deps app
```

```bash
# Kubernetes — update values and helm upgrade
helm upgrade ritapi-advanced helm/ritapi-advanced -n ritapi \
    --set config.rateLimitRequests=200 \
    --reuse-values --wait
```

### Decrease threshold (active attack)

Lower `RATE_LIMIT_REQUESTS` and restart. For an immediate effect without restart, manually set rate-limit keys in Redis:

```bash
# Force a specific IP to be rate-limited for the next window
redis-cli -a "$REDIS_PASSWORD" SET "ratelimit:ip:1.2.3.4" 999 EX 60
```

### Add IP to bot bypass list

For monitoring/health-check IPs that trigger false positives:

```bash
# Add to .env and restart
BOT_DETECTION_BYPASS_IPS=127.0.0.1,::1,10.0.1.5
```

### Nginx-layer rate limit

The Nginx config (`nginx.conf`) has an outer `limit_req_zone`. Tune `rate=` (requests/second) and `burst=` to match the application-layer thresholds.

---

## 6. WAF Tuning

**Triggers:** False-positive WAF blocks reported by clients, `RitAPIInjectionSurge`.

### Investigate a block

```bash
# Find the blocked request in JSONL logs
grep '"action":"block"' /var/log/ritapi/ritapi_advanced.jsonl \
    | jq 'select(.client_ip == "1.2.3.4")' | tail -20

# Key fields to inspect:
#   detection_type — which rule triggered (SQLI, XSS, CMDI, etc.)
#   reasons        — list of specific pattern names
#   path           — request path
```

### Add a YARA rule exception

If a YARA rule fires on legitimate traffic, narrow the rule condition (add `and not` constraints). Do not delete the rule unless the attack class is no longer relevant.

### Regex pattern review

Injection detection regex patterns are in `app/middlewares/injection_detection.py`. To reduce false positives:

1. Identify the `detection_type` and `reasons` from logs.
2. Find the matching pattern in `INJECTION_PATTERNS`.
3. Make the pattern more specific (tighten anchors, add negative lookaheads).
4. Add a test case to `tests/test_waf.py` for the formerly-blocked legitimate payload.
5. Run `python -m pytest tests/ -q` — all 162 tests must pass.
6. Commit and deploy.

---

## 7. API Key Rotation Policy

### Default TTL

All API keys issued via `POST /admin/apikey` must include a `ttl_days` value. Recommended defaults by role:

| Role | TTL | Rationale |
|---|---|---|
| `SUPER_ADMIN` | 1 day | Bootstrap only; rotate immediately after use |
| `ADMIN` | 30 days | Administrative access; short window |
| `OPERATOR` | 90 days | Service accounts; standard rotation |
| `AUDITOR` | 90 days | Read-heavy; standard rotation |
| `VIEWER` | 180 days | Low-privilege read access |

### Rotation procedure

1. Issue a replacement key before the old one expires:

   ```bash
   curl -s -X POST https://ritapi.example.com/admin/apikey/rotate \
       -H "Authorization: Bearer $ADMIN_TOKEN" \
       -H "Content-Type: application/json" \
       -d '{"old_key": "rita_...", "ttl_days": 90}' | jq .
   ```

   The rotate endpoint issues a new key and revokes the old one atomically.

2. Distribute the new key to the client over a secure channel (not email).

3. Confirm the client is using the new key (check `ritapi_auth_failures_total` for the old key hash).

4. If the old key is still in use after 7 days, contact the key owner — do not force-revoke without notification.

### Emergency revocation

```bash
curl -s -X DELETE https://ritapi.example.com/admin/apikey \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"key": "rita_..."}' | jq .
```

Revocation takes effect immediately (the key is deleted from Redis).

### Expiry reminder workflow

Add a cron job or CI scheduled pipeline to alert on keys expiring within 14 days:

```bash
#!/usr/bin/env bash
# scripts/check_key_expiry.sh — run weekly via cron or CI
TOKEN=$(curl -s -X POST https://ritapi.example.com/admin/token \
    -H "X-Admin-Secret: $ADMIN_SECRET" | jq -r .access_token)

# The /admin/apikey endpoint returns TTL remaining per key
curl -s https://ritapi.example.com/admin/apikey \
    -H "Authorization: Bearer $TOKEN" \
    | jq '.[] | select(.ttl_remaining_days < 14) | "EXPIRING SOON: \(.subject) (\(.ttl_remaining_days) days)"' -r
```

---

## 8. Log Management

### View live logs

```bash
# Bare metal
tail -f /var/log/ritapi/ritapi_advanced.jsonl | jq .

# Docker
docker compose -f docker/app.yml logs -f app | jq .

# Kubernetes
kubectl logs -f deploy/ritapi-advanced -n ritapi | jq .
```

### Search logs

```bash
# All blocks in the last hour
jq 'select(.action == "block")' /var/log/ritapi/ritapi_advanced.jsonl | tail -50

# Blocks from a specific IP
jq 'select(.client_ip == "1.2.3.4" and .action == "block")' \
    /var/log/ritapi/ritapi_advanced.jsonl

# Exfiltration events
jq 'select(.detection_type | startswith("EXFIL"))' \
    /var/log/ritapi/ritapi_advanced.jsonl
```

### Log rotation

Install via:

```bash
sudo cp scripts/logrotate.conf /etc/logrotate.d/ritapi-advanced
# Test:
sudo logrotate --debug /etc/logrotate.d/ritapi-advanced
```

Rotated files are kept for 90 days and gzip-compressed after one day. See `scripts/logrotate.conf` for full configuration.

### Log shipping (optional)

To ship JSONL logs to a central SIEM (e.g., Elasticsearch, Loki):

```bash
# Filebeat config (excerpt)
filebeat.inputs:
  - type: log
    paths:
      - /var/log/ritapi/ritapi_advanced.jsonl
    json.keys_under_root: true
    json.add_error_key: true
    fields:
      service: ritapi-advanced
```

---

## 9. Escalation Path

| Severity | First responder | Escalate to | SLA |
|---|---|---|---|
| Critical (service down, Redis lost) | On-call engineer | Platform lead | 15 min |
| Critical (active exfiltration alert) | On-call engineer | Security team | 15 min |
| Warning (auth spike, rate surge) | On-call engineer | — | 1 hour |
| Warning (cert expiry < 30 d) | On-call engineer | — | 24 hours |
| Info (routine rotation, log rotation) | Owner | — | 72 hours |

**Prometheus alert → on-call:**
Configure AlertManager `receivers` in `docker/prometheus/alerts.yaml` contact points section with PagerDuty, Opsgenie, or email. Update `ops@example.com` to your real address.

**Post-incident:**
File a post-mortem for any Critical incident that persisted > 15 minutes. Template:
1. Timeline (UTC timestamps)
2. Root cause
3. Impact (requests affected, data exposure risk)
4. Mitigation taken
5. Prevention action items with owner and deadline

---

## 10. Multi-Worker Known Limitation (M-8)

RitAPI Advanced uses per-process in-memory singletons for:

- **YARA scanner** (`app/utils/yara_scanner.py`) — rules loaded once at startup
- **Redis client** (`app/utils/redis_client.py`) — singleton per process
- **Policy/route caches** (`app/policies/service.py`, `app/routing/service.py`) — TTL-cached per process (default 60 s, configurable via `CACHE_TTL_SECONDS`)

### Cache TTL (v1.4.0)

Policy and route cache entries now expire automatically after `CACHE_TTL_SECONDS` (default: 60). On expiry the next request to that cache key triggers a fresh disk read. This limits stale-config exposure to at most one TTL window without a full restart.

### Forced reload via admin API (v1.4.0)

```bash
curl -s -X POST https://your-host/admin/reload \
  -H "X-Admin-Secret: $ADMIN_SECRET"
# → {"reloaded": true, "routes": N, "policies": N}
```

This clears both caches and reloads from disk **for the worker that receives the request**. Under multi-worker deployments, send the request once per worker or use a rolling restart instead.

### Impact under `uvicorn --workers N`

When running with multiple Uvicorn workers, each worker is a separate OS process with its own memory space. This means:

- `POST /admin/reload` only affects the worker that handles that specific request
- YARA rule hot-reload via the admin endpoint only affects the worker handling that specific request
- Redis reconnect state (`mark_failed()`) is per-worker — one worker may have a healthy client while another is in cooldown
- TTL expiry is independent per worker, but bounded by `CACHE_TTL_SECONDS`

### Recommended configuration

**Production (multiple workers):** Use a **process manager** (systemd, Kubernetes) to restart all workers atomically when config changes:

```bash
# Full reload — restarts all workers atomically
kill -SIGTERM $(cat /var/run/ritapi.pid) && systemctl start ritapi
# or in Kubernetes: kubectl rollout restart deployment/ritapi-advanced
```

**Single-worker deployments** (e.g. `uvicorn --workers 1`) are not affected — `POST /admin/reload` and TTL expiry work correctly.

**If multi-worker hot-reload is required:** Front the singletons with a shared cache (Redis pub/sub invalidation or a shared config file with inotify) — this is a planned Stage 5 enhancement.
