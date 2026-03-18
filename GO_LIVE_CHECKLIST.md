# RitAPI Advanced — Go-Live Checklist

Complete all items before transitioning from MONITOR → ENFORCE in production.

---

## Infrastructure

- [ ] Host provisioned with required resources (CPU, RAM, disk)
- [ ] TLS certificates installed and valid (not self-signed in production)
- [ ] Nginx configured and passing `nginx -t`
- [ ] HSTS header enabled in Nginx config
- [ ] Redis running (standalone or Sentinel HA for production)
- [ ] Redis persistence configured (AOF or RDB) if state must survive restarts
- [ ] DNS records pointing to the load balancer / Nginx host
- [ ] Firewall rules: only 80 (redirect), 443 (HTTPS), and monitoring ports open
- [ ] Log directory `/var/log/ritapi/` exists with correct ownership (`ritapi:ritapi`)
- [ ] Logrotate config deployed to `/etc/logrotate.d/ritapi-advanced`
- [ ] Backup script (`scripts/backup.sh`) tested and cron job scheduled
- [ ] Restore script (`scripts/restore.sh`) tested with a real backup
- [ ] Prometheus scraping `/metrics` endpoint
- [ ] Grafana dashboard imported and alerting rules active
- [ ] Disk space monitoring configured for log and backup directories

## Product / Application

- [ ] `SECRET_KEY` set to a strong random value (not the default)
- [ ] `ADMIN_SECRET` set to a strong random value (not the default)
- [ ] `routing.yml` deployed with all production routes defined
- [ ] Policy files (`auth.yml`, `payment.yml`, `admin.yml`) reviewed and deployed
- [ ] Rate limits tuned per-route based on expected traffic
- [ ] JSON schema enforcement enabled for endpoints that require strict input
- [ ] YARA rules deployed and `YARA_RULES_DIR` set
- [ ] Bot detection bypass IPs updated (`BOT_DETECTION_BYPASS_IPS`)
- [ ] Dashboard access secured (`DASHBOARD_TOKEN` set or network-restricted)
- [ ] `/healthz` returning 200
- [ ] `/metrics` returning Prometheus data
- [ ] MONITOR phase completed with < 1% false-positive rate
- [ ] All decision actions set to intended values (block/throttle/monitor)
- [ ] Admin API tested: token issuance, key rotation, key revocation

## Security

- [ ] No hardcoded secrets in code or config files committed to git
- [ ] `.env` file excluded from version control (`.gitignore`)
- [ ] systemd service hardened (`NoNewPrivileges`, `ProtectSystem`, `ProtectHome`, `PrivateTmp`)
- [ ] Nginx security headers present (HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
- [ ] TLS 1.2+ only (no SSLv3, TLS 1.0, TLS 1.1)
- [ ] SSL ciphers restricted to AEAD suites
- [ ] `/metrics` endpoint restricted to localhost / monitoring subnet
- [ ] WAF injection patterns tested (XSS, SQLi, CMDi, path traversal)
- [ ] Exfiltration detection thresholds reviewed
- [ ] API keys use SHA-256 hashing (not stored in plaintext)
- [ ] JWT expiration configured appropriately (`JWT_EXPIRE_MINUTES`)
- [ ] Penetration test completed (see `PENTEST.md`)
- [ ] gitleaks / secret scanning passing in CI

---

## Sign-Off

| Role | Name | Date | Approved |
|------|------|------|----------|
| Infrastructure Lead | | | [ ] |
| Product Owner | | | [ ] |
| Security Lead | | | [ ] |
