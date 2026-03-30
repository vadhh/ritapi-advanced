# Configuration Reference — RitAPI Advanced

All configuration is supplied via environment variables (or a `.env` file in the working directory). No YAML or TOML config files are used at runtime.

---

## Auth & JWT

| Variable | Type | Default | Description |
|---|---|---|---|
| `SECRET_KEY` | string | **required** | HMAC signing key for JWT tokens. Generate with `python -c "import secrets; print(secrets.token_hex(32))"`. Minimum 32 bytes of entropy. |
| `JWT_ALGORITHM` | string | `HS256` | JWT signing algorithm. Only `HS256` is tested and supported. |
| `JWT_EXPIRE_MINUTES` | integer | `60` | Access token TTL in minutes. Tokens are rejected after expiry regardless of Redis state. |

---

## Admin Bootstrap

| Variable | Type | Default | Description |
|---|---|---|---|
| `ADMIN_SECRET` | string | **required** | Shared secret for the `POST /admin/token` bootstrap endpoint. Used to obtain the first SUPER_ADMIN JWT. Rotate after first use if possible. Must not be empty. |

---

## Redis

| Variable | Type | Default | Description |
|---|---|---|---|
| `REDIS_URL` | string | `redis://localhost:6379/1` | Full Redis connection URL. Format: `redis://[:password@]host:port/db`. Use `rediss://` for TLS. |
| `REDIS_PASSWORD` | string | `""` | Redis AUTH password. If set, appended to the URL automatically (takes precedence over any password in `REDIS_URL`). |
| `REDIS_SENTINEL_HOSTS` | string | `""` | Comma-separated `host:port` pairs for Sentinel HA mode, e.g. `sentinel1:26379,sentinel2:26379,sentinel3:26379`. When set, `REDIS_URL` is used as fallback only. |
| `REDIS_SENTINEL_SERVICE` | string | `mymaster` | Sentinel master name. Only used when `REDIS_SENTINEL_HOSTS` is non-empty. |

**Redis database layout:**

| Key pattern | Namespace | TTL |
|---|---|---|
| `ratelimit:ip:<ip>` | rate limiting | `RATE_LIMIT_WINDOW` seconds |
| `ratelimit:key:<hash>` | per-API-key rate limit | `RATE_LIMIT_WINDOW` seconds |
| `bot:<ip>:score` | bot risk accumulator | 300 s |
| `bot:<ip>:<rule>` | per-rule counters | varies |
| `exfil:<ip>:vol` | exfiltration volume | 3600 s |
| `exfil:<ip>:bulk` | bulk access counter | 300 s |
| `apikey:<sha256>` | API key store | key TTL |

---

## Rate Limiting

| Variable | Type | Default | Description |
|---|---|---|---|
| `RATE_LIMIT_REQUESTS` | integer | `100` | Maximum requests per window per IP (or per API key when authenticated). |
| `RATE_LIMIT_WINDOW` | integer | `60` | Sliding window size in seconds. |

Requests exceeding the limit receive HTTP `429` with a `Retry-After` header.

---

## Bot Detection

| Variable | Type | Default | Description |
|---|---|---|---|
| `BOT_DETECTION_BYPASS_IPS` | string | `127.0.0.1,::1` | Comma-separated IPs exempt from bot detection. Add monitoring agents, health-check sources, and trusted internal IPs. Supports exact IPv4/IPv6 addresses only (no CIDR). |

Bot detection uses a risk accumulator. Rules and their default score contributions:

| Rule | Score | Notes |
|---|---|---|
| `RAPID_FIRE` | 40 | >50 req/min |
| `BURST_TRAFFIC` | 30 | >20 req in 5 s |
| `NO_USER_AGENT` | 60 | Missing UA header |
| `SUSPICIOUS_USER_AGENT` | 60 | Known scanner UA (sqlmap, nikto, etc.) |
| `ENDPOINT_SCANNING` | 50 | >10 distinct 404s in 60 s |
| `ERROR_RATE_ANOMALY` | 35 | >30% 4xx/5xx over 100 requests |

Requests with accumulated score ≥ 70 are blocked with HTTP `403`.

---

## Injection Detection (WAF)

No env vars tune WAF behaviour at runtime. Pattern matching uses compiled regexes (96 patterns across XSS, SQLi, CMDi, path traversal, LDAP, scanner UA) plus YARA rules.

To add custom patterns, add `.yar` rule files to `YARA_RULES_DIR` and restart the service.

---

## Exfiltration Detection

| Variable | Type | Default | Description |
|---|---|---|---|
| *(none)* | — | — | Thresholds are compiled constants. See `app/middlewares/exfiltration_detection.py` for `LARGE_RESPONSE_BYTES`, `BULK_ACCESS_THRESHOLD`, `VOLUME_THRESHOLD_BYTES`, `SEQUENTIAL_CRAWL_THRESHOLD`. |

---

## Logging

| Variable | Type | Default | Description |
|---|---|---|---|
| `LOG_PATH` | string | `/var/log/ritapi/ritapi_advanced.jsonl` | Absolute path to the JSONL structured log file. Parent directories are created automatically. Fallback to stderr if the path is not writable. |

Each log line is a JSON object:

```json
{
  "timestamp": "2026-03-07T12:00:00.123456Z",
  "client_ip": "1.2.3.4",
  "path": "/api/data",
  "method": "POST",
  "action": "block",
  "detection_type": "SQLI",
  "score": 100,
  "reasons": ["sql_union_select"]
}
```

`action` values: `allow`, `block`, `monitor`.

---

## YARA

| Variable | Type | Default | Description |
|---|---|---|---|
| `YARA_RULES_DIR` | string | `/app/rules` | Directory containing `.yar` rule files. All files in this directory are compiled at startup. Invalid rule files are skipped with a warning; the service starts regardless. |

Bundled rule files:

| File | Rules | Detects |
|---|---|---|
| `rules/sqli.yar` | 6 | UNION SELECT, stacked queries, boolean blind, time-based, error-based, information_schema |
| `rules/xss.yar` | 5 | Script tags, event handlers, javascript: URI, polyglots, dangerous HTML |
| `rules/shell_injection.yar` | 5 | Command chaining, file read, remote exec, env var leaks, reverse shells |
| `rules/credential_stuffing.yar` | 4 | Bulk credential arrays, tool signatures, JSON auth arrays, common password lists |

To add rules without restarting: hot-reload is not supported. Restart the service after adding `.yar` files.

---

## Environment Tag

| Variable | Type | Default | Description |
|---|---|---|---|
| `ENV` | string | `production` | Informational tag included in structured log entries. Common values: `development`, `staging`, `production`. Does not change behaviour. |

---

## TLS / Nginx

TLS is terminated by Nginx, not by the Python application. Configure Nginx using `nginx.conf`. The application listens on plain HTTP port `8001` internally.

Relevant Nginx variables (set in `nginx.conf`, not `.env`):

| Directive | Default | Description |
|---|---|---|
| `ssl_certificate` | `certs/server.crt` | Path to TLS certificate chain |
| `ssl_certificate_key` | `certs/server.key` | Path to TLS private key |
| `limit_req_zone` | 100r/s per IP | Nginx-level rate limit (first line of defence) |

---

## Prometheus Metrics

Metrics are exported at `GET /metrics` (plain text, Prometheus format). The endpoint is not auth-protected by the application — restrict it at the Nginx or network layer.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `ritapi_requests_total` | counter | `action`, `detection_type` | All processed requests |
| `ritapi_injections_total` | counter | `detection_type` | WAF blocks |
| `ritapi_bot_blocks_total` | counter | `rule` | Bot detection blocks |
| `ritapi_exfil_blocks_total` | counter | `heuristic` | Exfiltration blocks |
| `ritapi_auth_failures_total` | counter | `reason` | Auth rejections |
| `ritapi_rate_limit_hits_total` | counter | `limit_type` | Rate limit 429s |
| `ritapi_threat_score` | histogram | — | Risk score distribution |
| `ritapi_response_size_bytes` | histogram | — | Outbound response sizes |
| `ritapi_redis_connected` | gauge | — | Redis connection state (0/1) |
| `ritapi_active_api_keys` | gauge | — | Count of non-expired API keys |

---

## Security Hardening Checklist

Before going to production, verify:

- [ ] `SECRET_KEY` is at least 32 bytes of random entropy, not reused across environments
- [ ] `ADMIN_SECRET` is a strong random value, rotated after initial bootstrap
- [ ] `REDIS_PASSWORD` is set and Redis is not exposed outside the internal network
- [ ] `LOG_PATH` directory is writable by the service user only (`chmod 750`)
- [ ] Nginx restricts `GET /metrics` to internal/monitoring IPs (`allow 10.0.0.0/8; deny all;`)
- [ ] TLS 1.2 minimum enforced in `nginx.conf` (`ssl_protocols TLSv1.2 TLSv1.3;`)
- [ ] `BOT_DETECTION_BYPASS_IPS` contains only trusted IPs; remove `127.0.0.1` if not needed
- [ ] `JWT_EXPIRE_MINUTES` is tuned to your session lifetime requirements
