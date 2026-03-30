"""
Prometheus metrics for RitAPI Advanced.

All counters/histograms are defined here as module-level singletons.
Middlewares import what they need directly.

Exposed at GET /metrics (see app/main.py).
"""
from prometheus_client import Counter, Gauge, Histogram

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------

requests_total = Counter(
    "ritapi_requests_total",
    "Total requests processed by RitAPI Advanced",
    ["method", "action", "detection_type"],
)

rate_limit_hits = Counter(
    "ritapi_rate_limit_hits_total",
    "Number of requests blocked by rate limiter",
    ["identity_type"],  # "ip" or "apikey"
)

injection_blocks = Counter(
    "ritapi_injection_blocks_total",
    "Requests blocked by injection detection",
    ["category"],  # xss, sqli, cmdi, path_traversal, ldap, scanner_ua, yara
)

bot_signals = Counter(
    "ritapi_bot_signals_total",
    "Bot detection signals fired",
    ["rule"],  # RAPID_FIRE, BURST_TRAFFIC, etc.
)

bot_blocks = Counter(
    "ritapi_bot_blocks_total",
    "Requests blocked by bot detection (cumulative risk ≥ threshold)",
)

exfiltration_alerts = Counter(
    "ritapi_exfiltration_alerts_total",
    "Exfiltration detection alerts fired",
    ["reason"],  # large_response, bulk_access, sequential_crawl
)

auth_failures = Counter(
    "ritapi_auth_failures_total",
    "Authentication failures (invalid/missing JWT or API key)",
    ["method"],  # jwt, apikey
)

# ---------------------------------------------------------------------------
# Histograms
# ---------------------------------------------------------------------------

threat_score = Histogram(
    "ritapi_threat_score",
    "Distribution of threat scores assigned by detection layer (0.0–1.0)",
    buckets=[0.0, 0.1, 0.25, 0.5, 0.6, 0.75, 0.9, 1.0],
)

response_size_bytes = Histogram(
    "ritapi_response_size_bytes",
    "Distribution of response body sizes in bytes",
    buckets=[1_024, 10_240, 102_400, 512_000, 1_048_576, 5_242_880, 10_485_760],
)

# ---------------------------------------------------------------------------
# Gauges
# ---------------------------------------------------------------------------

active_rate_limit_keys = Gauge(
    "ritapi_active_rate_limit_keys",
    "Current number of active per-IP rate limit keys in Redis",
)

active_bot_risk_ips = Gauge(
    "ritapi_active_bot_risk_ips",
    "Current number of IPs with a non-zero bot risk score in Redis",
)

redis_connected = Gauge(
    "ritapi_redis_connected",
    "1 if Redis is reachable, 0 if the client is in fail-open mode",
)
