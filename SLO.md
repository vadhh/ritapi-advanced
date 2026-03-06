# Service Level Objectives — RitAPI Advanced

Version: 1.0.0 | Effective: 2026-03-07 | Review cadence: quarterly

---

## SLO 1 — Availability

**Objective:** 99.5% monthly uptime for the `/healthz` endpoint as measured by an external synthetic monitor.

| Window | Target | Error budget |
|---|---|---|
| Monthly | 99.5% | 3h 39m downtime/month |
| Weekly | 99.0% | 1h 41m downtime/week |

**Measurement:**
- Probe `/healthz` every 60 seconds from at least two external locations.
- A probe returning HTTP 200 within 5 seconds counts as "up".
- Scheduled maintenance windows (announced ≥ 24 h in advance) are excluded.

**Alerting threshold:** Page on-call when availability drops below 99.9% over any rolling 1-hour window (burns >10× the monthly error budget rate).

---

## SLO 2 — Latency (non-blocked requests)

**Objective:** p99 latency < 200 ms for requests that are allowed through the middleware stack (action = "allow"), measured at the application boundary.

| Percentile | Target | Prometheus query |
|---|---|---|
| p50 | < 30 ms | `histogram_quantile(0.50, rate(ritapi_request_duration_seconds_bucket[5m]))` |
| p95 | < 100 ms | `histogram_quantile(0.95, rate(ritapi_request_duration_seconds_bucket[5m]))` |
| p99 | < 200 ms | `histogram_quantile(0.99, rate(ritapi_request_duration_seconds_bucket[5m]))` |

**Error budget:** The p99 SLO may be violated for at most 0.5% of requests over a 30-day rolling window.

**Alerting threshold:** Fire `RitAPIHighLatency` (see `docker/prometheus/alerts.yaml`) when p99 > 1 s for > 5 minutes. Investigate before p99 reaches 200 ms steady-state.

---

## SLO 3 — WAF False-Positive Rate

**Objective:** WAF should not block more than 0.1% of legitimate (non-attack) traffic.

**Measurement method:**
1. Tag a representative sample of known-good requests with a test header during controlled load tests.
2. Count the fraction of tagged requests that receive HTTP 400/403.
3. Alternatively, track the `ritapi_injections_total` rate against overall `ritapi_requests_total{action="allow"}` during baseline (no known attack) periods.

**Target:** False-positive rate ≤ 0.1% over any 7-day window.

**Known open findings that increase false-positive risk:**
- F-02 (PENTEST.md): Fullwidth Unicode characters bypass current regex but could be misidentified if NFKC normalisation is added incorrectly.
- F-03 (PENTEST.md): HTTP Parameter Pollution — low risk, review before enabling strict HPP mode.

**Remediation:** If the false-positive rate exceeds 0.1%, audit JSONL logs for `detection_type` distribution, identify the pattern causing the false positives, and either add an allowlist entry or tune the regex. Do not lower the overall block threshold.

---

## SLO 4 — Auth Latency

**Objective:** JWT and API key validation overhead < 5 ms p99 (in-process, excluding network).

This is an internal implementation SLO, verified via unit benchmarks in `tests/`. It is not directly Prometheus-observable but contributes to SLO 2.

---

## Error Budget Policy

| Remaining budget | Action |
|---|---|
| > 50% | Normal operations. Feature work and non-critical changes proceed. |
| 25–50% | Slow down risky deployments. Add extra monitoring. |
| 10–25% | Freeze non-essential changes. Focus on reliability improvements. |
| < 10% | Incident response posture. Escalate to platform team lead. All changes require approval. |

Budget is tracked monthly. Resets on the 1st of each calendar month.

---

## Review Process

1. SLO compliance is reported in the monthly ops review.
2. Targets are reviewed quarterly against actual traffic and attack volume.
3. Changes to SLO targets require sign-off from the platform lead.
4. Alert thresholds in `docker/prometheus/alerts.yaml` must be updated to match any SLO target changes.
