"""
S4 — Throttle (Rate Limit)

5 users sharing a fixed X-Forwarded-For IP, firing at 150 req/s total.
Default RATE_LIMIT_REQUESTS=100 / RATE_LIMIT_WINDOW=60 must produce 429s
within the first window, then reset cleanly on the next window.

Run:
    locust -f tests/perf/locustfile_s4_throttle.py --headless \
      -u 5 -r 5 -t 4m --host http://localhost:8001 \
      --csv=results/s4 --html=results/s4_report.html

Note: flush Redis before re-running to reset counters:
    redis-cli -n 1 FLUSHDB
"""
import os

from locust import HttpUser, constant, events, task

_JWT = os.environ.get("PERF_JWT", "")
_TENANT = "throttle-tenant"

# Fixed spoofed IP so all 5 users share the same Redis rate counter.
# In a real run this should be the actual runner IP (no X-Forwarded-For needed
# if running locally), but a shared header makes the scenario deterministic.
_SHARED_IP = "10.99.0.1"

# Counters for post-run assertion printing
_stats = {"ok": 0, "throttled": 0, "error": 0}


class ThrottleUser(HttpUser):
    wait_time = constant(0)  # fire as fast as possible

    def on_start(self):
        if not _JWT:
            raise RuntimeError("Set PERF_JWT env var to a valid VIEWER token before running.")
        self.headers = {
            "Authorization": f"Bearer {_JWT}",
            "X-Target-ID": _TENANT,
            "X-Forwarded-For": _SHARED_IP,
            "User-Agent": "perf-runner/1.0",
        }

    @task
    def hit_resource(self):
        with self.client.get(
            "/api/v1/resource",
            headers=self.headers,
            catch_response=True,
        ) as resp:
            if resp.status_code in (200, 404):
                _stats["ok"] += 1
                resp.success()
            elif resp.status_code == 429:
                # Expected once threshold is exceeded — not a Locust failure
                _stats["throttled"] += 1
                resp.success()
            elif resp.status_code >= 500:
                _stats["error"] += 1
                resp.failure(f"Server error {resp.status_code} — Redis pipeline may be broken")
            else:
                resp.success()


@events.test_stop.add_listener
def print_throttle_summary(environment, **kwargs):
    total = _stats["ok"] + _stats["throttled"] + _stats["error"]
    throttle_pct = (_stats["throttled"] / total * 100) if total else 0
    print("\n--- S4 Throttle Summary ---")
    print(f"  Total requests : {total}")
    print(f"  200/404 (ok)   : {_stats['ok']}")
    print(f"  429 (throttled): {_stats['throttled']}  ({throttle_pct:.1f} %)")
    print(f"  5xx (errors)   : {_stats['error']}")
    if _stats["error"] > 0:
        print("  FAIL: 5xx responses indicate Redis pipeline instability")
    elif _stats["throttled"] == 0:
        print("  FAIL: no 429s observed — rate limit may not have fired")
    else:
        print("  PASS: throttle fired, no server errors")
