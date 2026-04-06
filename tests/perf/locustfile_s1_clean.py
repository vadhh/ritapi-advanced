"""
S1 — Clean Traffic (Baseline)

50 concurrent authenticated users sending GET requests that should pass
all middleware without any detections.

Run:
    locust -f tests/perf/locustfile_s1_clean.py --headless \
      -u 50 -r 5 -t 5m --host http://localhost:8001 \
      --csv=results/s1 --html=results/s1_report.html
"""
import os

from locust import HttpUser, between, task


_JWT = os.environ.get("PERF_JWT", "")
_TENANT = "perf-tenant"


class CleanUser(HttpUser):
    wait_time = between(0.1, 0.5)

    def on_start(self):
        if not _JWT:
            raise RuntimeError("Set PERF_JWT env var to a valid VIEWER token before running.")
        self.headers = {
            "Authorization": f"Bearer {_JWT}",
            "X-Target-ID": _TENANT,
            "User-Agent": "perf-runner/1.0",
        }

    @task(3)
    def healthz(self):
        """Bypass route — no auth, no Redis, baseline for raw framework overhead."""
        with self.client.get("/healthz", catch_response=True) as resp:
            if resp.status_code != 200:
                resp.failure(f"Expected 200, got {resp.status_code}")
            else:
                resp.success()

    @task(5)
    def api_status(self):
        """Authenticated GET — exercises the full middleware stack on a clean request."""
        with self.client.get(
            "/api/v1/status",
            headers=self.headers,
            catch_response=True,
        ) as resp:
            # 404 is fine — route may not be defined; we care that it is not blocked
            if resp.status_code in (200, 404):
                resp.success()
            else:
                resp.failure(f"Unexpected status {resp.status_code} on clean request")

    @task(1)
    def metrics_scrape(self):
        """Prometheus scrape — should always return 200 with text/plain."""
        with self.client.get("/metrics", catch_response=True) as resp:
            if resp.status_code == 200:
                resp.success()
            else:
                resp.failure(f"Metrics endpoint returned {resp.status_code}")
