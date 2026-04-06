"""
S3 — Injection Block (WAF Regex)

30 concurrent authenticated users cycling through SQLi, XSS, CMDi, and
clean payloads.  Injection payloads must be blocked (403); clean payloads
must pass (200/404).

Run:
    locust -f tests/perf/locustfile_s3_injection.py --headless \
      -u 30 -r 10 -t 3m --host http://localhost:8001 \
      --csv=results/s3 --html=results/s3_report.html
"""
import itertools
import os

from locust import HttpUser, between, task

_JWT = os.environ.get("PERF_JWT", "")
_TENANT = "perf-tenant"

# Payloads: (body_dict, expect_block)
_PAYLOADS = itertools.cycle([
    ({"q": "' OR '1'='1"},            True),   # SQLi
    ({"q": "<script>alert(1)</script>"}, True),  # XSS
    ({"q": "; ls -la /etc/passwd"},    True),   # CMDi
    ({"q": "normal search term"},      False),  # clean
])


class InjectionUser(HttpUser):
    wait_time = between(0.05, 0.2)

    def on_start(self):
        if not _JWT:
            raise RuntimeError("Set PERF_JWT env var to a valid VIEWER token before running.")
        self.headers = {
            "Authorization": f"Bearer {_JWT}",
            "X-Target-ID": _TENANT,
            "User-Agent": "perf-runner/1.0",
            "Content-Type": "application/json",
        }

    @task
    def send_payload(self):
        body, expect_block = next(_PAYLOADS)
        with self.client.post(
            "/api/v1/search",
            json=body,
            headers=self.headers,
            catch_response=True,
        ) as resp:
            if expect_block:
                if resp.status_code == 403:
                    resp.success()
                else:
                    resp.failure(
                        f"BYPASS: attack payload {body!r} returned {resp.status_code} "
                        f"(expected 403)"
                    )
            else:
                # Clean payload must not be blocked
                if resp.status_code in (200, 404, 422):
                    resp.success()
                elif resp.status_code == 403:
                    resp.failure(
                        f"FALSE POSITIVE: clean payload {body!r} was blocked (403)"
                    )
                else:
                    resp.success()  # unexpected but not a WAF failure
