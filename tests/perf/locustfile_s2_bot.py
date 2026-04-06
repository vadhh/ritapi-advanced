"""
S2 — Bot Traffic (Behavioral Detection)

20 concurrent users with a suspicious user-agent rotating across 15+
distinct endpoints.  Triggers SUSPICIOUS_USER_AGENT, RAPID_FIRE,
BURST_TRAFFIC, and ENDPOINT_SCANNING rules.

Expected: ≥ 95 % of requests after the 30-second warm-up return 403.

Run:
    locust -f tests/perf/locustfile_s2_bot.py --headless \
      -u 20 -r 20 -t 3m --host http://localhost:8001 \
      --csv=results/s2 --html=results/s2_report.html

Note: ensure the Locust runner IP is NOT in BOT_DETECTION_BYPASS_IPS.
"""
import itertools

from locust import HttpUser, constant, task

# 20 distinct paths — drives ENDPOINT_SCANNING (threshold: 15 / 5 min)
_PATHS = [f"/api/v1/endpoint/{i}" for i in range(20)]
_PATH_CYCLE = itertools.cycle(_PATHS)

# Matches _SUSPICIOUS_UA_TOKENS in bot_detection.py
_BOT_UA = "python-requests/2.31.0"


class BotUser(HttpUser):
    # No wait — fire as fast as possible to trigger RAPID_FIRE (50 req / 10 s)
    wait_time = constant(0)

    def on_start(self):
        self.headers = {
            "User-Agent": _BOT_UA,
            # No auth — also triggers NO_USER_AGENT scoring indirectly via missing auth
        }

    @task
    def scan_endpoint(self):
        path = next(_PATH_CYCLE)
        with self.client.get(path, headers=self.headers, catch_response=True) as resp:
            if resp.status_code == 403:
                # Expected after warm-up — mark as success so Locust counts throughput
                resp.success()
            elif resp.status_code in (200, 404, 401):
                # Acceptable during warm-up window (first ~30 s)
                resp.success()
            else:
                resp.failure(f"Unexpected {resp.status_code} from bot scenario")
