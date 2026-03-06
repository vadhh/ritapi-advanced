"""
locustfile.py — Load and stress testing for RitAPI Advanced.

Usage:
    pip install locust
    locust -f locustfile.py --host=http://localhost:8001

Then open http://localhost:8089 to configure and start the test.

Or headless (CI):
    locust -f locustfile.py --host=http://localhost:8001 \
           --users=50 --spawn-rate=10 --run-time=60s --headless

Scenarios:
  LegitimateUser   — authenticated requests (70% of traffic)
  AttackerUser     — injection attempts, scanner UA (20% of traffic)
  CrawlerBot       — rapid endpoint scanning (10% of traffic)

Prerequisites:
  - Server running: uvicorn app.main:app --port 8001
  - Valid JWT in env: export LOCUST_TOKEN=$(python -c "
        from dotenv import load_dotenv; load_dotenv()
        from app.auth.jwt_handler import create_access_token
        print(create_access_token('loadtest', 'VIEWER'))")
"""
import os
import random

from locust import HttpUser, between, task


_TOKEN = os.getenv("LOCUST_TOKEN", "")
_AUTH_HEADERS = {
    "Authorization": f"Bearer {_TOKEN}",
    "User-Agent": "LoadTest-Client/1.0",
    "Content-Type": "application/json",
}

_PATHS = [
    "/api/users",
    "/api/products",
    "/api/orders",
    "/api/search",
    "/api/config",
    "/api/status",
    "/api/events",
    "/api/metrics",
    "/api/reports",
    "/api/audit",
]

_XSS_PAYLOADS = [
    '{"input": "<script>alert(1)</script>"}',
    '{"comment": "\' OR 1=1--"}',
    '{"q": "$(whoami)"}',
    '{"redirect": "javascript:alert(1)"}',
]


class LegitimateUser(HttpUser):
    """Simulates a normal authenticated API consumer."""
    weight = 70
    wait_time = between(0.5, 2.0)

    @task(5)
    def get_resource(self):
        path = random.choice(_PATHS)
        with self.client.get(
            path,
            headers=_AUTH_HEADERS,
            catch_response=True,
            name="/api/[resource]",
        ) as resp:
            # 404 is expected (routes don't exist) — not a failure
            if resp.status_code not in (200, 404, 401, 429):
                resp.failure(f"Unexpected status: {resp.status_code}")
            else:
                resp.success()

    @task(2)
    def post_data(self):
        with self.client.post(
            "/api/data",
            headers=_AUTH_HEADERS,
            data='{"key": "value", "count": 42}',
            catch_response=True,
            name="/api/data [POST]",
        ) as resp:
            if resp.status_code not in (200, 404, 401, 422, 429):
                resp.failure(f"Unexpected status: {resp.status_code}")
            else:
                resp.success()

    @task(1)
    def health_check(self):
        self.client.get("/healthz", name="/healthz")

    @task(1)
    def dashboard(self):
        self.client.get(
            "/dashboard/stats",
            headers=_AUTH_HEADERS,
            name="/dashboard/stats",
        )


class AttackerUser(HttpUser):
    """Simulates an attacker sending injection payloads."""
    weight = 20
    wait_time = between(0.1, 0.5)

    @task(3)
    def injection_attempt(self):
        payload = random.choice(_XSS_PAYLOADS)
        with self.client.post(
            "/api/data",
            headers={**_AUTH_HEADERS, "User-Agent": "sqlmap/1.7"},
            data=payload,
            catch_response=True,
            name="/api/data [ATTACK]",
        ) as resp:
            # 403 is expected — the WAF should block these
            if resp.status_code == 403:
                resp.success()
            elif resp.status_code == 429:
                resp.success()  # rate limited — also correct
            else:
                resp.failure(f"Attack not blocked: {resp.status_code}")

    @task(1)
    def path_traversal(self):
        with self.client.get(
            "/api/data?path=../../etc/passwd",
            headers=_AUTH_HEADERS,
            catch_response=True,
            name="/api [traversal]",
        ) as resp:
            if resp.status_code == 403:
                resp.success()
            elif resp.status_code == 429:
                resp.success()
            else:
                resp.failure(f"Traversal not blocked: {resp.status_code}")


class CrawlerBot(HttpUser):
    """Simulates a rapid-fire endpoint scanner / crawler."""
    weight = 10
    wait_time = between(0.05, 0.2)
    _counter = 0

    @task
    def scan_endpoint(self):
        CrawlerBot._counter += 1
        path = f"/api/endpoint/{CrawlerBot._counter}"
        with self.client.get(
            path,
            headers={"User-Agent": "crawler/1.0"},
            catch_response=True,
            name="/api/endpoint/[n]",
        ) as resp:
            # 401 (no auth), 403 (bot/exfil blocked), 429 (rate limited) all OK
            if resp.status_code in (401, 403, 404, 429):
                resp.success()
            else:
                resp.success()  # any response is fine for scanning simulation
