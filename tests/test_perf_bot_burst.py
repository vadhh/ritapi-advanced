"""
Bot-burst latency profile.

Sends requests with a suspicious User-Agent so bot detection fires on every
request, recording bot_ms + redis_ms under load.

Run with:
    pytest tests/test_perf_bot_burst.py -v -s
"""
import json
import statistics

import pytest
from fastapi.testclient import TestClient

from app.auth.jwt_handler import create_access_token
from app.main import app

BURST_N = 10
# A UA that triggers SUSPICIOUS_USER_AGENT in bot detection
BOT_UA = "sqlmap/1.7.8"


@pytest.fixture(scope="module")
def tc():
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


def test_bot_burst_latency(tc, capsys):
    token = create_access_token("bot-tester", "VIEWER", tenant_id="default")
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": BOT_UA,
        "X-Forwarded-For": "10.99.perf.bot.1",
    }

    for _ in range(BURST_N):
        tc.get("/probe", headers=headers)

    raw = capsys.readouterr().out
    perf_samples = []
    for line in raw.splitlines():
        try:
            ev = json.loads(line.strip())
        except json.JSONDecodeError:
            continue
        p = ev.get("perf")
        if isinstance(p, dict) and p:
            perf_samples.append(p)

    assert perf_samples, "No perf samples captured"

    stages = ["auth_ms", "bot_ms", "injection_ms", "exfil_ms", "decision_ms", "redis_ms", "total_ms"]
    avgs = {}
    for s in stages:
        vals = [float(p[s]) for p in perf_samples if isinstance(p.get(s), (int, float))]
        if vals:
            avgs[s] = round(statistics.mean(vals), 3)

    ranked = sorted(
        ((s, v) for s, v in avgs.items() if s != "total_ms"),
        key=lambda x: x[1], reverse=True
    )

    print(f"\n{'='*60}")
    print(f"BOT BURST ({BURST_N} reqs, UA={BOT_UA!r}) — sample:")
    print(json.dumps(perf_samples[-1], indent=2))
    print(f"\n{'='*60}\nPER-STAGE AVERAGES (ms):")
    for i, (s, v) in enumerate(ranked, 1):
        print(f"  {i:2d}. {s:<16s}  {v:>8.3f} ms{'  ◄ TOP' if i<=2 else ''}")
    if "total_ms" in avgs:
        print(f"\n      total_ms          {avgs['total_ms']:>8.3f} ms")
    print(f"{'='*60}")
