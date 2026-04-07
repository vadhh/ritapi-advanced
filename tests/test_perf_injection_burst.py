"""
Injection-burst latency profile.

POSTs a body containing a SQLi pattern so InjectionDetectionMiddleware fires
on every request, recording injection_ms under load.

Run with:
    pytest tests/test_perf_injection_burst.py -v -s
"""
import json
import statistics

import pytest
from fastapi.testclient import TestClient

from app.auth.jwt_handler import create_access_token
from app.main import app

BURST_N = 10


@pytest.fixture(scope="module")
def tc():
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


def test_injection_burst_latency(tc, capsys):
    token = create_access_token("inj-tester", "VIEWER", tenant_id="default")
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": "pytest-perf/1.0",
    }
    # XSS in the URL query string — caught by InjectionDetectionMiddleware's URL scan
    # (not by HardGate YARA which only scans the request body).
    # This exercises the regex scan path that dominates injection_ms.
    path = "/probe?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"

    for _ in range(BURST_N):
        tc.get(path, headers=headers)

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
    print(f"INJECTION BURST ({BURST_N} reqs, XSS URL) — sample:")
    print(json.dumps(perf_samples[-1], indent=2))
    print(f"\n{'='*60}\nPER-STAGE AVERAGES (ms):")
    for i, (s, v) in enumerate(ranked, 1):
        print(f"  {i:2d}. {s:<16s}  {v:>8.3f} ms{'  ◄ TOP' if i<=2 else ''}")
    if "total_ms" in avgs:
        print(f"\n      total_ms          {avgs['total_ms']:>8.3f} ms")
    print(f"{'='*60}")

    # All blocked → injection_ms must be present
    inj_vals = [p.get("injection_ms") for p in perf_samples if p.get("injection_ms")]
    assert inj_vals, "injection_ms must be recorded on injection-blocked requests"
