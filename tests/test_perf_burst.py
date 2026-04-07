"""
Latency profiling burst test.

Sends 25 clean requests through the full middleware stack, captures the
perf breakdown from SIEM stdout, and prints per-stage averages + top 2
bottlenecks.

Run with:
    pytest tests/test_perf_burst.py -v -s
"""
import json
import statistics

import pytest
from fastapi.testclient import TestClient

from app.auth.jwt_handler import create_access_token
from app.main import app

UA = "pytest-perf-burst/1.0"
BURST_N = 15  # stay under RATE_LIMIT_REQUESTS=20 set in conftest


@pytest.fixture(scope="module")
def tc():
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


def test_burst_latency_profile(tc, capsys):
    token = create_access_token("perf-tester", "VIEWER", tenant_id="default")
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": UA,
    }

    # Drive BURST_N requests to a real route so every middleware stage runs.
    # /healthz bypasses auth; /probe goes through the full stack.
    for _ in range(BURST_N):
        tc.get("/probe", headers=headers)

    # Harvest SIEM lines from stdout
    raw = capsys.readouterr().out
    perf_samples: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        p = ev.get("perf")
        if isinstance(p, dict) and p:
            perf_samples.append(p)

    assert perf_samples, (
        "No perf data found in SIEM output — "
        "check that security_event_logger.py emits the perf field"
    )

    # Collect per-stage samples
    stages = ["auth_ms", "bot_ms", "injection_ms", "exfil_ms", "decision_ms",
              "redis_ms", "total_ms"]
    stage_vals: dict[str, list[float]] = {s: [] for s in stages}

    for p in perf_samples:
        for s in stages:
            v = p.get(s)
            if isinstance(v, (int, float)):
                stage_vals[s].append(float(v))

    # Compute averages (only for stages with data)
    avgs: dict[str, float] = {}
    for s, vals in stage_vals.items():
        if vals:
            avgs[s] = round(statistics.mean(vals), 3)

    # Print sample log
    print("\n" + "=" * 62)
    print(f"PERF BURST ({BURST_N} requests) — sample event:")
    print("=" * 62)
    print(json.dumps(perf_samples[-1], indent=2))

    # Print stage averages
    print("\n" + "=" * 62)
    print("PER-STAGE AVERAGES (ms):")
    print("-" * 62)
    ranked = sorted(
        ((s, v) for s, v in avgs.items() if s != "total_ms"),
        key=lambda x: x[1],
        reverse=True,
    )
    for i, (stage, avg) in enumerate(ranked, 1):
        marker = " ◄ TOP" if i <= 2 else ""
        print(f"  {i:2d}. {stage:<16s}  {avg:>8.3f} ms{marker}")
    if "total_ms" in avgs:
        print(f"\n      total_ms          {avgs['total_ms']:>8.3f} ms  (wall time)")

    # Bottleneck summary
    print("\n" + "=" * 62)
    print("Top contributors:")
    for i, (stage, avg) in enumerate(ranked[:2], 1):
        print(f"  {i}. {stage} ≈ {avg:.1f} ms")
    print("=" * 62)

    # Assertions: perf keys must be present and non-negative
    assert len(perf_samples) >= BURST_N // 2, (
        f"Expected at least {BURST_N // 2} perf samples, got {len(perf_samples)}"
    )
    for stage, avg in avgs.items():
        assert avg >= 0, f"{stage} average must be non-negative (got {avg})"
