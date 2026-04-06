"""
Prometheus metrics snapshot differ.

Reads two /metrics text snapshots (before and after a load scenario),
extracts ritapi_* counters, and prints a diff table.

Usage:
    python tests/perf/metrics_diff.py results/before.txt results/after.txt
"""
import re
import sys
from pathlib import Path

_COUNTER_RE = re.compile(r'^(ritapi_\S+)\s+([\d.]+)$')


def parse_metrics(path: Path) -> dict[str, float]:
    out: dict[str, float] = {}
    for line in path.read_text().splitlines():
        m = _COUNTER_RE.match(line.strip())
        if m:
            out[m.group(1)] = float(m.group(2))
    return out


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <before.txt> <after.txt>")
        sys.exit(1)

    before = parse_metrics(Path(sys.argv[1]))
    after  = parse_metrics(Path(sys.argv[2]))

    all_keys = sorted(set(before) | set(after))
    changed = [(k, before.get(k, 0.0), after.get(k, 0.0)) for k in all_keys
               if after.get(k, 0.0) != before.get(k, 0.0)]

    if not changed:
        print("No ritapi_* counters changed between snapshots.")
        return

    col = max(len(k) for k, *_ in changed)
    print(f"\n{'Metric':<{col}}  {'Before':>12}  {'After':>12}  {'Delta':>12}")
    print("-" * (col + 40))
    for key, b, a in changed:
        delta = a - b
        sign = "+" if delta >= 0 else ""
        print(f"{key:<{col}}  {b:>12.0f}  {a:>12.0f}  {sign}{delta:>11.0f}")
    print()


if __name__ == "__main__":
    main()
