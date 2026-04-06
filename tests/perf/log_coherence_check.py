"""
SIEM log coherence checker — run alongside a load scenario.

Tails the SIEM log (stdout JSON lines from DecisionEngine / hard_gate /
injection_detection) and verifies every line has the required fields and
correct types.  Reports violations immediately; prints a summary on exit.

Usage:
    # In one terminal, run the server so its stdout goes to a file:
    uvicorn app.main:app --port 8001 2>&1 | tee /tmp/ritapi_siem.log

    # In another terminal, start the coherence checker:
    python tests/perf/log_coherence_check.py /tmp/ritapi_siem.log

    # Then run any load scenario in a third terminal.
    # Press Ctrl-C to stop the checker and see the summary.
"""
import json
import signal
import sys
import time
from pathlib import Path

REQUIRED_FIELDS: dict[str, type] = {
    "event_type":       str,
    "severity":         str,
    "action":           str,
    "timestamp":        str,
    "request_id":       str,
    "tenant_id":        str,
    "source_ip":        str,
    "method":           str,
    "route":            str,
    "reason":           str,
    "trigger_type":     str,
    "trigger_source":   str,
    "status_code":      int,
    "detection_count":  int,
    "detection_types":  str,
}

VALID_ACTIONS    = {"block", "throttle", "monitor", "allow"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def check_event(event: dict) -> list[str]:
    errors: list[str] = []

    for field, expected_type in REQUIRED_FIELDS.items():
        if field not in event:
            errors.append(f"missing field: {field!r}")
        elif not isinstance(event[field], expected_type):
            errors.append(
                f"field {field!r} type mismatch: "
                f"expected {expected_type.__name__}, got {type(event[field]).__name__}"
            )

    if event.get("action") not in VALID_ACTIONS:
        errors.append(f"invalid action: {event.get('action')!r}")

    if event.get("severity") not in VALID_SEVERITIES:
        errors.append(f"invalid severity: {event.get('severity')!r}")

    if event.get("request_id", "") in ("", "none", "null", None):
        errors.append("request_id is empty or null")

    return errors


def tail(path: Path):
    """Generator that yields new lines appended to a file (like `tail -f`)."""
    with path.open() as fh:
        fh.seek(0, 2)  # seek to end
        while True:
            line = fh.readline()
            if line:
                yield line
            else:
                time.sleep(0.05)


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <log_file>")
        sys.exit(1)

    log_path = Path(sys.argv[1])
    if not log_path.exists():
        print(f"Log file not found: {log_path}  (waiting for it to appear…)")
        while not log_path.exists():
            time.sleep(0.5)

    total = 0
    violations = 0
    parse_errors = 0

    def _summary(*_):
        print(f"\n--- Log Coherence Summary ---")
        print(f"  SIEM events checked : {total}")
        print(f"  Field violations    : {violations}")
        print(f"  JSON parse errors   : {parse_errors}")
        if violations == 0 and parse_errors == 0:
            print("  PASS: all events are well-formed")
        else:
            print("  FAIL: see violations above")
        sys.exit(0)

    signal.signal(signal.SIGINT, _summary)
    signal.signal(signal.SIGTERM, _summary)

    print(f"Watching {log_path}  (Ctrl-C to stop and print summary)")

    for raw_line in tail(log_path):
        raw_line = raw_line.strip()
        if not raw_line:
            continue

        # Only check lines that look like SIEM events
        if '"event_type"' not in raw_line:
            continue

        try:
            event = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            parse_errors += 1
            print(f"PARSE ERROR: {exc}  line={raw_line[:120]!r}")
            continue

        total += 1
        errors = check_event(event)
        if errors:
            violations += len(errors)
            rid = event.get("request_id", "?")
            for err in errors:
                print(f"VIOLATION [{rid}] {err}")


if __name__ == "__main__":
    main()
