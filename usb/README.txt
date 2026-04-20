RitAPI Advanced — API Protection Demo
======================================

Requirements
------------
  - Windows 10/11 with WSL2 + Docker Desktop, OR native Linux with Docker
  - Docker Compose v2  (docker compose version — should print v2.x)
  - curl and python3 installed
  - Ports 8001 and 6379 free on localhost

Run the Demo
------------
  bash demo.sh

  First run on a new machine: loads Docker images from USB (~1-2 min, one-time).
  Subsequent runs: starts immediately.

  The attack suite runs automatically after startup.
  Watch the SIEM events in a second terminal:

    docker compose -f docker/demo.yml logs -f app

Dashboard
---------
  http://localhost:8001/dashboard   ← real-time security event dashboard
  http://localhost:8001/metrics     ← Prometheus metrics

Re-run Attacks
--------------
  bash scripts/demo_attack.sh

Reset Counters Between Runs
---------------------------
  bash scripts/demo_clean.sh

Stop
----
  bash stop.sh
  (or Ctrl+C if running in foreground — the exit message will show the stop command)

Troubleshooting
---------------
  Port 8001 in use?
    bash stop.sh
    then re-run demo.sh

  Docker not found?
    Windows: open Docker Desktop and ensure WSL integration is enabled.
    Linux:   sudo systemctl start docker

  Attack script reports "Token issuance failed"?
    The app container is still starting. Wait 10 seconds and run:
    bash scripts/demo_attack.sh

Full demo script: ask your RitAPI contact for the demo master script.
