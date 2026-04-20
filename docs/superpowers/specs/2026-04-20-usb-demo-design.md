# USB Demo Kit — Design Spec
**Date:** 2026-04-20
**Project:** RitAPI Advanced
**Status:** approved

---

## Goal

Package the RitAPI Advanced demo into a single 8GB USB key that a sales person can plug into any Windows (WSL2) or Linux laptop and run with one command — no internet required.

---

## Approach

Single smart launcher (`demo.sh` at USB root). On first run it loads Docker images from the USB tar onto the host; subsequent runs detect images already loaded and skip the load step. The stack runs detached (`-d`) then fires the attack suite automatically — matching the existing `demo_run.sh` pattern. A `stop.sh` convenience script handles teardown.

---

## USB Layout

```
USB root/
├── demo.sh                    ← smart launcher (load → up -d → attack)
├── stop.sh                    ← docker compose down wrapper
├── README.txt                 ← quickstart for sales team
├── .env.demo                  ← demo credentials (safe to distribute)
├── images/
│   └── ritapi-advanced.tar    ← docker save of app image + redis:7-alpine (~500MB–1GB)
├── docker/
│   └── demo.usb.yml           ← USB compose file using image: tags
└── scripts/
    ├── demo_attack.sh         ← re-run attack suite manually
    └── demo_clean.sh          ← reset counters between demo runs
```

---

## demo.sh Logic

```
1. Resolve USB_DIR from BASH_SOURCE[0]
2. Check Docker installed, Docker Compose v2, docker info (daemon running)
3. Check COMPOSE_FILE exists (guard against partial USB copy)
4. Check if app image exists in local Docker
   → if not: docker load -i images/ritapi-advanced.tar (loads both app + redis)
   → if yes: skip load
5. docker compose -f docker/demo.usb.yml up -d
6. Wait for app healthcheck (poll /healthz)
7. Print dashboard URL + credentials
8. Run scripts/demo_attack.sh automatically
9. EXIT trap prints: "To stop: bash stop.sh"
```

---

## stop.sh Logic

```
Resolve USB_DIR, run:
  docker compose -f docker/demo.usb.yml --project-directory "$USB_DIR" down
```

---

## docker/demo.usb.yml

Identical to `docker/demo.yml` except:
- `app` service uses `image: ritapi-advanced-app:demo` instead of `build:`
- `redis` service uses `image: redis:7-alpine` (same — already an image reference)
- `env_file` path: `../.env.demo` (relative to `docker/`, resolves to USB root)

---

## Build Script (build_usb.sh)

1. Validate source files exist
2. Build app image: `docker compose -f docker/demo.yml build`
3. Tag app image: `docker tag ritapi-advanced-app ritapi-advanced-app:demo`
4. Save both images: `docker save ritapi-advanced-app:demo redis:7-alpine -o images/ritapi-advanced.tar`
5. Stage USB layout: demo.sh, stop.sh, README.txt, .env.demo, docker/demo.usb.yml, scripts/
6. Print copy instructions

---

## Constraints

- Target: Windows WSL2 or native Linux with Docker installed
- Offline: no image pulls during demo
- Manual launch: sales person runs `bash demo.sh` from USB mount
- Not handed directly to clients
- Port 8001 must be free on localhost

---

## Out of Scope

- Autorun / autoplay
- macOS support
- Client-facing handoff packaging
- Grafana / Prometheus stack (demo.yml doesn't include them)
