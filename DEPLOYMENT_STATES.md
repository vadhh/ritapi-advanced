# RitAPI Advanced — Deployment States

RitAPI follows a 5-state deployment lifecycle. Each state has entry criteria,
actions, and exit criteria. Transitions are manual (operator-driven).

```
INSTALL → SETUP → MONITOR → ENFORCE → ROLLBACK
                    ↑                      │
                    └──────────────────────┘
```

---

## 1. INSTALL

**Purpose:** Deploy binaries, configs, and dependencies onto the target host.

| Item | Detail |
|------|--------|
| Entry criteria | Host provisioned, network access confirmed |
| Actions | Install .deb / Docker image / Helm chart; create `ritapi` user; place config in `/etc/ritapi-advanced/env` |
| Validation | `scripts/validate_install.sh` passes all checks |
| Exit criteria | Service starts, `/healthz` returns 200 |

## 2. SETUP

**Purpose:** Configure routing, policies, TLS, Redis, and integrations.

| Item | Detail |
|------|--------|
| Entry criteria | INSTALL complete |
| Actions | Deploy `routing.yml` and policy files to `/etc/ritapi/`; generate TLS certs (`scripts/gen_cert.sh`); configure Redis (standalone or Sentinel); set env vars in `/etc/ritapi-advanced/env`; configure Nginx (`nginx.conf`) |
| Validation | `curl -k https://localhost/healthz` returns 200; Redis `PING` succeeds; Nginx config passes `nginx -t` |
| Exit criteria | All subsystems reachable, policies loaded without errors in logs |

## 3. MONITOR

**Purpose:** Run in observation mode — all detections log but do not block.

| Item | Detail |
|------|--------|
| Entry criteria | SETUP complete |
| Actions | Set all `decision_actions` in policy files to `monitor`; route production traffic through RitAPI; observe dashboards, logs, and Prometheus metrics for false positives |
| Duration | Minimum 48 hours recommended |
| Validation | No unexpected 4xx spikes; detection logs reviewed; false-positive rate < 1% |
| Exit criteria | Operator confirms detection accuracy is acceptable |

## 4. ENFORCE

**Purpose:** Full enforcement — detections trigger block/throttle actions.

| Item | Detail |
|------|--------|
| Entry criteria | MONITOR phase reviewed and approved |
| Actions | Update `decision_actions` in policy files to intended values (`block`, `throttle`); reload service (`systemctl reload ritapi-advanced`) |
| Validation | Blocked requests return 403/429 as expected; legitimate traffic unaffected; SLO targets met (see `SLO.md`) |
| Exit criteria | Steady-state operation confirmed over 24+ hours |

## 5. ROLLBACK

**Purpose:** Revert to a known-good state if issues are detected.

| Item | Detail |
|------|--------|
| Entry criteria | Critical issue detected (SLO breach, mass false positives, service degradation) |
| Actions | Option A: Set all `decision_actions` to `monitor` (soft rollback); Option B: `scripts/restore.sh <backup_dir>` (full rollback); Option C: `systemctl stop ritapi-advanced` and bypass in Nginx (emergency) |
| Validation | Legitimate traffic restored; incident documented in runbook |
| Exit criteria | Root cause identified; return to MONITOR or SETUP state |

---

## State Transition Commands

```bash
# INSTALL → SETUP
sudo dpkg -i ritapi-advanced_*.deb
sudo ./scripts/validate_install.sh

# SETUP → MONITOR
# Edit policy files: set all decision_actions to "monitor"
sudo systemctl reload ritapi-advanced

# MONITOR → ENFORCE
# Edit policy files: set decision_actions to final values
sudo systemctl reload ritapi-advanced

# Any → ROLLBACK (soft)
# Edit policy files: set all decision_actions to "monitor"
sudo systemctl reload ritapi-advanced

# Any → ROLLBACK (full)
sudo systemctl stop ritapi-advanced
sudo ./scripts/restore.sh /var/backups/ritapi/<timestamp>
```
