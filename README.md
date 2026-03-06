# RitAPI Advanced — API & IP Protection System

Standalone FastAPI service providing layer-7 API protection.

## Features (PRD)
- Rate limiting (per-IP and per-API-key, Redis-backed)
- Payload validation (Pydantic schemas)
- Injection detection: XSS, SQLi, CMDi, path traversal, LDAP (regex + YARA)
- JWT and API key authentication with 5-level RBAC
- Bot detection: rapid-fire, endpoint scanning, suspicious UA, error-rate anomalies
- Data exfiltration detection
- Logs to `/var/log/ritapi_advanced.jsonl`
- Prometheus metrics export

## Implementation Status
All modules are scaffolded. See `# TODO` comments in each file.
WAF patterns to port from: `_archive/ritapi_v/ritapi/utils/waf.py`
Bot detection to port from: `_archive/ritapi_v/ritapi/utils/behaviour_detection.py`

## Run
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # edit as needed
uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
```
