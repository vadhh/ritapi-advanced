# Proof Artifact: Unified Detections + Decision Engine Consumption

Date: 2026-04-01
Scope requested:
1. `request.state.detections` populated in all detection middlewares
2. unified detection schema
3. `DecisionEngineMiddleware` reading detections

## A) Unified detection schema exists

Evidence:
- `app/middlewares/detection_schema.py:38` defines `append_detection(...)`
- `app/middlewares/detection_schema.py:62` defines `normalize_detection(...)`
- `app/middlewares/detection_schema.py:34` ensures `request.state.detections` container

Unified schema fields produced by `append_detection(...)`:
- `type`
- `score` (normalized 0..1)
- `severity`
- `reason`
- `status_code`
- `source`
- `metadata`

## B) All detection middlewares populate `request.state.detections`

### RateLimit middleware
Evidence:
- `app/middlewares/rate_limit.py:52` initializes `request.state.detections = []`
- `app/middlewares/rate_limit.py:130` appends via `append_detection(...)`

### InjectionDetection middleware
Evidence:
- `app/middlewares/injection_detection.py:215` initializes `request.state.detections = []`
- `app/middlewares/injection_detection.py:227` append on UA signal
- `app/middlewares/injection_detection.py:243` append on URL signal
- `app/middlewares/injection_detection.py:276` append on body text signal
- `app/middlewares/injection_detection.py:295` append on recursive JSON signal
- `app/middlewares/injection_detection.py:317` append on YARA signal

### BotDetection middleware
Evidence:
- `app/middlewares/bot_detection.py:234` append on pre-block risk threshold
- `app/middlewares/bot_detection.py:270` append on post-response detection hits

### ExfiltrationDetection middleware
Evidence:
- `app/middlewares/exfiltration_detection.py:116` append on pre-request counter block
- `app/middlewares/exfiltration_detection.py:206` append on post-response exfil alerts

## C) Decision Engine reads and normalizes detections

Evidence:
- `app/middlewares/decision_engine.py:59` reads raw detections from request state
- `app/middlewares/decision_engine.py:61` normalizes each detection via `normalize_detection(...)`
- `app/middlewares/decision_engine.py:66` logs arrival:
  - `"DecisionEngine: received detections for %s %s from %s: %s"`

## D) Verification test run (proof of behavior)

Command executed:
- `pytest -q tests/test_decision_engine.py tests/test_rate_limit.py tests/test_waf.py tests/test_bot_detection.py tests/test_exfiltration.py`

Result:
- `83 passed, 1 warning in 2.71s`

Captured output excerpt:

```text
........................................................................ [ 86%]
...........                                                              [100%]
83 passed, 1 warning in 2.71s
```

## E) Live Runtime Proof (Terminal + Response)

Test route used:
- `GET /dashboard/demo`
- Handler contains a backend marker print:
  - `BACKEND_EXECUTED: /dashboard/demo handler ran`

Malicious request sent:
- `GET /dashboard/demo?id=1' OR '1'='1`

Terminal log excerpt:

```text
TEST_ROUTE: GET /dashboard/demo?id=1' OR '1'='1
WARNING app.middlewares.injection_detection: Injection blocked [cmdi] from testclient on /dashboard/demo ...
INFO app.middlewares.decision_engine: DecisionEngine: received detections for GET /dashboard/demo from testclient: [{'type': 'injection', 'score': 0.95, ...}]
WARNING app.middlewares.decision_engine: DecisionEngine: blocking GET /dashboard/demo from testclient ...
INFO httpx: HTTP Request: GET http://testserver/dashboard/demo?id=1'%20OR%20'1'='1 "HTTP/1.1 403 Forbidden"
RESPONSE_STATUS: 403
RESPONSE_BODY: {"error":"Forbidden","detail":"cmdi: http://testserver/dashboard/demo?id=1'%20OR%20'1'='1"}
```

Block-before-backend proof:
- The backend marker line `BACKEND_EXECUTED: /dashboard/demo handler ran` does not appear in terminal output.
- DecisionEngine block log appears before the HTTP 403 response line.

## F) Fix Applied (False Positive)

Issue observed:
- Query keys like `id` could trigger CMDi false positives.

Code fix:
- Tightened CMDi command-name regex to require command-context tokens.
- File: `app/middlewares/injection_detection.py`

Regression test added:
- `tests/test_waf.py`:
  - `test_clean_query_id_not_blocked`

Validation result:
- `pytest -q tests/test_waf.py tests/test_decision_engine.py`
- `25 passed, 1 warning`

Corrected runtime demo transcript:

```text
--- BENIGN REQUEST ---
BACKEND_EXECUTED: /dashboard/demo handler ran
BENIGN_STATUS: 200
BENIGN_BODY: {"ok":true,"message":"backend reached"}

--- MALICIOUS REQUEST ---
WARNING app.middlewares.injection_detection: Injection blocked [cmdi] ... q=$(whoami)
INFO app.middlewares.decision_engine: DecisionEngine: received detections ...
WARNING app.middlewares.decision_engine: DecisionEngine: blocking GET /dashboard/demo ...
MALICIOUS_STATUS: 403
MALICIOUS_BODY: {"error":"Forbidden","detail":"cmdi: http://testserver/dashboard/demo?q=$(whoami)"}
```
