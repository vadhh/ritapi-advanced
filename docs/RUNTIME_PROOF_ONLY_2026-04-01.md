RUNTIME PROOF ARTIFACT
Date: 2026-04-01
Route marker configured: BACKEND EXECUTED
Route used: /dashboard/demo-proof
Detection path: exfiltration (bulk_access pre-request)

TERMINAL OUTPUT
WARNING app.middlewares.exfiltration_detection: Exfiltration pre-block [bulk_access] from testclient on /dashboard/demo-proof
INFO app.middlewares.decision_engine: DecisionEngine: received detections for GET /dashboard/demo-proof from testclient: [{'type': 'exfiltration_block', 'score': 0.9, 'severity': 'critical', 'reason': 'bulk_access (pre-request counter exceeded)', 'status_code': 403, 'source': 'exfiltration_detection', 'metadata': {'reason': 'bulk_access', 'phase': 'pre_request'}}]
WARNING app.middlewares.decision_engine: DecisionEngine: blocking GET /dashboard/demo-proof from testclient — bulk_access (pre-request counter exceeded)
INFO httpx: HTTP Request: GET http://testserver/dashboard/demo-proof "HTTP/1.1 403 Forbidden"
HTTP_STATUS: 403
HTTP_BODY: {"error":"Forbidden","detail":"bulk_access (pre-request counter exceeded)"}

BACKEND MARKER CHECK (runtime-output only)
BACKEND_EXECUTED_NOT_FOUND_IN_RUNTIME_OUTPUT
