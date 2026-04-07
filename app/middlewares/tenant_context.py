"""
Tenant Context Middleware.

Runs after RequestIDMiddleware and before HardGateMiddleware.
Reads the X-Target-ID request header and attaches the sanitised value to
request.state.claimed_tenant_id so downstream middlewares know what tenant
the client *claims* to belong to.

If the header is absent, blank, or contains characters outside [a-zA-Z0-9_-]
the claim defaults to "default", which preserves identical behaviour for
single-tenant deployments and prevents Redis key injection via the header.

claimed_tenant_id is UNVERIFIED — it reflects what the client stated, not what
was proven.  AuthMiddleware compares this value against the tenant embedded in
the credential and, on match, writes the verified value to
request.state.tenant_id.  Pre-auth middlewares (HardGate, RateLimit) use
claimed_tenant_id for key namespacing; post-auth middlewares use tenant_id.
"""
import re

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

# Only alphanumeric, underscore, and hyphen — max 64 chars.
# Prevents colons or wildcards from being injected into Redis key names.
_TENANT_ID_RE = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')


class TenantContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        raw = request.headers.get("X-Target-ID", "").strip()
        if raw and _TENANT_ID_RE.match(raw):
            request.state.claimed_tenant_id = raw
        else:
            request.state.claimed_tenant_id = "default"
        return await call_next(request)
