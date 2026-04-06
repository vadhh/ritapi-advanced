"""
Tenant Context Middleware.

Runs after RequestIDMiddleware and before HardGateMiddleware.
Reads the X-Target-ID request header and attaches the resolved tenant_id to
request.state so all downstream middlewares can namespace their Redis keys and
policy lookups per tenant.

If the header is absent, blank, or contains characters outside [a-zA-Z0-9_-]
the tenant defaults to "default", which preserves identical behaviour for
single-tenant deployments and prevents Redis key injection via the header.

The tenant_id accepted here is unverified — it reflects what the client
*claimed*, not what was *proven*. AuthMiddleware is responsible for rejecting
requests where the credential's embedded tenant does not match this value.
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
            request.state.tenant_id = raw
        else:
            request.state.tenant_id = "default"
        return await call_next(request)
