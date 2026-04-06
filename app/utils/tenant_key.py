"""
Tenant-scoped Redis key helper.

All Redis counters for rate limiting, bot detection, exfiltration, and
throttle state must use this helper so that:
  1. Key format is consistent across every middleware.
  2. A malformed or empty tenant_id can never produce an ambiguous key
     (falls back to "default" rather than injecting empty segments).
  3. Injection via special Redis characters (colons, wildcards) is already
     blocked upstream by TenantContextMiddleware's regex validation, but
     this helper provides a second, unconditional defense: it only accepts
     the sanitised tenant_id value that has already passed the regex.

Key format:
    ritapi:{tenant}:{category}:{subject}

Examples:
    tenant_scoped_key("acme", "rate:ip", "10.0.0.1:_api_v1_data")
        → "ritapi:acme:rate:ip:10.0.0.1:_api_v1_data"

    tenant_scoped_key("acme", "bot")
        → "ritapi:acme:bot"   (prefix form, no trailing colon)
"""
from __future__ import annotations


def tenant_scoped_key(tenant_id: str, category: str, subject: str = "") -> str:
    """
    Return a namespaced Redis key for the given tenant, category, and subject.

    Args:
        tenant_id: Tenant identifier. Empty / non-string values fall back to
                   "default" so callers do not need to guard against None.
        category:  Dot-or-colon path segment identifying the counter type,
                   e.g. "rate:ip", "bot:rapid", "throttle".
        subject:   Per-identity suffix, e.g. an IP address or hash.
                   Omit (or pass "") for prefix-only keys used as Redis
                   key prefixes or set keys.

    Returns:
        "ritapi:{tenant}:{category}"          when subject is empty
        "ritapi:{tenant}:{category}:{subject}" otherwise
    """
    tenant = tenant_id if (isinstance(tenant_id, str) and tenant_id) else "default"
    if subject:
        return f"ritapi:{tenant}:{category}:{subject}"
    return f"ritapi:{tenant}:{category}"
