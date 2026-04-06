"""
Policy loader service.

Loads per-route policy YAML files and provides policy config lookup by name.

Each policy file defines:
  - auth: which auth methods are required (jwt, api_key)
  - rate_limit: per-route rate limit settings
  - schema_enforcement: whether JSON schema validation is enforced and which schema
  - decision_actions: what action to take for each detection type
    (allow / monitor / throttle / block)
"""
import logging
import os
from dataclasses import dataclass, field

import yaml

logger = logging.getLogger(__name__)

_POLICIES_DIR = os.getenv(
    "POLICIES_DIR",
    os.path.join(os.path.dirname(__file__), "../../configs/policies"),
)

# Valid decision actions
VALID_ACTIONS = frozenset({"allow", "monitor", "throttle", "block"})


@dataclass
class AuthPolicy:
    jwt: bool = True
    api_key: bool = True


@dataclass
class RateLimitPolicy:
    requests: int = 100
    window_seconds: int = 60


@dataclass
class SchemaPolicy:
    enabled: bool = False
    schema: str | None = None


@dataclass
class DecisionActions:
    on_auth_failure: str = "block"
    on_rate_limit: str = "block"
    on_injection: str = "block"
    on_bot_detection: str = "monitor"   # post-response scoring is informational
    on_bot_block: str = "block"         # pre-request block when risk >= threshold
    on_exfiltration: str = "monitor"
    on_exfiltration_block: str = "block"  # pre-request block when counter exceeded
    on_schema_violation: str = "block"  # request body fails schema validation

    def get_action(self, detection_type: str) -> str:
        """Return the action for a detection type.

        Unknown detection types default to 'monitor' rather than 'block'.
        Why: defaulting unknown types to 'block' causes production outages
        when a new detection type is introduced or a misconfiguration creates
        a type string that doesn't match any on_* field — every request would
        be blocked.  'monitor' is the safe fallback: it logs without blocking.
        """
        key = f"on_{detection_type}"
        action = getattr(self, key, "monitor")
        return action if action in VALID_ACTIONS else "monitor"


@dataclass
class Policy:
    name: str
    auth: AuthPolicy = field(default_factory=AuthPolicy)
    rate_limit: RateLimitPolicy = field(default_factory=RateLimitPolicy)
    schema_enforcement: SchemaPolicy = field(default_factory=SchemaPolicy)
    decision_actions: DecisionActions = field(default_factory=DecisionActions)


_policies: dict[str, Policy] = {}
_loaded: bool = False

# Default policy used when no policy is assigned to a route
DEFAULT_POLICY = Policy(
    name="default",
    auth=AuthPolicy(jwt=True, api_key=True),
    rate_limit=RateLimitPolicy(requests=100, window_seconds=60),
    schema_enforcement=SchemaPolicy(enabled=False),
    decision_actions=DecisionActions(),
)


def _parse_policy_data(name: str, data: dict) -> Policy:
    """Build a Policy dataclass from a parsed YAML dict."""
    auth_data = data.get("auth", {})
    rate_data = data.get("rate_limit", {})
    schema_data = data.get("schema_enforcement", {})
    actions_data = data.get("decision_actions", {})
    return Policy(
        name=name,
        auth=AuthPolicy(
            jwt=auth_data.get("jwt", True),
            api_key=auth_data.get("api_key", True),
        ),
        rate_limit=RateLimitPolicy(
            requests=rate_data.get("requests", 100),
            window_seconds=rate_data.get("window_seconds", 60),
        ),
        schema_enforcement=SchemaPolicy(
            enabled=schema_data.get("enabled", False),
            schema=schema_data.get("schema"),
        ),
        decision_actions=DecisionActions(
            on_auth_failure=actions_data.get("on_auth_failure", "block"),
            on_rate_limit=actions_data.get("on_rate_limit", "block"),
            on_injection=actions_data.get("on_injection", "block"),
            on_bot_detection=actions_data.get("on_bot_detection", "monitor"),
            on_bot_block=actions_data.get("on_bot_block", "block"),
            on_exfiltration=actions_data.get("on_exfiltration", "monitor"),
            on_exfiltration_block=actions_data.get("on_exfiltration_block", "block"),
            on_schema_violation=actions_data.get("on_schema_violation", "block"),
        ),
    )


def _load_policies() -> None:
    global _policies, _loaded
    policies_dir = os.path.normpath(_POLICIES_DIR)
    _policies = {}

    if not os.path.isdir(policies_dir):
        logger.warning("Policies directory not found at %s — using defaults", policies_dir)
        _loaded = True
        return

    for filename in os.listdir(policies_dir):
        if not filename.endswith((".yml", ".yaml")):
            continue
        filepath = os.path.join(policies_dir, filename)
        try:
            with open(filepath) as f:
                data = yaml.safe_load(f)
            if not data:
                continue
            name = filename.rsplit(".", 1)[0]
            policy = _parse_policy_data(name, data)
            _policies[name] = policy
            logger.info("Loaded policy '%s' from %s", name, filepath)
        except Exception:
            logger.exception("Failed to load policy from %s", filepath)

    _loaded = True
    logger.info("Loaded %d policies from %s", len(_policies), policies_dir)


def _load_tenant_policy(name: str, tenant_id: str) -> "Policy | None":
    """Load a tenant-specific policy file, returning None if not found.

    Looks for {_POLICIES_DIR}/tenants/{tenant_id}/{name}.yml (or .yaml).
    Falls back to None so the caller can use the global policy instead.
    Never raises.
    """
    policies_dir = os.path.normpath(_POLICIES_DIR)
    tenant_name = name if name else "default"
    for ext in (".yml", ".yaml"):
        filepath = os.path.join(policies_dir, "tenants", tenant_id, f"{tenant_name}{ext}")
        if not os.path.isfile(filepath):
            continue
        try:
            with open(filepath) as f:
                data = yaml.safe_load(f)
            if not data:
                return None
            policy = _parse_policy_data(tenant_name, data)
            logger.debug("Loaded tenant policy '%s/%s' from %s", tenant_id, tenant_name, filepath)
            return policy
        except Exception:
            logger.exception("Failed to load tenant policy from %s", filepath)
            return None
    return None


def get_policy(name: str | None, tenant_id: str = "default") -> "Policy":
    """Return a policy by name.

    Lookup order:
      1. Tenant-specific file at {POLICIES_DIR}/tenants/{tenant_id}/{name}.yml
         (only when tenant_id != "default")
      2. Global policy from the main policies directory
      3. DEFAULT_POLICY when nothing matches

    Returns DEFAULT_POLICY if name is None or not found.
    """
    if not _loaded:
        _load_policies()

    # 1. Try tenant-specific override first
    if tenant_id and tenant_id != "default":
        tenant_policy = _load_tenant_policy(name, tenant_id)
        if tenant_policy is not None:
            return tenant_policy

    # 2. Global policy
    if name is None:
        return DEFAULT_POLICY
    return _policies.get(name, DEFAULT_POLICY)


def reload_policies() -> None:
    """Force reload of all policies (e.g. on SIGHUP)."""
    global _loaded
    _loaded = False
    _load_policies()


def get_all_policies() -> dict[str, Policy]:
    """Return all loaded policies."""
    if not _loaded:
        _load_policies()
    return dict(_policies)
