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

    def get_action(self, detection_type: str) -> str:
        """Return the action for a detection type, defaulting to 'block'."""
        key = f"on_{detection_type}"
        action = getattr(self, key, "block")
        return action if action in VALID_ACTIONS else "block"


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

            auth_data = data.get("auth", {})
            rate_data = data.get("rate_limit", {})
            schema_data = data.get("schema_enforcement", {})
            actions_data = data.get("decision_actions", {})

            policy = Policy(
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
                ),
            )
            _policies[name] = policy
            logger.info("Loaded policy '%s' from %s", name, filepath)
        except Exception:
            logger.exception("Failed to load policy from %s", filepath)

    _loaded = True
    logger.info("Loaded %d policies from %s", len(_policies), policies_dir)


def get_policy(name: str | None) -> Policy:
    """
    Return a policy by name. Returns DEFAULT_POLICY if name is None or not found.
    """
    if not _loaded:
        _load_policies()

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
