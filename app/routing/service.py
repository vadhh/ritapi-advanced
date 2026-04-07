"""
Route resolver service.

Loads route definitions from a YAML config and resolves incoming requests
to a named route based on path prefix + HTTP method matching.
"""
import logging
import os
from dataclasses import dataclass

import yaml

logger = logging.getLogger(__name__)

_ROUTING_CONFIG_PATH = os.getenv(
    "ROUTING_CONFIG_PATH",
    os.path.join(os.path.dirname(__file__), "../../configs/routing.yml"),
)


@dataclass
class Route:
    name: str
    path_prefix: str
    methods: list[str]
    upstream: str
    policy: str | None = None


_routes: list[Route] = []
_loaded: bool = False
# Memoised (path, method) → Route | None.  Cleared on reload_routes().
_route_cache: dict[tuple[str, str], "Route | None"] = {}


def _load_routes() -> None:
    global _routes, _loaded
    config_path = os.path.normpath(_ROUTING_CONFIG_PATH)
    try:
        with open(config_path) as f:
            data = yaml.safe_load(f)
        _routes = []
        for entry in data.get("routes", []):
            _routes.append(
                Route(
                    name=entry["name"],
                    path_prefix=entry["path_prefix"],
                    methods=[m.upper() for m in entry.get("methods", [])],
                    upstream=entry.get("upstream", "http://127.0.0.1:8001"),
                    policy=entry.get("policy"),
                )
            )
        # Sort by prefix length descending so longer (more specific) prefixes match first
        _routes.sort(key=lambda r: len(r.path_prefix), reverse=True)
        _loaded = True
        logger.info("Loaded %d routes from %s", len(_routes), config_path)
    except FileNotFoundError:
        logger.warning("Routing config not found at %s — using empty route table", config_path)
        _routes = []
        _loaded = True
    except Exception:
        logger.exception("Failed to load routing config from %s", config_path)
        _routes = []
        _loaded = True


def resolve_route(path: str, method: str) -> "Route | None":
    """
    Resolve a request path + method to a Route.

    Returns the first matching route (longest prefix wins) or None.
    Result is memoised per (path, method) pair; cache is cleared on reload_routes().
    """
    if not _loaded:
        _load_routes()

    method = method.upper()
    key = (path, method)
    if key in _route_cache:
        return _route_cache[key]

    result = None
    for route in _routes:
        if path.startswith(route.path_prefix) and method in route.methods:
            result = route
            break
    _route_cache[key] = result
    return result


def reload_routes() -> None:
    """Force reload of routing config (e.g. on SIGHUP)."""
    global _loaded
    _loaded = False
    _route_cache.clear()
    _load_routes()


def get_all_routes() -> list[Route]:
    """Return all loaded routes."""
    if not _loaded:
        _load_routes()
    return list(_routes)
