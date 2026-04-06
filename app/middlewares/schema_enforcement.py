"""
Per-Route JSON Schema Enforcement Middleware.

When a route's policy has schema_enforcement.enabled = true, this middleware
validates the request body against the named Pydantic schema before the
request reaches the route handler.

Schema lookup:
  policy.schema_enforcement.schema → class name in app.schemas.payload_schema

Runs after auth (we need claims) and before the decision engine gate.
Only enforces on methods that carry a body (POST, PUT, PATCH).
"""
import importlib
import json
import logging

from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from starlette.middleware.base import BaseHTTPMiddleware

from app.middlewares.detection_schema import append_detection

logger = logging.getLogger(__name__)

# Methods that may carry a request body
_BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})

# Cache for resolved schema classes
_schema_cache: dict[str, type] = {}


def _resolve_schema(schema_name: str):
    """Resolve a schema class name from app.schemas.payload_schema."""
    if schema_name in _schema_cache:
        return _schema_cache[schema_name]

    try:
        module = importlib.import_module("app.schemas.payload_schema")
        cls = getattr(module, schema_name, None)
        if cls is not None:
            _schema_cache[schema_name] = cls
            return cls
        logger.error(
            "Schema class '%s' not found in app.schemas.payload_schema — "
            "schema enforcement DISABLED for this route. Fix the policy YAML. (R2-M-2)",
            schema_name,
        )
    except Exception:
        logger.exception("Failed to import schema module")
    return None


class SchemaEnforcementMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method not in _BODY_METHODS:
            return await call_next(request)

        policy = getattr(request.state, "policy", None)
        if policy is None or not policy.schema_enforcement.enabled:
            return await call_next(request)

        schema_name = policy.schema_enforcement.schema
        if not schema_name:
            return await call_next(request)

        schema_cls = _resolve_schema(schema_name)
        if schema_cls is None:
            return await call_next(request)

        # Read and validate body.
        # Explicitly use request.body() to populate Starlette's body cache so
        # downstream middlewares (InjectionDetection) can also call request.body()
        # without relying on implicit caching from request.json() (M-6).
        try:
            raw = await request.body()
            body = json.loads(raw)
        except Exception:
            append_detection(
                request,
                detection_type="schema_violation",
                score=0.8,
                reason="Invalid JSON body",
                status_code=400,
                source="schema_enforcement",
                metadata={"schema": schema_name, "error": "json_parse_error"},
            )
            return await call_next(request)

        try:
            schema_cls.model_validate(body)
        except ValidationError as e:
            errors = e.errors()
            append_detection(
                request,
                detection_type="schema_violation",
                score=0.8,
                reason=f"Schema validation failed: {len(errors)} error(s)",
                status_code=422,
                source="schema_enforcement",
                metadata={"schema": schema_name, "errors": errors},
            )
            return await call_next(request)

        return await call_next(request)
