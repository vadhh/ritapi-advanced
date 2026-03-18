"""
Pydantic schemas for request payload validation.

Pattern
-------
1. All request bodies extend `BasePayload`.
2. Route functions declare the schema as a parameter:

    @app.post("/api/endpoint")
    async def handler(body: MyRequestSchema, _ct=Depends(require_json_content_type)):
        ...

3. `require_json_content_type` is a reusable dependency that rejects non-JSON
   Content-Type before Pydantic even runs.

Adding a new endpoint
---------------------
Define a new class that extends BasePayload (or BaseRequest for objects
that carry an explicit `metadata` block).  Pydantic handles required/optional
fields, type coercion, and validation error responses (422) automatically.

Body size (≤ 2 MB) and injection scanning are enforced upstream by
InjectionDetectionMiddleware — no need to repeat here.
"""
import unicodedata
from typing import Any

from fastapi import HTTPException, Request, status
from pydantic import BaseModel, field_validator

# ---------------------------------------------------------------------------
# Shared dependency — Content-Type guard
# ---------------------------------------------------------------------------

async def require_json_content_type(request: Request) -> None:
    """
    FastAPI dependency that rejects requests whose Content-Type is not
    application/json.  Attach to any route that expects a JSON body.

    Usage:
        @app.post("/api/data", dependencies=[Depends(require_json_content_type)])
    """
    if request.method in ("POST", "PUT", "PATCH"):
        ct = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if ct != "application/json":
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail=f"Unsupported Content-Type '{ct}'. Expected application/json.",
            )


# ---------------------------------------------------------------------------
# Base models
# ---------------------------------------------------------------------------

class BasePayload(BaseModel):
    """
    Root base for all request schemas.

    Applies Unicode NFC normalisation to every string field so that
    the injection middleware and application logic see a consistent form.
    """

    model_config = {"str_strip_whitespace": True}

    @field_validator("*", mode="before")
    @classmethod
    def normalise_strings(cls, v: Any) -> Any:
        if isinstance(v, str):
            return unicodedata.normalize("NFC", v)
        return v


class BaseRequest(BasePayload):
    """Base for requests that carry optional caller metadata."""
    metadata: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Example endpoint schemas
# (extend as endpoints are added to app/main.py)
# ---------------------------------------------------------------------------

class HealthPayload(BasePayload):
    """Body schema for POST /healthz (if ever needed)."""
    pass


class GenericDataPayload(BaseRequest):
    """
    Catch-all schema for endpoints that accept arbitrary JSON objects.
    Use a specific schema whenever the expected shape is known.
    """
    data: dict[str, Any]


class PaymentPayload(BasePayload):
    """Schema for payment-related endpoints (enforced per-route via policy)."""
    amount: float
    currency: str
    recipient: str
    reference: str | None = None
