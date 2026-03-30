"""
RitAPI Advanced — API & IP Protection System
Entry point for the FastAPI application.
"""
import os

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.middlewares.auth import AuthMiddleware
from app.middlewares.bot_detection import BotDetectionMiddleware
from app.middlewares.decision_engine import DecisionEngineMiddleware
from app.middlewares.exfiltration_detection import ExfiltrationDetectionMiddleware
from app.middlewares.injection_detection import InjectionDetectionMiddleware
from app.middlewares.rate_limit import RateLimitMiddleware
from app.middlewares.schema_enforcement import SchemaEnforcementMiddleware
from app.web.admin import router as admin_router
from app.web.dashboard import router as dashboard_router

app = FastAPI(title="RitAPI Advanced", version="0.1.0")

# Middleware stack — last add_middleware() runs first on incoming requests.
# Request order:  RateLimit → Auth → Schema → Bot → Injection → Exfil → Engine → route
# Response order: reversed.
app.add_middleware(DecisionEngineMiddleware)        # innermost: block gate + policy
app.add_middleware(ExfiltrationDetectionMiddleware)
app.add_middleware(InjectionDetectionMiddleware)
app.add_middleware(BotDetectionMiddleware)
app.add_middleware(SchemaEnforcementMiddleware)     # after auth, validates body per policy
app.add_middleware(AuthMiddleware)                  # after rate limit, before WAF
app.add_middleware(RateLimitMiddleware)             # outermost: catches floods before auth

# Routes
app.include_router(dashboard_router)
app.include_router(admin_router)


@app.get("/healthz", tags=["Health"])
def health():
    return {"status": "ok"}


@app.get("/metrics", tags=["Observability"], include_in_schema=False)
def metrics():
    """Prometheus metrics scrape endpoint."""
    from app.utils.metrics import active_bot_risk_ips, active_rate_limit_keys
    from app.utils.redis_client import RedisClientSingleton

    # Update gauges from Redis on every scrape
    redis = RedisClientSingleton.get_client()
    if redis:
        try:
            active_rate_limit_keys.set(len(redis.keys("ritapi:rate:ip:*")))
            active_bot_risk_ips.set(len(redis.keys("bot:risk:*")))
        except Exception:  # noqa: S110 — Redis gauge update is best-effort; failure is non-critical
            pass

    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


def main() -> None:
    """Entry point for the ``ritapi`` CLI command."""
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    log_level = os.getenv("LOG_LEVEL", "info")
    uvicorn.run("app.main:app", host=host, port=port, log_level=log_level)
