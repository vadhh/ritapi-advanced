"""
RitAPI Advanced — API & IP Protection System
Entry point for the FastAPI application.
"""
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from app.middlewares.rate_limit import RateLimitMiddleware
from app.middlewares.bot_detection import BotDetectionMiddleware
from app.middlewares.injection_detection import InjectionDetectionMiddleware
from app.middlewares.exfiltration_detection import ExfiltrationDetectionMiddleware
from app.middlewares.auth import AuthMiddleware
from app.middlewares.decision_engine import DecisionEngineMiddleware
from app.web.dashboard import router as dashboard_router
from app.web.admin import router as admin_router

app = FastAPI(title="RitAPI Advanced", version="0.1.0")

# Middleware stack — last add_middleware() runs first on incoming requests.
# Request order: RateLimit → Auth → BotDetection → InjectionDetection → Exfiltration → DecisionEngine → route
# Response order: reversed.
app.add_middleware(DecisionEngineMiddleware)        # innermost: unified block gate
app.add_middleware(ExfiltrationDetectionMiddleware)
app.add_middleware(InjectionDetectionMiddleware)
app.add_middleware(BotDetectionMiddleware)
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
    from app.utils.metrics import active_rate_limit_keys, active_bot_risk_ips
    from app.utils.redis_client import RedisClientSingleton

    # Update gauges from Redis on every scrape
    redis = RedisClientSingleton.get_client()
    if redis:
        try:
            active_rate_limit_keys.set(len(redis.keys("ritapi:rate:ip:*")))
            active_bot_risk_ips.set(len(redis.keys("bot:risk:*")))
        except Exception:
            pass

    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
