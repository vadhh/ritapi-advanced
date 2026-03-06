"""
Test configuration and shared fixtures.

Uses FastAPI's TestClient (synchronous httpx wrapper).
Redis-dependent tests are skipped automatically if Redis is unavailable.
"""
import os

import pytest

# Set required env vars before any app import
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-unit-tests-only")
os.environ.setdefault("JWT_ALGORITHM", "HS256")
os.environ.setdefault("JWT_EXPIRE_MINUTES", "60")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")  # DB 15 = test DB
os.environ.setdefault("LOG_PATH", "/tmp/ritapi_test.jsonl")
os.environ.setdefault("ADMIN_SECRET", "test-admin-secret")
os.environ.setdefault("BOT_DETECTION_BYPASS_IPS", "127.0.0.1,::1,testclient")
# Set rate limit well below exfiltration bulk_access threshold (50) so rate limit
# fires first in tests and bulk_access doesn't interfere.
os.environ.setdefault("RATE_LIMIT_REQUESTS", "20")
os.environ.setdefault("RATE_LIMIT_WINDOW", "60")
# YARA rules directory — absolute path resolved from repo root
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("YARA_RULES_DIR", os.path.join(_REPO_ROOT, "rules"))

from fastapi.testclient import TestClient

from app.auth.jwt_handler import create_access_token
from app.main import app
from app.utils.redis_client import RedisClientSingleton


@pytest.fixture(scope="session")
def client():
    """Session-scoped TestClient. App is initialised once per test session."""
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture(scope="session")
def redis():
    """Session-scoped Redis client. Skips if unavailable."""
    r = RedisClientSingleton.get_client()
    if r is None:
        pytest.skip("Redis unavailable")
    return r


@pytest.fixture(autouse=True)
def flush_test_redis(redis):
    """Flush test Redis DB before each test to prevent state leakage."""
    try:
        redis.flushdb()
    except Exception:
        pass
    yield
    try:
        redis.flushdb()
    except Exception:
        pass


@pytest.fixture(scope="session")
def viewer_token():
    return create_access_token("test-viewer", "VIEWER")


@pytest.fixture(scope="session")
def admin_token():
    return create_access_token("test-admin", "ADMIN")


@pytest.fixture(scope="session")
def super_admin_token():
    return create_access_token("test-super-admin", "SUPER_ADMIN")


@pytest.fixture(scope="session")
def auth_headers(viewer_token):
    return {"Authorization": f"Bearer {viewer_token}",
            "User-Agent": "pytest-test-client/1.0"}


@pytest.fixture(scope="session")
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}",
            "User-Agent": "pytest-test-client/1.0"}


@pytest.fixture(scope="session")
def super_admin_headers(super_admin_token):
    return {"Authorization": f"Bearer {super_admin_token}",
            "User-Agent": "pytest-test-client/1.0"}


@pytest.fixture(scope="session")
def admin_secret_headers():
    # Read the actual env var so this fixture matches _ADMIN_SECRET in admin.py
    # regardless of whether the value came from conftest setdefault or CI env.
    secret = os.environ.get("ADMIN_SECRET", "test-admin-secret")
    return {
        "X-Admin-Secret": secret,
        "User-Agent": "pytest-test-client/1.0",
        "Content-Type": "application/json",
    }
