# Dockerfile — RitAPI Advanced
#
# Multi-stage build:
#   builder  — installs all dependencies including build tools for yara-python
#   runtime  — lean image, non-root user, no dev/build tools
#
# Build:
#   docker build -t ritapi-advanced:latest .
#
# Run (standalone, Redis must be accessible via REDIS_URL):
#   docker run --env-file .env -p 8001:8001 ritapi-advanced:latest

# ---------------------------------------------------------------------------
# Stage 1: builder — install Python deps (yara-python needs gcc + yara headers)
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        g++ \
        make \
        automake \
        libyara-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY requirements.txt .
RUN pip install --upgrade pip \
 && pip install --prefix=/install --no-warn-script-location -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2: runtime — minimal image
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

# Runtime dependency for yara-python shared library
RUN apt-get update && apt-get install -y --no-install-recommends \
        libyara10 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Non-root user
RUN useradd --uid 1000 --no-create-home --shell /usr/sbin/nologin ritapi
USER ritapi

WORKDIR /app

# Copy application source
COPY --chown=ritapi:ritapi app/ ./app/
COPY --chown=ritapi:ritapi rules/ ./rules/

# Writable log directory (mounted as volume in production)
VOLUME ["/var/log/ritapi"]

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LOG_PATH=/var/log/ritapi/ritapi_advanced.jsonl \
    YARA_RULES_DIR=/app/rules

EXPOSE 8001

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8001/healthz')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001", \
     "--workers", "2", "--log-level", "warning"]
