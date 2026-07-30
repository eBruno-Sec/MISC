# ArsGoatia API — multi-stage build
# Context: repository root (../../ from deploy/compose)

# ---------------------------------------------------------------------------
# Stage 1: dependency install
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY pyproject.toml ./
RUN pip install --no-cache-dir --prefix=/install .

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN groupadd --gid 1000 arsgoatia \
    && useradd --uid 1000 --gid arsgoatia --shell /bin/false arsgoatia

WORKDIR /app

# Installed packages from builder
COPY --from=builder /install /usr/local

# Application sources — only what the API needs
COPY apps/api/ apps/api/
COPY packages/ packages/
COPY packs/ packs/
COPY services/ services/
COPY migrations/ migrations/
COPY alembic.ini ./

# Ensure __init__.py files exist at top-level package roots
COPY apps/__init__.py apps/__init__.py

RUN chown -R arsgoatia:arsgoatia /app
USER arsgoatia

ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
