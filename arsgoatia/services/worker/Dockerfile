# ArsGoatia Worker — Temporal activity/workflow worker
# Context: repository root (../../ from deploy/compose)

FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libpq-dev libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN groupadd --gid 1000 arsgoatia \
    && useradd --uid 1000 --gid arsgoatia --shell /bin/false arsgoatia

WORKDIR /app

COPY pyproject.toml ./
RUN pip install --no-cache-dir . \
    && apt-get purge -y --auto-remove gcc \
    && rm -rf /var/lib/apt/lists/*

# Application sources — only what the worker needs
COPY services/worker/ services/worker/
COPY packages/ packages/
COPY packs/ packs/

# Ensure __init__.py files exist at top-level package roots
COPY services/__init__.py services/__init__.py

RUN chown -R arsgoatia:arsgoatia /app
USER arsgoatia

ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

CMD ["python", "-m", "services.worker"]
