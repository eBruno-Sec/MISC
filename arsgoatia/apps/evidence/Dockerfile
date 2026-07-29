FROM python:3.12-slim AS base

WORKDIR /app

RUN pip install --no-cache-dir \
    "fastapi>=0.115" \
    "uvicorn[standard]>=0.30" \
    "pydantic>=2.6"

COPY packages/ packages/
COPY apps/evidence/ apps/evidence/

ENV PYTHONPATH=/app
EXPOSE 8001

RUN useradd --create-home appuser
USER appuser

HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8001/healthz')"

CMD ["uvicorn", "apps.evidence:app", "--host", "0.0.0.0", "--port", "8001"]
