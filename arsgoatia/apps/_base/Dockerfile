# Shared Python image for the API and Temporal workers.
# Build context is the arsgoatia/ root (see docker-compose.yml) so the shared
# packages/ install alongside the app entrypoints.
FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/packages:/app

# Copy the whole project (a .dockerignore keeps secrets/venvs/caches out) and
# install it editable so setuptools discovers the packages/ distributions.
COPY . /app
RUN pip install --upgrade pip && pip install -e .

EXPOSE 8000
# Default command is overridden per service in docker-compose.yml.
CMD ["python", "-c", "print('arsgoatia base image; override CMD per service')"]
