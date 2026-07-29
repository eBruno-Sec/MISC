"""ArsGoatia runtime settings.

Centralises all environment-driven configuration behind a single
Pydantic settings model.  Every variable is prefixed ``ARSGOATIA_`` so
deployments can't accidentally collide with unrelated environment
variables (e.g. a bare ``DATABASE_URL`` set by a hosting platform).

Use :func:`get_settings` everywhere -- it returns a process-wide cached
singleton so settings are parsed from the environment exactly once.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = ["ArsGoatiaSettings", "get_settings"]


class ArsGoatiaSettings(BaseSettings):
    """Process-wide configuration, sourced from ``ARSGOATIA_*`` env vars."""

    model_config = SettingsConfigDict(env_prefix="ARSGOATIA_", extra="ignore")

    # -- Persistence ---------------------------------------------------
    database_url: str = "postgresql+asyncpg://arsgoatia:arsgoatia@localhost:5433/arsgoatia"

    # -- Temporal (workflow orchestration) ------------------------------
    temporal_address: str = "localhost:7233"
    temporal_namespace: str = "default"

    # -- MinIO (evidence object storage) --------------------------------
    minio_endpoint: str = "localhost:9100"
    minio_access_key: str = "arsgoatia"
    minio_secret_key: str = "arsgoatia-secret"
    minio_bucket: str = "arsgoatia-evidence"

    # -- Envelope signing ------------------------------------------------
    signing_key: str = "dev-signing-key-change-in-production"

    # -- API server ------------------------------------------------------
    api_port: int = 8000
    log_level: str = "INFO"

    # -- AI gateway --------------------------------------------------------
    ai_model: str = "gpt-4o-mini"
    ai_budget_usd: float = 25.0
    ai_redact_secrets: bool = True

    # -- CORS --------------------------------------------------------------
    cors_origins: list[str] = ["http://localhost:3100"]


@lru_cache(maxsize=1)
def get_settings() -> ArsGoatiaSettings:
    """Return the process-wide cached :class:`ArsGoatiaSettings` singleton.

    Cached with :func:`functools.lru_cache` so the environment is parsed
    exactly once per process. Tests that need to override the environment
    should call ``get_settings.cache_clear()`` after mutating ``os.environ``.
    """
    return ArsGoatiaSettings()
