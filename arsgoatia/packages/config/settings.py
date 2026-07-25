"""Runtime configuration (pydantic-settings).

Ported from the Yggdrasil/olympus config pattern: a single Settings object read
from environment/.env, cached per process. Every service reads config here rather
than calling os.getenv directly.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    # App
    app_env: str = "development"
    app_name: str = "ArsGoatia"

    # Database
    database_url: str = "postgresql+psycopg://arsgoatia:arsgoatia@postgres:5432/arsgoatia"

    # Temporal
    temporal_address: str = "temporal:7233"
    temporal_namespace: str = "default"
    temporal_task_queue_control: str = "workflow-control"

    # Object storage (MinIO / S3)
    s3_endpoint_url: str = "http://minio:9000"
    s3_access_key_id: str = "minioadmin"
    s3_secret_access_key: str = "minioadmin"
    s3_bucket: str = "arsgoatia-evidence"
    s3_region: str = "us-east-1"

    # Eventing
    event_bus_driver: str = "postgres_outbox"

    # Auth / signing (SESSION_SECRET derives the dev HMAC envelope-signing key)
    auth_mode: str = "local"
    session_secret: str = "replace-me-dev-only"

    # Policy defaults
    default_policy_profile: str = "lab-safe"
    production_default_deny_mutation: bool = True
    require_authorization_record: bool = True
    require_explicit_scope: bool = True
    default_max_requests_per_module: int = 500
    default_max_rps: float = 2.0
    default_chain_depth: int = 8

    # Evidence
    evidence_require_hash: bool = True
    evidence_default_sensitivity: str = "confidential"
    evidence_enable_object_lock: bool = False
    evidence_max_artifact_bytes: int = 104_857_600

    # AI (subset; full AI config lives in the ai_gateway package)
    ai_provider: str = "openrouter"
    ai_api_key: str = ""
    ai_base_url: str = "https://openrouter.ai/api/v1"
    ai_model: str = ""
    ai_request_budget_usd: float = Field(default=1.0)
    ai_assessment_budget_usd: float = Field(default=5.0)
    ai_daily_budget_usd: float = Field(default=10.0)

    # Logging
    log_level: str = "INFO"

    @property
    def ai_enabled(self) -> bool:
        return bool(self.ai_api_key)


@lru_cache
def get_settings() -> Settings:
    return Settings()
