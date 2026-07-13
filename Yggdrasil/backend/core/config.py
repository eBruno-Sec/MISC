from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://yggdrasil:yggdrasil_secret@localhost:5432/yggdrasil"
    redis_url: str = "redis://localhost:6379"
    anthropic_api_key: str = ""
    secret_key: str = "dev-secret"
    reports_dir: str = "/app/reports"
    wordlists_dir: str = "/app/wordlists"

    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()
