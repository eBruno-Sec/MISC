from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://olympus:olympus_secret@localhost:5432/olympus"
    redis_url: str = "redis://localhost:6379"
    anthropic_api_key: str = ""
    secret_key: str = "dev-secret"
    reports_dir: str = "/app/reports"
    wordlists_dir: str = "/app/wordlists"

    class Config:
        env_file = ".env"


settings = Settings()
