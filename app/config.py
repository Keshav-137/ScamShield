"""app/config.py — Central application configuration."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    SERPAPI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    SAFE_BROWSING_API_KEY: str = ""
    CLAUDE_MODEL: str = "claude-sonnet-5-5"

    SERPAPI_TIMEOUT: float = 45.0
    CACHE_TTL_SECONDS: int = 3600

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()