"""app/config.py — Central application configuration."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    SERPAPI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    GEMINI_API_KEY: str = ""
    SAFE_BROWSING_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""

    CLAUDE_MODEL: str = "claude-sonnet-5-5"
    GEMINI_MODEL: str = "gemini-3.8-flash"

    SERPAPI_TIMEOUT: float = 45.0
    CACHE_TTL_SECONDS: int = 3600
    RATE_LIMIT_PER_MIN: int = 30   # per IP on POST /api/*, 0 disables
    RATE_LIMIT_PER_MINUTE: int = 30
    DAILY_SEARCH_BUDGET: int = 50
    DATA_DIR: str = "data"
    STATS_FILE: str = "stats.json"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()