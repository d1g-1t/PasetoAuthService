from functools import lru_cache
from typing import Any

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    APP_NAME: str = "PasetoAuthService"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    DATABASE_URL: str
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_TIMEOUT: int = 30

    REDIS_URL: str = "redis://localhost:6379/0"

    PASETO_PRIVATE_KEY_PASERK: SecretStr
    PASETO_PUBLIC_KEY_PASERK: str
    PASETO_LOCAL_KEY_PASERK: SecretStr
    PASETO_PREVIOUS_LOCAL_KEYS_PASERK: str = ""

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    CORS_ORIGINS: list[str] = []

    LOGIN_RATE_LIMIT_ATTEMPTS: int = 10
    LOGIN_RATE_LIMIT_WINDOW_SECONDS: int = 900
    ACCOUNT_LOCKOUT_AFTER_FAILURES: int = 5
    ACCOUNT_LOCKOUT_DURATION_SECONDS: int = 900

    @field_validator("DATABASE_URL")
    @classmethod
    def ensure_async_driver(cls, v: Any) -> str:
        url = str(v)
        if url.startswith("postgresql://"):
            return url.replace("postgresql://", "postgresql+asyncpg://", 1)
        return url


@lru_cache
def get_settings() -> Settings:
    return Settings()
