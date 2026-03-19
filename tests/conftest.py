import uuid
from unittest.mock import AsyncMock

import pytest

from paseto_forge.config import Settings
from paseto_forge.services.paseto_service import PasetoService


@pytest.fixture(scope="session")
def paseto_keys() -> dict[str, str]:
    return PasetoService.generate_keys()


@pytest.fixture
def settings(paseto_keys: dict[str, str]) -> Settings:
    return Settings(
        DATABASE_URL="postgresql+asyncpg://test:test@localhost:5499/paseto_forge",
        REDIS_URL="redis://localhost:6399/0",
        PASETO_PRIVATE_KEY_PASERK=paseto_keys["PASETO_PRIVATE_KEY_PASERK"],
        PASETO_PUBLIC_KEY_PASERK=paseto_keys["PASETO_PUBLIC_KEY_PASERK"],
        PASETO_LOCAL_KEY_PASERK=paseto_keys["PASETO_LOCAL_KEY_PASERK"],
    )


@pytest.fixture
def paseto_service(settings: Settings) -> PasetoService:
    return PasetoService(settings)


@pytest.fixture
def mock_redis() -> AsyncMock:
    redis = AsyncMock()
    redis.exists.return_value = 0
    redis.get.return_value = None
    redis.incr.return_value = 1
    redis.setex.return_value = True
    redis.expire.return_value = True
    redis.delete.return_value = 1
    return redis


@pytest.fixture
def sample_user_id() -> uuid.UUID:
    return uuid.uuid4()
