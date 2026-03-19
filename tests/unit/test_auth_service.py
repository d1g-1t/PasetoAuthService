import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from paseto_forge.exceptions import (
    AccountLockedError,
    AuthenticationError,
    RefreshTokenReuseError,
    UserAlreadyExistsError,
)
from paseto_forge.models.refresh_token import RefreshToken
from paseto_forge.models.user import User
from paseto_forge.services.auth_service import AuthService
from paseto_forge.services.paseto_service import PasetoService


@pytest.fixture
def user_repo() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def token_repo() -> AsyncMock:
    return AsyncMock()


@pytest.fixture
def auth_service(
    user_repo: AsyncMock,
    token_repo: AsyncMock,
    paseto_service: PasetoService,
    mock_redis: AsyncMock,
    settings,
) -> AuthService:
    return AuthService(user_repo, token_repo, paseto_service, mock_redis, settings)


def _make_user(
    email: str = "user@example.com",
    password_hash: str = "",
    is_active: bool = True,
) -> User:
    from argon2 import PasswordHasher

    ph = PasswordHasher()
    user = User(
        id=uuid.uuid4(),
        email=email,
        hashed_password=password_hash or ph.hash("Test1234!"),
        is_active=is_active,
        is_superuser=False,
        roles=["user"],
    )
    return user


class TestRegister:
    async def test_register_success(self, auth_service: AuthService, user_repo: AsyncMock):
        user_repo.get_by_email.return_value = None
        new_user = _make_user()
        user_repo.create.return_value = new_user

        result = await auth_service.register("user@example.com", "Test1234!")
        assert result == new_user
        user_repo.create.assert_called_once()

    async def test_register_duplicate_email(
        self, auth_service: AuthService, user_repo: AsyncMock
    ):
        user_repo.get_by_email.return_value = _make_user()

        with pytest.raises(UserAlreadyExistsError):
            await auth_service.register("user@example.com", "Test1234!")


class TestLogin:
    async def test_login_success(
        self, auth_service: AuthService, user_repo: AsyncMock, token_repo: AsyncMock
    ):
        user = _make_user()
        user_repo.get_by_email.return_value = user
        token_repo.create.return_value = MagicMock()

        access, refresh = await auth_service.login("user@example.com", "Test1234!")

        assert access.startswith("v4.public.")
        assert refresh.startswith("v4.local.")
        token_repo.create.assert_called_once()

    async def test_login_wrong_password(
        self, auth_service: AuthService, user_repo: AsyncMock
    ):
        user = _make_user()
        user_repo.get_by_email.return_value = user

        with pytest.raises(AuthenticationError, match="Invalid credentials"):
            await auth_service.login("user@example.com", "WrongPass1!")

    async def test_login_unknown_email(
        self, auth_service: AuthService, user_repo: AsyncMock
    ):
        user_repo.get_by_email.return_value = None

        with pytest.raises(AuthenticationError, match="Invalid credentials"):
            await auth_service.login("nobody@example.com", "Test1234!")

    async def test_login_inactive_user(
        self, auth_service: AuthService, user_repo: AsyncMock
    ):
        user = _make_user(is_active=False)
        user_repo.get_by_email.return_value = user

        with pytest.raises(AuthenticationError, match="disabled"):
            await auth_service.login("user@example.com", "Test1234!")

    async def test_login_rate_limit(
        self, auth_service: AuthService, mock_redis: AsyncMock
    ):
        mock_redis.exists.return_value = 1

        with pytest.raises(AccountLockedError):
            await auth_service.login("user@example.com", "Test1234!")


class TestRefresh:
    async def test_refresh_reuse_detection(
        self,
        auth_service: AuthService,
        paseto_service: PasetoService,
        token_repo: AsyncMock,
    ):
        user_id = uuid.uuid4()
        family_id = uuid.uuid4()
        token, jti = paseto_service.create_refresh_token(user_id, family_id)

        stored = MagicMock(spec=RefreshToken)
        stored.is_revoked = True
        stored.family_id = family_id
        stored.user_id = user_id
        token_repo.get_by_token_hash.return_value = stored
        token_repo.revoke_token_family.return_value = 3

        with pytest.raises(RefreshTokenReuseError):
            await auth_service.refresh(token)

        token_repo.revoke_token_family.assert_called_once_with(family_id)
