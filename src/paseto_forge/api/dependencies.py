import uuid
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, Request
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from paseto_forge.config import Settings, get_settings
from paseto_forge.database import get_async_session
from paseto_forge.exceptions import (
    AuthenticationError,
    PermissionDeniedError,
    TokenInvalidError,
    TokenRevokedError,
    UserNotFoundError,
)
from paseto_forge.models.user import User
from paseto_forge.redis_client import get_redis
from paseto_forge.repositories.refresh_token_repo import RefreshTokenRepository
from paseto_forge.repositories.user_repo import UserRepository
from paseto_forge.services.auth_service import AuthService
from paseto_forge.services.paseto_service import PasetoService, TokenPayload

SettingsDep = Annotated[Settings, Depends(get_settings)]
SessionDep = Annotated[AsyncSession, Depends(get_async_session)]
RedisDep = Annotated[Redis, Depends(get_redis)]


@lru_cache
def _cached_paseto_service() -> PasetoService:
    return PasetoService(get_settings())


def get_paseto_service() -> PasetoService:
    return _cached_paseto_service()


PasetoServiceDep = Annotated[PasetoService, Depends(get_paseto_service)]


def get_user_repo(session: SessionDep) -> UserRepository:
    return UserRepository(session)


def get_token_repo(session: SessionDep) -> RefreshTokenRepository:
    return RefreshTokenRepository(session)


UserRepoDep = Annotated[UserRepository, Depends(get_user_repo)]
TokenRepoDep = Annotated[RefreshTokenRepository, Depends(get_token_repo)]


def get_auth_service(
    user_repo: UserRepoDep,
    token_repo: TokenRepoDep,
    paseto_service: PasetoServiceDep,
    redis: RedisDep,
    settings: SettingsDep,
) -> AuthService:
    return AuthService(user_repo, token_repo, paseto_service, redis, settings)


AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]


async def get_current_token_payload(
    request: Request,
    paseto_service: PasetoServiceDep,
    redis: RedisDep,
) -> TokenPayload:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise TokenInvalidError(detail="Missing or invalid Authorization header")

    token = auth_header.removeprefix("Bearer ")
    payload = paseto_service.decode_access_token(token)

    if await redis.exists(f"blacklist:{payload.jti}"):
        raise TokenRevokedError()

    return payload


TokenPayloadDep = Annotated[TokenPayload, Depends(get_current_token_payload)]


async def get_current_active_user(
    payload: TokenPayloadDep,
    user_repo: UserRepoDep,
) -> User:
    user = await user_repo.get_by_id(uuid.UUID(payload.sub))
    if not user:
        raise UserNotFoundError()
    if not user.is_active:
        raise AuthenticationError(detail="Account is disabled")
    return user


CurrentUserDep = Annotated[User, Depends(get_current_active_user)]


def require_roles(*roles: str):
    async def _check(current_user: CurrentUserDep) -> User:
        if not any(r in current_user.roles for r in roles):
            raise PermissionDeniedError(detail=f"Required roles: {', '.join(roles)}")
        return current_user

    return _check
