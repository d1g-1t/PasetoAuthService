import uuid
from datetime import datetime, timedelta, timezone

import structlog
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from redis.asyncio import Redis

from paseto_forge.config import Settings
from paseto_forge.exceptions import (
    AccountLockedError,
    AuthenticationError,
    RefreshTokenReuseError,
    TokenExpiredError,
    TokenInvalidError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from paseto_forge.models.user import User
from paseto_forge.repositories.refresh_token_repo import RefreshTokenRepository
from paseto_forge.repositories.user_repo import UserRepository
from paseto_forge.services.paseto_service import PasetoService

logger = structlog.get_logger()
ph = PasswordHasher()


class AuthService:
    def __init__(
        self,
        user_repo: UserRepository,
        token_repo: RefreshTokenRepository,
        paseto_service: PasetoService,
        redis: Redis,
        settings: Settings,
    ):
        self.user_repo = user_repo
        self.token_repo = token_repo
        self.paseto = paseto_service
        self.redis = redis
        self.settings = settings

    async def register(self, email: str, password: str) -> User:
        existing = await self.user_repo.get_by_email(email)
        if existing:
            raise UserAlreadyExistsError(detail=f"Email {email} is already registered")

        hashed = ph.hash(password)
        return await self.user_repo.create(
            email=email,
            hashed_password=hashed,
            roles=["user"],
        )

    async def login(
        self,
        email: str,
        password: str,
        device_info: str | None = None,
        ip_address: str | None = None,
    ) -> tuple[str, str]:
        await self._check_rate_limit(email, ip_address)

        user = await self.user_repo.get_by_email(email)
        if not user:
            await self._record_failed_login(email, ip_address)
            raise AuthenticationError(detail="Invalid credentials")

        if not user.is_active:
            raise AuthenticationError(detail="Account is disabled")

        try:
            ph.verify(user.hashed_password, password)
        except (VerifyMismatchError, VerificationError):
            await self._record_failed_login(email, ip_address)
            raise AuthenticationError(detail="Invalid credentials")

        if ph.check_needs_rehash(user.hashed_password):
            await self.user_repo.update(user, hashed_password=ph.hash(password))

        await self._clear_failed_logins(email, ip_address)

        family_id = uuid.uuid4()
        access_token = self.paseto.create_access_token(user.id, user.email, user.roles)
        refresh_token, jti = self.paseto.create_refresh_token(user.id, family_id)

        await self.token_repo.create(
            token_hash=PasetoService.hash_jti(jti),
            family_id=family_id,
            user_id=user.id,
            device_info=device_info,
            ip_address=ip_address,
            expires_at=datetime.now(timezone.utc)
            + timedelta(days=self.settings.REFRESH_TOKEN_EXPIRE_DAYS),
        )

        logger.info("user.login", user_id=str(user.id), ip=ip_address)
        return access_token, refresh_token

    async def refresh(self, raw_refresh_token: str) -> tuple[str, str]:
        payload = self.paseto.decode_refresh_token(raw_refresh_token)
        token_hash = PasetoService.hash_jti(payload.jti)
        stored = await self.token_repo.get_by_token_hash(token_hash)

        if not stored:
            raise TokenInvalidError(detail="Refresh token not recognized")

        if stored.is_revoked:
            revoked_count = await self.token_repo.revoke_token_family(stored.family_id)
            logger.warning(
                "refresh_token.reuse_detected",
                family_id=str(stored.family_id),
                user_id=str(stored.user_id),
                revoked=revoked_count,
            )
            raise RefreshTokenReuseError()

        if stored.is_expired:
            raise TokenExpiredError(detail="Refresh token has expired")

        await self.token_repo.update(stored, revoked_at=datetime.now(timezone.utc))

        user = await self.user_repo.get_by_id(stored.user_id)
        if not user or not user.is_active:
            raise UserNotFoundError(detail="User not found or disabled")

        new_rotation = stored.rotation_count + 1
        access_token = self.paseto.create_access_token(user.id, user.email, user.roles)
        refresh_token, new_jti = self.paseto.create_refresh_token(
            user.id, stored.family_id, new_rotation
        )

        await self.token_repo.create(
            token_hash=PasetoService.hash_jti(new_jti),
            family_id=stored.family_id,
            user_id=user.id,
            rotation_count=new_rotation,
            device_info=stored.device_info,
            ip_address=stored.ip_address,
            expires_at=datetime.now(timezone.utc)
            + timedelta(days=self.settings.REFRESH_TOKEN_EXPIRE_DAYS),
        )

        return access_token, refresh_token

    async def logout(self, access_jti: str, access_exp: str) -> None:
        try:
            exp_dt = datetime.fromisoformat(access_exp)
            remaining = int((exp_dt - datetime.now(timezone.utc)).total_seconds())
            if remaining > 0:
                await self.redis.setex(f"blacklist:{access_jti}", remaining, "1")
        except (ValueError, TypeError):
            pass

    async def logout_with_refresh(
        self, access_jti: str, access_exp: str, refresh_token: str | None
    ) -> None:
        await self.logout(access_jti, access_exp)

        if refresh_token:
            try:
                payload = self.paseto.decode_refresh_token(refresh_token)
                token_hash = PasetoService.hash_jti(payload.jti)
                stored = await self.token_repo.get_by_token_hash(token_hash)
                if stored and not stored.is_revoked:
                    await self.token_repo.update(
                        stored, revoked_at=datetime.now(timezone.utc)
                    )
            except Exception:
                pass

    async def logout_all(self, user_id: uuid.UUID) -> None:
        await self.token_repo.revoke_all_for_user(user_id)

    async def _check_rate_limit(self, email: str, ip_address: str | None) -> None:
        lockout_key = f"lockout:{email}"
        if await self.redis.exists(lockout_key):
            raise AccountLockedError(
                detail="Account temporarily locked — too many failed attempts"
            )

        if ip_address:
            rate_key = f"login_rate:{ip_address}"
            count = await self.redis.get(rate_key)
            if count and int(count) >= self.settings.LOGIN_RATE_LIMIT_ATTEMPTS:
                raise AccountLockedError(detail="Too many login attempts from this IP")

    async def _record_failed_login(self, email: str, ip_address: str | None) -> None:
        fail_key = f"login_fail:{email}"
        failures = await self.redis.incr(fail_key)
        await self.redis.expire(fail_key, self.settings.ACCOUNT_LOCKOUT_DURATION_SECONDS)

        if failures >= self.settings.ACCOUNT_LOCKOUT_AFTER_FAILURES:
            lockout_key = f"lockout:{email}"
            await self.redis.setex(
                lockout_key, self.settings.ACCOUNT_LOCKOUT_DURATION_SECONDS, "1"
            )
            logger.warning("account.locked", email=email)

        if ip_address:
            rate_key = f"login_rate:{ip_address}"
            await self.redis.incr(rate_key)
            await self.redis.expire(rate_key, self.settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS)

    async def _clear_failed_logins(self, email: str, ip_address: str | None) -> None:
        await self.redis.delete(f"login_fail:{email}")
        if ip_address:
            await self.redis.delete(f"login_rate:{ip_address}")
