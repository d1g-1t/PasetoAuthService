import hashlib
import json
import uuid

import pyseto
from pydantic import BaseModel
from pyseto import Key, Paseto

from paseto_forge.config import Settings
from paseto_forge.exceptions import TokenExpiredError, TokenInvalidError


class TokenPayload(BaseModel):
    sub: str
    email: str
    roles: list[str]
    jti: str
    iss: str
    aud: str
    iat: str
    exp: str


class RefreshTokenPayload(BaseModel):
    sub: str
    jti: str
    family_id: str
    rotation_count: int
    iat: str
    exp: str


class PasetoService:
    def __init__(self, settings: Settings):
        self._private_key = Key.from_paserk(
            settings.PASETO_PRIVATE_KEY_PASERK.get_secret_value()
        )
        self._public_key = Key.from_paserk(settings.PASETO_PUBLIC_KEY_PASERK)
        self._local_key = Key.from_paserk(settings.PASETO_LOCAL_KEY_PASERK.get_secret_value())

        self._previous_local_keys: list[Key] = []
        if settings.PASETO_PREVIOUS_LOCAL_KEYS_PASERK:
            for k in settings.PASETO_PREVIOUS_LOCAL_KEYS_PASERK.split(","):
                k = k.strip()
                if k:
                    self._previous_local_keys.append(Key.from_paserk(k))

        self._access_exp = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        self._refresh_exp = settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400
        self._public_key_paserk = settings.PASETO_PUBLIC_KEY_PASERK

        self._access_encoder = Paseto.new(exp=self._access_exp, include_iat=True)
        self._refresh_encoder = Paseto.new(exp=self._refresh_exp, include_iat=True)

    def create_access_token(
        self, user_id: uuid.UUID, email: str, roles: list[str]
    ) -> str:
        payload = {
            "sub": str(user_id),
            "email": email,
            "roles": roles,
            "jti": str(uuid.uuid4()),
            "iss": "paseto-forge",
            "aud": "paseto-forge-client",
        }
        token = self._access_encoder.encode(
            self._private_key,
            payload,
            serializer=json,
        )
        return token.decode() if isinstance(token, bytes) else token

    def create_refresh_token(
        self,
        user_id: uuid.UUID,
        family_id: uuid.UUID,
        rotation_count: int = 0,
    ) -> tuple[str, str]:
        jti = str(uuid.uuid4())
        payload = {
            "sub": str(user_id),
            "jti": jti,
            "family_id": str(family_id),
            "rotation_count": rotation_count,
        }
        token = self._refresh_encoder.encode(
            self._local_key,
            payload,
            serializer=json,
        )
        raw = token.decode() if isinstance(token, bytes) else token
        return raw, jti

    def decode_access_token(self, token: str) -> TokenPayload:
        raw = token.encode() if isinstance(token, str) else token
        try:
            decoded = pyseto.decode(self._public_key, raw, deserializer=json)
            return TokenPayload(**decoded.payload)
        except Exception as exc:
            if "expired" in str(exc).lower() or "exp" in str(exc).lower():
                raise TokenExpiredError()
            raise TokenInvalidError()

    def decode_refresh_token(self, token: str) -> RefreshTokenPayload:
        raw = token.encode() if isinstance(token, str) else token
        keys = [self._local_key, *self._previous_local_keys]
        for key in keys:
            try:
                decoded = pyseto.decode(key, raw, deserializer=json)
                return RefreshTokenPayload(**decoded.payload)
            except Exception:
                continue
        raise TokenInvalidError(detail="Invalid refresh token")

    @staticmethod
    def hash_jti(jti: str) -> str:
        return hashlib.sha256(jti.encode()).hexdigest()

    @property
    def public_key_paserk(self) -> str:
        return self._public_key_paserk

    @classmethod
    def generate_keys(cls) -> dict[str, str]:
        from secrets import token_bytes

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )

        ed_private = Ed25519PrivateKey.generate()
        private_pem = ed_private.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
        public_pem = ed_private.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )

        private_key = Key.new(4, "public", private_pem)
        public_key = Key.new(4, "public", public_pem)
        local_key = Key.new(4, "local", token_bytes(32))

        return {
            "PASETO_PRIVATE_KEY_PASERK": private_key.to_paserk(),
            "PASETO_PUBLIC_KEY_PASERK": public_key.to_paserk(),
            "PASETO_LOCAL_KEY_PASERK": local_key.to_paserk(),
        }
