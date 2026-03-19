import uuid

import pytest

from paseto_forge.exceptions import TokenExpiredError, TokenInvalidError
from paseto_forge.services.paseto_service import PasetoService


class TestPasetoService:
    def test_create_access_token_returns_v4_public(self, paseto_service: PasetoService):
        token = paseto_service.create_access_token(
            uuid.uuid4(), "test@example.com", ["user"]
        )
        assert token.startswith("v4.public.")

    def test_decode_access_token_roundtrip(self, paseto_service: PasetoService):
        user_id = uuid.uuid4()
        token = paseto_service.create_access_token(user_id, "a@b.com", ["user", "admin"])
        payload = paseto_service.decode_access_token(token)

        assert payload.sub == str(user_id)
        assert payload.email == "a@b.com"
        assert payload.roles == ["user", "admin"]
        assert payload.iss == "paseto-forge"
        assert payload.aud == "paseto-forge-client"

    def test_create_refresh_token_returns_v4_local(self, paseto_service: PasetoService):
        token, jti = paseto_service.create_refresh_token(uuid.uuid4(), uuid.uuid4())
        assert token.startswith("v4.local.")
        assert len(jti) == 36

    def test_decode_refresh_token_roundtrip(self, paseto_service: PasetoService):
        user_id = uuid.uuid4()
        family_id = uuid.uuid4()
        token, jti = paseto_service.create_refresh_token(user_id, family_id, rotation_count=3)
        payload = paseto_service.decode_refresh_token(token)

        assert payload.sub == str(user_id)
        assert payload.jti == jti
        assert payload.family_id == str(family_id)
        assert payload.rotation_count == 3

    def test_hash_jti_deterministic(self):
        jti = str(uuid.uuid4())
        assert PasetoService.hash_jti(jti) == PasetoService.hash_jti(jti)
        assert len(PasetoService.hash_jti(jti)) == 64

    def test_hash_jti_unique(self):
        a = PasetoService.hash_jti(str(uuid.uuid4()))
        b = PasetoService.hash_jti(str(uuid.uuid4()))
        assert a != b

    def test_generate_keys_format(self):
        keys = PasetoService.generate_keys()
        assert keys["PASETO_PRIVATE_KEY_PASERK"].startswith("k4.secret.")
        assert keys["PASETO_PUBLIC_KEY_PASERK"].startswith("k4.public.")
        assert keys["PASETO_LOCAL_KEY_PASERK"].startswith("k4.local.")

    def test_invalid_access_token_raises(self, paseto_service: PasetoService):
        with pytest.raises(TokenInvalidError):
            paseto_service.decode_access_token("v4.public.garbage-data-here")

    def test_invalid_refresh_token_raises(self, paseto_service: PasetoService):
        with pytest.raises(TokenInvalidError):
            paseto_service.decode_refresh_token("v4.local.garbage-data-here")

    def test_cross_key_decode_fails(self, settings):
        svc1 = PasetoService(settings)
        keys2 = PasetoService.generate_keys()
        from paseto_forge.config import Settings

        settings2 = Settings(
            DATABASE_URL=settings.DATABASE_URL,
            REDIS_URL=settings.REDIS_URL,
            PASETO_PRIVATE_KEY_PASERK=keys2["PASETO_PRIVATE_KEY_PASERK"],
            PASETO_PUBLIC_KEY_PASERK=keys2["PASETO_PUBLIC_KEY_PASERK"],
            PASETO_LOCAL_KEY_PASERK=keys2["PASETO_LOCAL_KEY_PASERK"],
        )
        svc2 = PasetoService(settings2)

        token = svc1.create_access_token(uuid.uuid4(), "a@b.com", ["user"])
        with pytest.raises(TokenInvalidError):
            svc2.decode_access_token(token)
