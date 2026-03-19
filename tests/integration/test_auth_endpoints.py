"""Integration tests for authentication endpoints.

Key design decisions
--------------------
* ``ASGITransport`` does **not** trigger the ASGI lifespan, so ``init_db()``
  and ``init_redis()`` must be called manually before the first request.
* The ``.env`` file uses ``auto`` as a placeholder for PASETO keys; the
  entrypoint script generates real keys for the uvicorn process, but pytest
  runs in a separate process that sees only ``auto``.  We generate ephemeral
  keys in the fixture and inject them via FastAPI dependency overrides.
* All tests in ``TestAuthFlow`` share a single module-scoped ``client`` so the
  database state (created user) persists across test methods.
"""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine

import paseto_forge.database as db_module
import paseto_forge.redis_client as redis_module
from paseto_forge.api.dependencies import _cached_paseto_service, get_paseto_service
from paseto_forge.config import Settings, get_settings
from paseto_forge.main import app
from paseto_forge.models import Base
from paseto_forge.services.paseto_service import PasetoService

EMAIL = "integration@example.com"
PASSWORD = "IntTest1!"


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def client():
    """Prepare the full stack once and yield a shared HTTP client.

    Steps
    -----
    1. Generate real PASETO keys (env has ``auto`` placeholders).
    2. Build a ``Settings`` object with those keys.
    3. Create the DB schema via a dedicated engine.
    4. Manually call ``init_db`` / ``init_redis`` (lifespan doesn't fire).
    5. Override ``get_settings`` and ``get_paseto_service`` dependencies.
    6. Yield the ``AsyncClient``.
    7. Tear down: clear overrides, drop schema, close connections.
    """
    # ── Real PASETO keys ────────────────────────────────────────────────────
    keys = PasetoService.generate_keys()
    base_settings = get_settings()
    settings = Settings(
        DATABASE_URL=base_settings.DATABASE_URL,
        REDIS_URL=base_settings.REDIS_URL,
        PASETO_PRIVATE_KEY_PASERK=keys["PASETO_PRIVATE_KEY_PASERK"],
        PASETO_PUBLIC_KEY_PASERK=keys["PASETO_PUBLIC_KEY_PASERK"],
        PASETO_LOCAL_KEY_PASERK=keys["PASETO_LOCAL_KEY_PASERK"],
    )

    # ── Schema setup ────────────────────────────────────────────────────────
    setup_engine = create_async_engine(settings.DATABASE_URL, pool_pre_ping=True)
    async with setup_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    await setup_engine.dispose()

    # ── Manual init (ASGITransport does not trigger ASGI lifespan) ──────────
    db_module.init_db(
        settings.DATABASE_URL,
        pool_size=2,
        max_overflow=0,
        pool_pre_ping=True,
    )
    redis_module.init_redis(settings.REDIS_URL)
    paseto_service = PasetoService(settings)

    # ── Override FastAPI dependencies ────────────────────────────────────────
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_paseto_service] = lambda: paseto_service
    _cached_paseto_service.cache_clear()

    # ── Run tests ────────────────────────────────────────────────────────────
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    # ── Cleanup ──────────────────────────────────────────────────────────────
    app.dependency_overrides.clear()
    await db_module.close_db()
    await redis_module.close_redis()

    teardown_engine = create_async_engine(settings.DATABASE_URL)
    async with teardown_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await teardown_engine.dispose()


@pytest.mark.asyncio(loop_scope="module")
class TestAuthFlow:
    """Sequential end-to-end auth flow – order matters (shared DB state)."""

    async def test_register(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/register",
            json={"email": EMAIL, "password": PASSWORD, "password_confirm": PASSWORD},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["email"] == EMAIL
        assert "id" in data
        assert data["is_active"] is True

    async def test_register_duplicate(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/register",
            json={"email": EMAIL, "password": PASSWORD, "password_confirm": PASSWORD},
        )
        assert resp.status_code == 409

    async def test_login(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": EMAIL, "password": PASSWORD},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["access_token"].startswith("v4.public.")
        assert data["token_type"] == "bearer"
        assert "refresh_token" in resp.cookies

    async def test_me(self, client: AsyncClient):
        login = await client.post(
            "/api/v1/auth/login",
            json={"email": EMAIL, "password": PASSWORD},
        )
        assert login.status_code == 200
        token = login.json()["access_token"]

        resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == EMAIL
        assert "id" in data

    async def test_public_key(self, client: AsyncClient):
        resp = await client.get("/api/v1/auth/.well-known/paseto-public-key")
        assert resp.status_code == 200
        data = resp.json()
        assert data["version"] == "v4"
        assert data["purpose"] == "public"
        assert data["key"].startswith("k4.public.")

    async def test_password_too_short(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "weak@example.com",
                "password": "short",
                "password_confirm": "short",
            },
        )
        assert resp.status_code == 422

    async def test_password_no_uppercase(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "weak@example.com",
                "password": "alllower1!",
                "password_confirm": "alllower1!",
            },
        )
        assert resp.status_code == 422

    async def test_password_mismatch(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "new@example.com",
                "password": "ValidPass1!",
                "password_confirm": "DifferentPass1!",
            },
        )
        assert resp.status_code == 422

    async def test_login_wrong_password(self, client: AsyncClient):
        resp = await client.post(
            "/api/v1/auth/login",
            json={"email": EMAIL, "password": "WrongPass1!"},
        )
        assert resp.status_code == 401

    async def test_me_unauthenticated(self, client: AsyncClient):
        resp = await client.get("/api/v1/auth/me")
        assert resp.status_code == 401

    async def test_me_bad_token(self, client: AsyncClient):
        resp = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer not.a.real.token"},
        )
        assert resp.status_code == 401

    async def test_healthz(self, client: AsyncClient):
        resp = await client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}
