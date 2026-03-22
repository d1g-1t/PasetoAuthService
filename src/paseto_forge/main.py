import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from paseto_forge.api.v1.router import router as v1_router
from paseto_forge.config import get_settings
from paseto_forge.database import SessionFactory, close_db, init_db
from paseto_forge.exceptions import PasetoAuthServiceError
from paseto_forge.middleware import RequestIdMiddleware
from paseto_forge.redis_client import close_redis, init_redis

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    settings = get_settings()

    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.dev.ConsoleRenderer()
            if settings.DEBUG
            else structlog.processors.JSONRenderer(),
        ],
    )

    init_db(
        settings.DATABASE_URL,
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_timeout=settings.DB_POOL_TIMEOUT,
        pool_pre_ping=True,
        echo=settings.DEBUG,
    )
    init_redis(settings.REDIS_URL)

    cleanup_task = asyncio.create_task(_cleanup_loop())
    logger.info("paseto_forge.started", version=settings.APP_VERSION)

    yield

    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass
    await close_redis()
    await close_db()
    logger.info("paseto_forge.stopped")


async def _cleanup_loop() -> None:
    from paseto_forge.repositories.refresh_token_repo import RefreshTokenRepository

    while True:
        await asyncio.sleep(6 * 3600)
        try:
            if SessionFactory is None:
                continue
            async with SessionFactory() as session:
                repo = RefreshTokenRepository(session)
                deleted = await repo.cleanup_expired()
                await session.commit()
                logger.info("expired_tokens_cleaned", count=deleted)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("cleanup_failed", error=str(exc))


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(RequestIdMiddleware)

    if settings.CORS_ORIGINS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.CORS_ORIGINS,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    @app.exception_handler(PasetoAuthServiceError)
    async def paseto_auth_service_exception_handler(
        request: Request, exc: PasetoAuthServiceError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error_code": exc.error_code,
                "detail": exc.detail,
                "request_id": getattr(request.state, "request_id", None),
            },
        )

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(v1_router, prefix="/api/v1")

    return app


app = create_app()
