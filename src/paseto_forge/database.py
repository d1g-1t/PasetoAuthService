from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

engine: AsyncEngine | None = None
SessionFactory: async_sessionmaker[AsyncSession] | None = None


def init_db(database_url: str, **kwargs: object) -> None:
    global engine, SessionFactory
    engine = create_async_engine(database_url, **kwargs)
    SessionFactory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )


async def close_db() -> None:
    global engine
    if engine:
        await engine.dispose()
        engine = None


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    assert SessionFactory is not None, "Database not initialized — call init_db() first"
    async with SessionFactory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
