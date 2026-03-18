from collections.abc import AsyncGenerator

from redis.asyncio import ConnectionPool, Redis

pool: ConnectionPool | None = None


def init_redis(redis_url: str) -> None:
    global pool
    pool = ConnectionPool.from_url(redis_url, decode_responses=True)


async def close_redis() -> None:
    global pool
    if pool:
        await pool.aclose()
        pool = None


async def get_redis() -> AsyncGenerator[Redis, None]:
    assert pool is not None, "Redis not initialized — call init_redis() first"
    client = Redis(connection_pool=pool)
    try:
        yield client
    finally:
        await client.aclose()
