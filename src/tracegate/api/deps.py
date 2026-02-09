from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.db import AsyncSessionLocal


async def db_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session
