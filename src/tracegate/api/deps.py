from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.db import get_sessionmaker


async def db_session() -> AsyncGenerator[AsyncSession, None]:
    async with get_sessionmaker()() as session:
        yield session
