import asyncio

from sqlalchemy import select

from tracegate.db import Base, get_engine, get_sessionmaker
from tracegate.models import IpamPool
from tracegate.services.ipam import ensure_pool_exists


async def init_db() -> None:
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with get_sessionmaker() as session:
        pool = await session.scalar(select(IpamPool).where(IpamPool.cidr == "10.70.0.0/24"))
        if not pool:
            await ensure_pool_exists(session, cidr="10.70.0.0/24", gateway="10.70.0.1")

        await session.commit()


def main() -> None:
    asyncio.run(init_db())


if __name__ == "__main__":
    main()
