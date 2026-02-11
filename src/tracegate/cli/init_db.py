import asyncio

from sqlalchemy import select

from tracegate.cli.migrate_db import migrate_db
from tracegate.db import get_sessionmaker
from tracegate.models import IpamPool
from tracegate.services.ipam import ensure_pool_exists


async def init_db() -> None:
    # Schema migrations are sync (Alembic); run them before doing async seeding.
    migrate_db()

    async with get_sessionmaker() as session:
        pool = await session.scalar(select(IpamPool).where(IpamPool.cidr == "10.70.0.0/24"))
        if not pool:
            await ensure_pool_exists(session, cidr="10.70.0.0/24", gateway="10.70.0.1")

        await session.commit()


def main() -> None:
    asyncio.run(init_db())


if __name__ == "__main__":
    main()
