import asyncio

from sqlalchemy import select

from tracegate.db import Base, AsyncSessionLocal, engine
from tracegate.models import IpamPool, SniDomain
from tracegate.services.ipam import ensure_pool_exists
from tracegate.settings import get_settings


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    settings = get_settings()
    async with AsyncSessionLocal() as session:
        for fqdn in settings.sni_seed:
            existing = await session.scalar(select(SniDomain).where(SniDomain.fqdn == fqdn))
            if not existing:
                session.add(SniDomain(fqdn=fqdn, enabled=True, is_test=True))

        pool = await session.scalar(select(IpamPool).where(IpamPool.cidr == "10.70.0.0/24"))
        if not pool:
            await ensure_pool_exists(session, cidr="10.70.0.0/24", gateway="10.70.0.1")

        await session.commit()


def main() -> None:
    asyncio.run(init_db())


if __name__ == "__main__":
    main()
