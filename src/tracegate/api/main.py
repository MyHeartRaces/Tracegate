from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from sqlalchemy import select

from tracegate.api.routers import auth, connections, devices, dispatch, health, nodes, revisions, sni, users
from tracegate.db import Base, engine, AsyncSessionLocal
from tracegate.models import SniDomain
from tracegate.services.ipam import ensure_pool_exists
from tracegate.settings import get_settings


@asynccontextmanager
async def lifespan(_: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    settings = get_settings()
    async with AsyncSessionLocal() as session:
        for fqdn in settings.sni_seed:
            existing = await session.scalar(select(SniDomain).where(SniDomain.fqdn == fqdn))
            if not existing:
                session.add(SniDomain(fqdn=fqdn, enabled=True, is_test=True))
        await ensure_pool_exists(session)
        await session.commit()

    yield


app = FastAPI(title="Tracegate Control Plane", version="0.1.0", lifespan=lifespan)

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(sni.router)
app.include_router(users.router)
app.include_router(devices.router)
app.include_router(connections.router)
app.include_router(revisions.router)
app.include_router(nodes.router)
app.include_router(dispatch.router)


def run() -> None:
    settings = get_settings()
    uvicorn.run(
        "tracegate.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=False,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    run()
