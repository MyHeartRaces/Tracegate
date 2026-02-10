from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from tracegate.api.routers import auth, connections, devices, dispatch, health, nodes, revisions, sni, users
from tracegate.db import Base, engine, AsyncSessionLocal
from tracegate.db_migrate import migrate
from tracegate.services.ipam import ensure_pool_exists
from tracegate.services.sni_seed import seed_sni
from tracegate.settings import get_settings


@asynccontextmanager
async def lifespan(_: FastAPI):
    async with engine.begin() as conn:
        await migrate(conn)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        await seed_sni(session)
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
