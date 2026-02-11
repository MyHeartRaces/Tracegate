from contextlib import asynccontextmanager

import anyio
import uvicorn
from fastapi import FastAPI

from tracegate.api.routers import auth, bot_messages, connections, devices, dispatch, grafana, health, metrics, nodes, revisions, sni, users
from tracegate.cli.migrate_db import migrate_db
from tracegate.db import get_sessionmaker
from tracegate.observability import configure_logging, install_http_observability
from tracegate.services.ipam import ensure_pool_exists
from tracegate.settings import get_settings


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Migrations are sync (Alembic). Run them before serving any traffic.
    await anyio.to_thread.run_sync(migrate_db)

    async with get_sessionmaker()() as session:
        await ensure_pool_exists(session)
        await session.commit()

    yield


settings = get_settings()
configure_logging(settings.log_level)

app = FastAPI(title="Tracegate Control Plane", version="0.3.0", lifespan=lifespan)
install_http_observability(app, component="api")

app.include_router(health.router)
app.include_router(metrics.router)
app.include_router(grafana.router)
app.include_router(auth.router)
app.include_router(sni.router)
app.include_router(users.router)
app.include_router(devices.router)
app.include_router(connections.router)
app.include_router(revisions.router)
app.include_router(nodes.router)
app.include_router(bot_messages.router)
app.include_router(dispatch.router)


def run() -> None:
    if not settings.api_internal_token:
        raise RuntimeError("API_INTERNAL_TOKEN is required")
    uvicorn.run(
        "tracegate.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=False,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    run()
