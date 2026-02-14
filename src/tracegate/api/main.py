from contextlib import asynccontextmanager, suppress
from importlib.metadata import PackageNotFoundError, version as pkg_version

import asyncio
import anyio
import uvicorn
from fastapi import FastAPI

from tracegate.api.routers import admin, auth, bot_messages, connections, devices, dispatch, grafana, health, metrics, nodes, revisions, sni, users
from tracegate.api.inventory_metrics import inventory_refresh_loop, register_inventory_metrics
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

    # Inventory metrics (connections/users mapping for Grafana dashboards).
    register_inventory_metrics()
    refresh_task = asyncio.create_task(inventory_refresh_loop(settings))
    try:
        yield
    finally:
        refresh_task.cancel()
        with suppress(asyncio.CancelledError):
            await refresh_task


settings = get_settings()
configure_logging(settings.log_level)

def _app_version() -> str:
    try:
        return pkg_version("tracegate")
    except PackageNotFoundError:
        return "dev"
    except Exception:
        return "unknown"


app = FastAPI(title="Tracegate Control Plane", version=_app_version(), lifespan=lifespan)
install_http_observability(app, component="api")

app.include_router(health.router)
app.include_router(metrics.router)
app.include_router(grafana.router)
app.include_router(auth.router)
app.include_router(admin.router)
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
