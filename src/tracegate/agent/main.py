from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version as pkg_version
from pathlib import Path

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Response, status
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from tracegate.observability import configure_logging, install_http_observability
from tracegate.schemas import AgentEventEnvelope, AgentEventResponse, AgentHealthCheckResult, AgentHealthResponse
from tracegate.security import require_agent_token
from tracegate.settings import ensure_agent_dirs, get_settings

from .metrics import register_agent_metrics
from .handlers import HandlerError, dispatch_event
from .state import AgentStateStore
from .system import gather_health_checks

settings = get_settings()
configure_logging(settings.log_level)
if not settings.agent_auth_token:
    raise RuntimeError("AGENT_AUTH_TOKEN is required")
if settings.agent_role == "VPS_T" and not settings.agent_stats_secret:
    raise RuntimeError("AGENT_STATS_SECRET is required for VPS_T health checks")
ensure_agent_dirs(settings)
state_store = AgentStateStore(Path(settings.agent_data_root))
register_agent_metrics(settings)

def _app_version() -> str:
    try:
        return pkg_version("tracegate")
    except PackageNotFoundError:
        return "dev"
    except Exception:
        return "unknown"


app = FastAPI(title="Tracegate Node Agent", version=_app_version())
install_http_observability(app, component="agent")


@app.post("/v1/events", response_model=AgentEventResponse, dependencies=[Depends(require_agent_token)])
async def receive_event(event: AgentEventEnvelope) -> AgentEventResponse:
    event_id = str(event.event_id)
    if state_store.seen(event_id):
        return AgentEventResponse(accepted=True, duplicate=True, message="event already processed")

    try:
        message = dispatch_event(settings, event.event_type, event.payload)
    except HandlerError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    state_store.mark(event_id, event.idempotency_key)
    return AgentEventResponse(accepted=True, duplicate=False, message=message)


@app.get("/v1/health", response_model=AgentHealthResponse)
async def health() -> AgentHealthResponse:
    rows = await gather_health_checks(
        settings.agent_stats_url,
        settings.agent_stats_secret,
        settings.agent_wg_interface,
        settings.agent_wg_expected_port,
        settings.agent_role,
        settings.agent_runtime_mode,
    )
    checks = [AgentHealthCheckResult(**row) for row in rows]
    return AgentHealthResponse(role=settings.agent_role, checks=checks, overall_ok=all(row["ok"] for row in rows))


@app.get("/metrics", dependencies=[Depends(require_agent_token)])
async def metrics() -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


def run() -> None:
    ssl_kwargs = {}
    if settings.agent_server_cert and settings.agent_server_key:
        ssl_kwargs = {
            "ssl_certfile": settings.agent_server_cert,
            "ssl_keyfile": settings.agent_server_key,
        }
        if settings.agent_ca_cert:
            ssl_kwargs["ssl_ca_certs"] = settings.agent_ca_cert
            ssl_kwargs["ssl_cert_reqs"] = 2

    uvicorn.run(
        "tracegate.agent.main:app",
        host=settings.agent_host,
        port=settings.agent_port,
        reload=False,
        log_level=settings.log_level.lower(),
        **ssl_kwargs,
    )


if __name__ == "__main__":
    run()
