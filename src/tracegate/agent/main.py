from __future__ import annotations

import logging
from importlib.metadata import PackageNotFoundError, version as pkg_version
from ipaddress import ip_address
from pathlib import Path

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel
from starlette.middleware.cors import CORSMiddleware

from tracegate.observability import configure_logging, install_http_observability
from tracegate.schemas import AgentEventEnvelope, AgentEventResponse, AgentHealthCheckResult, AgentHealthResponse
from tracegate.security import require_agent_token
from tracegate.services.decoy_auth import (
    DecoyAuthConfigError,
    build_decoy_session_cookie,
    decoy_auth_is_configured,
    load_decoy_session,
    load_github_repo_frame_html,
    load_mtproto_public_profile,
    verify_decoy_credentials,
)
from tracegate.services.mtproto_access import (
    issue_mtproto_access_profile,
    load_mtproto_access_entries,
    revoke_mtproto_access,
)
from tracegate.services.runtime_contract import resolve_runtime_contract
from tracegate.settings import effective_mtproto_reload_cmd, ensure_agent_dirs, get_settings

from .metrics import register_agent_metrics
from .reconcile import AgentPaths, _artifact_applies_to_role, _reconcile_all_result, load_all_user_artifacts
from .system import run_command
from .handlers import HandlerError, _reload_commands_for_changed, dispatch_event
from .state import AgentStateStore
from .system import gather_health_checks

settings = get_settings()
runtime_contract = resolve_runtime_contract(settings.agent_runtime_profile)
logger = logging.getLogger(__name__)
configure_logging(settings.log_level)
if not settings.agent_auth_token:
    raise RuntimeError("AGENT_AUTH_TOKEN is required")
if runtime_contract.requires_transit_stats_secret(settings.agent_role) and not settings.agent_stats_secret:
    raise RuntimeError("AGENT_STATS_SECRET is required for Transit Hysteria health checks")
ensure_agent_dirs(settings)
state_store = AgentStateStore(Path(settings.agent_data_root))
register_agent_metrics(settings)


def _agent_cors_origins() -> list[str]:
    origins: list[str] = []
    for raw in settings.agent_cors_origins or []:
        origin = str(raw or "").strip().rstrip("/")
        if origin:
            origins.append(origin)
    return origins


def _startup_reconcile() -> None:
    """
    Rebuild runtime configs from on-disk artifacts on process start.

    This prevents empty user lists after pod/node restarts when no fresh outbox events
    are delivered immediately.
    """
    reconcile_result = _reconcile_all_result(settings)
    changed = set(reconcile_result.changed)
    if not changed:
        return

    # Startup may materialize structural Xray changes (e.g. new inbounds/tags).
    # Apply them immediately even in API mode so gRPC sync has matching inbounds.
    commands = _reload_commands_for_changed(settings, changed, force_xray_reload=True)

    for cmd in commands:
        if not cmd:
            continue
        ok, out = run_command(cmd, settings.agent_dry_run)
        if ok:
            continue
        details = (out or "").strip() or "no output"
        raise RuntimeError(f"startup reconcile reload failed for `{cmd}`: {details}")


_startup_reconcile()


class DecoyMTProtoAuthRequest(BaseModel):
    login: str | None = None
    password: str | None = None


class DecoyLoginResponse(BaseModel):
    ok: bool
    redirect: str | None = None


class DecoySessionResponse(BaseModel):
    ok: bool
    redirect: str | None = None


class DecoyMTProtoAuthResponse(BaseModel):
    ok: bool
    profile: dict | None = None


class HysteriaAuthRequest(BaseModel):
    addr: str | None = None
    auth: str | None = None
    tx: int | None = None


class HysteriaAuthResponse(BaseModel):
    ok: bool
    id: str | None = None


class AgentMTProtoAccessIssueRequest(BaseModel):
    telegram_id: int
    label: str | None = None
    rotate: bool = False
    issued_by: str | None = None


class AgentMTProtoAccessResponse(BaseModel):
    ok: bool
    profile: dict | None = None
    changed: bool = False


class AgentMTProtoAccessListResponse(BaseModel):
    ok: bool
    entries: list[dict]


class AgentMTProtoAccessRevokeResponse(BaseModel):
    ok: bool
    removed: bool


def _sanitize_mtproto_access_entry(entry: dict) -> dict:
    payload = {
        "telegramId": int(entry.get("telegramId") or 0),
        "issuedAt": str(entry.get("issuedAt") or ""),
        "updatedAt": str(entry.get("updatedAt") or ""),
    }
    label = str(entry.get("label") or "").strip()
    if label:
        payload["label"] = label
    issued_by = str(entry.get("issuedBy") or "").strip()
    if issued_by:
        payload["issuedBy"] = issued_by
    return payload


def _is_loopback_host(host: str | None) -> bool:
    raw = str(host or "").strip()
    if not raw:
        return False
    try:
        return ip_address(raw).is_loopback
    except ValueError:
        return raw == "localhost"


def _app_version() -> str:
    try:
        return pkg_version("tracegate")
    except PackageNotFoundError:
        return "dev"
    except Exception:
        return "unknown"


def _cookie_secure(request: Request) -> bool:
    xf_proto = (request.headers.get("x-forwarded-proto") or "").strip().lower()
    if xf_proto in {"https", "wss"}:
        return True
    return request.url.scheme == "https"


def _forwarded_ip(request: Request) -> str:
    forwarded = (request.headers.get("x-forwarded-for") or "").strip()
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.client.host if request.client is not None else ""


def _forwarded_user_agent(request: Request) -> str:
    return (request.headers.get("user-agent") or "").strip()


def _hysteria_auth_candidates(row: dict) -> tuple[set[str], str]:
    cfg = row.get("config")
    if not isinstance(cfg, dict):
        return set(), ""
    auth = cfg.get("auth")
    if not isinstance(auth, dict):
        return set(), ""

    username = str(auth.get("username") or auth.get("client_id") or "").strip()
    password = str(auth.get("password") or "").strip()
    token = str(auth.get("token") or auth.get("value") or "").strip()
    client_id = str(auth.get("client_id") or username or token).strip()

    candidates = {value for value in (token, str(auth.get("auth") or "").strip()) if value}
    if username and password:
        candidates.add(f"{username}:{password}")
        # Some Hysteria2 URI importers split `user:password` userinfo and send
        # only the password as the auth string. Keep accepting the canonical
        # combined auth above, but tolerate the password-only form for client
        # interoperability.
        candidates.add(password)
    return candidates, client_id


def _match_hysteria_auth(auth_value: str) -> str:
    requested = str(auth_value or "").strip()
    if not requested:
        return ""

    paths = AgentPaths.from_settings(settings)
    for row in load_all_user_artifacts(paths):
        if str(row.get("protocol") or "").strip().lower() != "hysteria2":
            continue
        if not _artifact_applies_to_role(settings, row):
            continue
        candidates, client_id = _hysteria_auth_candidates(row)
        if requested in candidates:
            return client_id or requested
    return ""


def _decoy_session_or_401(request: Request) -> dict:
    if not decoy_auth_is_configured(settings):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    raw_cookie = request.cookies.get(str(settings.transit_decoy_auth_cookie_name or "").strip() or "tg_decoy_session") or ""
    session = load_decoy_session(settings, raw_cookie)
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Decoy session required")
    return session


def _apply_mtproto_reload() -> None:
    command = effective_mtproto_reload_cmd(settings)
    if not command:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="MTProto reload command is not configured")
    ok, output = run_command(command, settings.agent_dry_run)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(output or "").strip() or "MTProto reload failed",
        )


def _mtproto_reload_required_for_profile(profile: dict) -> bool:
    secret_policy = str(profile.get("secretPolicy") or "").strip().lower()
    if secret_policy == "shared":
        return False
    if secret_policy:
        return True
    if profile.get("perUserSecrets") is False:
        return False
    return True


def _mtproto_reload_required_for_current_profile() -> bool:
    try:
        profile = load_mtproto_public_profile(settings)
    except Exception:
        return True
    return _mtproto_reload_required_for_profile(profile)


app = FastAPI(title="Tracegate Node Agent", version=_app_version())
app.add_middleware(
    CORSMiddleware,
    allow_origins=_agent_cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
    max_age=300,
)
install_http_observability(app, component="agent")


@app.get("/v1/live")
async def live() -> dict:
    return {"ok": True, "role": settings.agent_role, "version": _app_version()}


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


@app.get("/v1/mtproto/access", response_model=AgentMTProtoAccessListResponse, dependencies=[Depends(require_agent_token)])
async def list_mtproto_access() -> AgentMTProtoAccessListResponse:
    entries = load_mtproto_access_entries(settings)
    return AgentMTProtoAccessListResponse(ok=True, entries=[_sanitize_mtproto_access_entry(entry) for entry in entries])


@app.post(
    "/v1/mtproto/access/issue",
    response_model=AgentMTProtoAccessResponse,
    dependencies=[Depends(require_agent_token)],
)
async def issue_mtproto_access(payload: AgentMTProtoAccessIssueRequest) -> AgentMTProtoAccessResponse:
    try:
        profile, _previous_entries, _next_entries, changed = issue_mtproto_access_profile(
            settings,
            telegram_id=int(payload.telegram_id),
            label=str(payload.label or "").strip(),
            issued_by=str(payload.issued_by or "").strip(),
            rotate=bool(payload.rotate),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="MTProto profile is unavailable") from exc
    except DecoyAuthConfigError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc

    # MTProto access issuance is part of the user lifecycle. Do not reload the
    # MTProto binary here; production profiles must use shared/live-readable
    # credentials if they need zero-drop issuance.

    logger.info(
        "mtproto_access_issued telegram_id=%s changed=%s rotate=%s",
        payload.telegram_id,
        changed,
        payload.rotate,
    )
    return AgentMTProtoAccessResponse(ok=True, profile=profile, changed=changed)


@app.delete(
    "/v1/mtproto/access/{telegram_id}",
    response_model=AgentMTProtoAccessRevokeResponse,
    dependencies=[Depends(require_agent_token)],
)
async def revoke_mtproto_access_profile(telegram_id: int) -> AgentMTProtoAccessRevokeResponse:
    try:
        removed, _previous_entries, _next_entries = revoke_mtproto_access(settings, telegram_id=int(telegram_id))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    if removed is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="MTProto access profile not found")

    # Revocation must not reload the MTProto binary. The no-reload contract is
    # enforced at the access layer instead of by restarting the service.

    logger.info("mtproto_access_revoked telegram_id=%s", telegram_id)
    return AgentMTProtoAccessRevokeResponse(ok=True, removed=True)


@app.post("/v1/decoy/mtproto", response_model=DecoyMTProtoAuthResponse)
async def decoy_mtproto_auth(payload: DecoyMTProtoAuthRequest, request: Request) -> DecoyMTProtoAuthResponse:
    if not decoy_auth_is_configured(settings):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    if not verify_decoy_credentials(settings, login=payload.login or "", password=payload.password or ""):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    try:
        profile = load_mtproto_public_profile(settings)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="MTProto profile is unavailable") from exc
    except DecoyAuthConfigError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc

    logger.info(
        "decoy_mtproto_legacy_fetch ip=%s ua=%r",
        _forwarded_ip(request),
        _forwarded_user_agent(request),
    )
    return DecoyMTProtoAuthResponse(ok=True, profile=profile)


@app.post("/v1/hysteria/auth", response_model=HysteriaAuthResponse)
async def hysteria_http_auth(payload: HysteriaAuthRequest, request: Request) -> HysteriaAuthResponse:
    client_host = request.client.host if request.client is not None else ""
    if not _is_loopback_host(client_host):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    client_id = _match_hysteria_auth(payload.auth or "")
    if not client_id:
        logger.warning("hysteria_auth_rejected addr=%s", str(payload.addr or "").strip())
        return HysteriaAuthResponse(ok=False)

    return HysteriaAuthResponse(ok=True, id=client_id)


@app.post("/v1/decoy/login", response_model=DecoyLoginResponse)
async def decoy_login(payload: DecoyMTProtoAuthRequest, request: Request) -> Response:
    if not decoy_auth_is_configured(settings):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    remote_ip = _forwarded_ip(request)
    user_agent = _forwarded_user_agent(request)
    if not verify_decoy_credentials(settings, login=payload.login or "", password=payload.password or ""):
        logger.warning("decoy_login_rejected ip=%s ua=%r", remote_ip, user_agent)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    response = JSONResponse(
        {
            "ok": True,
            "redirect": str(settings.transit_decoy_secret_path or "").strip() or "/vault/mtproto/",
        }
    )
    response.set_cookie(
        str(settings.transit_decoy_auth_cookie_name or "").strip() or "tg_decoy_session",
        build_decoy_session_cookie(settings),
        httponly=True,
        secure=_cookie_secure(request),
        samesite="lax",
        max_age=int(settings.transit_decoy_auth_session_ttl_seconds),
        path="/",
    )
    logger.info("decoy_login_ok ip=%s ua=%r", remote_ip, user_agent)
    return response


@app.post("/v1/decoy/logout")
async def decoy_logout(request: Request) -> Response:
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(str(settings.transit_decoy_auth_cookie_name or "").strip() or "tg_decoy_session", path="/")
    return response


@app.get("/v1/decoy/session", response_model=DecoySessionResponse)
async def decoy_session(request: Request) -> DecoySessionResponse:
    session = load_decoy_session(
        settings,
        request.cookies.get(str(settings.transit_decoy_auth_cookie_name or "").strip() or "tg_decoy_session") or "",
    )
    return DecoySessionResponse(
        ok=bool(session),
        redirect=(str(settings.transit_decoy_secret_path or "").strip() or "/vault/mtproto/") if session else None,
    )


@app.get("/v1/decoy/check")
async def decoy_check(request: Request) -> Response:
    _decoy_session_or_401(request)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/v1/decoy/mtproto", response_model=DecoyMTProtoAuthResponse)
async def decoy_mtproto_profile(request: Request) -> DecoyMTProtoAuthResponse:
    _decoy_session_or_401(request)
    try:
        profile = load_mtproto_public_profile(settings)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="MTProto profile is unavailable") from exc
    except DecoyAuthConfigError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc

    logger.info(
        "decoy_mtproto_session_fetch ip=%s ua=%r",
        _forwarded_ip(request),
        _forwarded_user_agent(request),
    )
    return DecoyMTProtoAuthResponse(ok=True, profile=profile)


@app.get("/v1/decoy/github/frame")
async def decoy_github_frame(request: Request) -> HTMLResponse:
    try:
        html = await load_github_repo_frame_html(settings)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="GitHub frame is unavailable") from exc
    return HTMLResponse(
        html,
        headers={"Cache-Control": f"public, max-age={max(30, int(settings.transit_decoy_github_cache_ttl_seconds or 300))}"},
    )


@app.get("/v1/health", response_model=AgentHealthResponse)
async def health(response: Response) -> AgentHealthResponse:
    rows = await gather_health_checks(
        settings.agent_stats_url,
        settings.agent_stats_secret,
        settings.agent_role,
        settings.agent_runtime_mode,
        settings.agent_runtime_profile,
    )
    checks = [AgentHealthCheckResult(**row) for row in rows]
    overall_ok = all(row["ok"] for row in rows)
    if not overall_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return AgentHealthResponse(role=settings.agent_role, checks=checks, overall_ok=overall_ok)


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
