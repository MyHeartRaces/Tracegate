from __future__ import annotations

import asyncio
import base64
import hashlib
import html
import hmac
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any
from urllib.parse import quote

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import BaseModel
from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.api.deps import db_session
from tracegate.cli.grafana_bootstrap import bootstrap_with_config
from tracegate.enums import ApiScope, UserRole
from tracegate.models import GrafanaOtp, User
from tracegate.security import require_api_scope, require_bootstrap_token
from tracegate.settings import get_settings
from tracegate.services.pseudonym import user_pid

router = APIRouter(prefix="/grafana", tags=["grafana"])
logger = logging.getLogger(__name__)

_TELEGRAM_API_BASE = "https://api.telegram.org"


class GrafanaOtpCreate(BaseModel):
    telegram_id: int
    scope: str = "user"


class GrafanaOtpCreated(BaseModel):
    code: str
    expires_at: datetime
    login_url: str
    scope: str


class GrafanaSessionScope(str, Enum):
    USER = "user"
    ADMIN = "admin"


class GrafanaBootstrapResult(BaseModel):
    ok: bool
    operator_dashboard_uid: str
    slo_rule_count: int
    contact_point_uid: str | None = None


class GrafanaAlertWebhookAccepted(BaseModel):
    ok: bool
    recipients: int
    alerts: int
    status: str


def _grafana_otp_handoff_url() -> str:
    configured = (get_settings().grafana_otp_handoff_url or "").strip()
    if configured:
        return configured
    return "/"


def _grafana_public_base_url(settings=None) -> str:
    settings = settings or get_settings()
    return (settings.grafana_public_base_url or settings.public_base_url or "").rstrip(
        "/"
    )


def _grafana_otp_login_url(
    *, public_base_url: str, code: str, scope: GrafanaSessionScope
) -> str:
    code_path = quote(str(code or "").strip(), safe="")
    scope_path = quote(str(scope.value), safe="")
    return f"{public_base_url.rstrip('/')}/grafana/otp/{code_path}/{scope_path}"


def _grafana_login_problem_response(
    *, title: str, message: str, status_code: int = status.HTTP_401_UNAUTHORIZED
) -> HTMLResponse:
    bot_url = _grafana_otp_handoff_url()
    bot_link = ""
    if bot_url and bot_url != "/":
        bot_link = f'<p><a href="{html.escape(bot_url, quote=True)}">Open Tracegate bot</a></p>'
    body = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <meta name="robots" content="noindex,nofollow" />
    <title>{html.escape(title)}</title>
    <style>
      body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; background: #0d1117; color: #e6edf3; font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
      main {{ width: min(520px, calc(100vw - 48px)); }}
      h1 {{ font-size: 22px; line-height: 1.2; margin: 0 0 12px; }}
      p {{ color: #9da7b3; line-height: 1.55; margin: 0 0 16px; }}
      a {{ color: #58a6ff; }}
    </style>
  </head>
  <body>
    <main>
      <h1>{html.escape(title)}</h1>
      <p>{html.escape(message)}</p>
      {bot_link}
    </main>
  </body>
</html>"""
    return HTMLResponse(content=body, status_code=status_code)


def _grafana_landing_url(*, admin_scope: bool) -> str:
    if admin_scope:
        return "/grafana/d/tracegate-admin-dashboard/tracegate-admin-dashboard"
    return "/grafana/d/tracegate-user/tracegate-user"


def _grafana_session_established_response(
    *,
    request: Request,
    cookie_value: str,
    landing: str,
    ttl_seconds: int,
) -> Response:
    if request.method.upper() == "HEAD":
        resp: Response = Response(
            status_code=status.HTTP_204_NO_CONTENT, headers={"location": landing}
        )
    else:
        landing_attr = html.escape(landing, quote=True)
        landing_js = json.dumps(landing)
        body = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <meta name="robots" content="noindex,nofollow" />
    <meta http-equiv="refresh" content="0;url={landing_attr}" />
    <title>Opening Grafana</title>
    <style>
      body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; background: #0d1117; color: #e6edf3; font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
      main {{ width: min(520px, calc(100vw - 48px)); }}
      p {{ color: #9da7b3; line-height: 1.55; margin: 0 0 16px; }}
      a {{ color: #58a6ff; }}
    </style>
  </head>
  <body>
    <main>
      <p>Opening Grafana...</p>
      <p><a href="{landing_attr}">Continue</a></p>
    </main>
    <script>window.location.replace({landing_js});</script>
  </body>
</html>"""
        resp = HTMLResponse(content=body, status_code=status.HTTP_200_OK)
    resp.set_cookie(
        "tg_grafana_session",
        cookie_value,
        httponly=True,
        secure=_cookie_secure(request),
        samesite="lax",
        path="/grafana",
        max_age=int(ttl_seconds),
    )
    return resp


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _sign(payload: dict[str, Any], secret: str) -> str:
    data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), data, hashlib.sha256).digest()
    return f"{_b64url(data)}.{_b64url(sig)}"


def _verify(token: str, secret: str) -> dict[str, Any] | None:
    try:
        data_b64, sig_b64 = token.split(".", 1)
        data = _b64url_decode(data_b64)
        sig = _b64url_decode(sig_b64)
    except Exception:
        return None
    expected = hmac.new(secret.encode("utf-8"), data, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, sig):
        return None
    try:
        payload = json.loads(data.decode("utf-8"))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _cookie_secure(request: Request) -> bool:
    # Respect reverse proxies if they set X-Forwarded-Proto.
    xf_proto = (request.headers.get("x-forwarded-proto") or "").strip().lower()
    if xf_proto in {"https", "wss"}:
        return True
    return request.url.scheme == "https"


def _cookie_secret() -> str:
    secret = (get_settings().grafana_cookie_secret or "").strip()
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GRAFANA_COOKIE_SECRET is not set",
        )
    return secret


def _session_cookie_value(
    *, telegram_id: int, ttl_seconds: int, scope: GrafanaSessionScope
) -> str:
    now = int(datetime.now(timezone.utc).timestamp())
    payload = {
        "telegram_id": int(telegram_id),
        "exp": now + int(ttl_seconds),
        "scope": scope.value,
    }
    return _sign(payload, _cookie_secret())


def _session_data_from_cookie(raw: str) -> tuple[int, GrafanaSessionScope] | None:
    payload = _verify(raw, _cookie_secret())
    if not payload:
        return None
    try:
        exp = int(payload.get("exp") or 0)
        telegram_id = int(payload.get("telegram_id") or 0)
        scope_raw = (
            str(payload.get("scope") or GrafanaSessionScope.USER.value).strip().lower()
        )
        scope = GrafanaSessionScope(scope_raw)
    except Exception:
        return None
    now = int(datetime.now(timezone.utc).timestamp())
    if exp <= now:
        return None
    if not telegram_id:
        return None
    return telegram_id, scope


async def _ensure_grafana_user_role(telegram_id: int, role: UserRole) -> None:
    settings = get_settings()
    if not settings.grafana_enabled:
        return
    base_url = settings.grafana_internal_url.rstrip("/")
    if not base_url:
        return
    if not settings.grafana_admin_password:
        return

    # Org role: keep normal users as Viewer; admins/superadmins as Admin.
    target_role = "Admin" if role in {UserRole.ADMIN, UserRole.SUPERADMIN} else "Viewer"
    login = user_pid(settings, telegram_id)

    async with httpx.AsyncClient(
        base_url=base_url,
        auth=(settings.grafana_admin_user, settings.grafana_admin_password),
        timeout=10,
    ) as client:
        user_id: int | None = None
        r = await client.get("/api/users/lookup", params={"loginOrEmail": login})
        if r.status_code == 200:
            body = r.json()
            user_id = int(body.get("id"))
        elif r.status_code == 404:
            # Create user proactively so we can set role before the first login.
            password = secrets.token_urlsafe(24)
            create = await client.post(
                "/api/admin/users",
                json={
                    "name": login,
                    "email": f"{login}@tracegate.local",
                    "login": login,
                    "password": password,
                },
            )
            if create.status_code in {200, 201}:
                body = create.json()
                user_id = int(body.get("id") or 0) or None
        if not user_id:
            return

        # Set role within the current org.
        await client.patch(f"/api/org/users/{user_id}", json={"role": target_role})


async def _load_admin_chat_ids(session: AsyncSession) -> list[int]:
    settings = get_settings()
    ids: set[int] = set(
        int(x) for x in (settings.superadmin_telegram_ids or []) if int(x) > 0
    )
    rows = (
        (
            await session.execute(
                select(User.telegram_id).where(
                    User.role.in_([UserRole.ADMIN, UserRole.SUPERADMIN])
                )
            )
        )
        .scalars()
        .all()
    )
    ids.update(int(row) for row in rows if int(row) > 0)
    return sorted(ids)


async def _send_telegram_message(
    *,
    http_client: httpx.AsyncClient,
    bot_token: str,
    chat_id: int,
    text: str,
) -> bool:
    url = f"{_TELEGRAM_API_BASE}/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": int(chat_id),
        "text": (text or "").strip()[:4000],
        "disable_web_page_preview": True,
    }
    for attempt in range(2):
        try:
            r = await http_client.post(url, json=payload)
            if r.status_code == 429 and attempt == 0:
                retry_after = 1
                try:
                    retry_after = int(
                        (r.json().get("parameters") or {}).get("retry_after") or 1
                    )
                except Exception:
                    retry_after = 1
                await asyncio.sleep(max(1, min(5, retry_after)))
                continue
            r.raise_for_status()
            return bool((r.json() or {}).get("ok"))
        except Exception:
            logger.exception(
                "grafana_alert_webhook_telegram_send_failed chat_id=%s", chat_id
            )
            return False
    return False


def _format_grafana_alert_webhook_message(
    payload: dict[str, Any],
) -> tuple[str, int, str]:
    status_raw = str(payload.get("status") or "unknown").strip().lower()
    alerts = payload.get("alerts")
    alert_list = alerts if isinstance(alerts, list) else []
    common_labels = (
        payload.get("commonLabels")
        if isinstance(payload.get("commonLabels"), dict)
        else {}
    )
    common_annotations = (
        payload.get("commonAnnotations")
        if isinstance(payload.get("commonAnnotations"), dict)
        else {}
    )

    title = (
        str(common_annotations.get("summary") or "").strip()
        or str(common_labels.get("alertname") or "").strip()
        or "Grafana alert"
    )
    status_label = status_raw or "unknown"
    status_header = {
        "firing": "🚨 Grafana Alert",
        "resolved": "✅ Grafana Recovered",
    }.get(status_raw, "ℹ️ Grafana Alert")
    lines = [
        status_header,
        "",
        title,
        "",
        f"Status: {status_label}",
        f"Alerts: {len(alert_list)}",
    ]

    for alert in alert_list[:4]:
        if not isinstance(alert, dict):
            continue
        labels = alert.get("labels") if isinstance(alert.get("labels"), dict) else {}
        annotations = (
            alert.get("annotations")
            if isinstance(alert.get("annotations"), dict)
            else {}
        )
        component = str(labels.get("component") or "-")
        severity = str(labels.get("severity") or "-")
        alert_type = str(
            labels.get("slo_type")
            or labels.get("alert_type")
            or labels.get("category")
            or "-"
        )
        summary = str(
            annotations.get("summary") or labels.get("alertname") or "alert"
        ).strip()
        target_parts = _grafana_alert_target_parts(labels)
        lines.extend(
            [
                "",
                f"• {component} / {alert_type} ({severity})",
                f"  {summary}",
            ]
        )
        if target_parts:
            lines.append(f"  Target: {' / '.join(target_parts)}")
    if len(alert_list) > 4:
        lines.extend(["", f"… and {len(alert_list) - 4} more"])

    return ("\n".join(lines)).strip(), len(alert_list), status_raw


def _grafana_alert_webhook_has_critical(payload: dict[str, Any]) -> bool:
    alerts = payload.get("alerts")
    alert_list = alerts if isinstance(alerts, list) else []
    for alert in alert_list:
        if not isinstance(alert, dict):
            continue
        labels = alert.get("labels") if isinstance(alert.get("labels"), dict) else {}
        if str(labels.get("severity") or "").strip().lower() == "critical":
            return True

    common_labels = (
        payload.get("commonLabels")
        if isinstance(payload.get("commonLabels"), dict)
        else {}
    )
    return str(common_labels.get("severity") or "").strip().lower() == "critical"


def _grafana_alert_node_alias(node: str) -> str:
    normalized = (node or "").strip().lower()
    aliases = {
        "tracegate-entry": "entry",
        "tracegate-chain-transit": "transit",
        "tracegate-transit": "endpoint",
    }
    return aliases.get(normalized, normalized)


def _grafana_alert_target_parts(labels: dict[str, Any]) -> list[str]:
    node = str(labels.get("node") or "").strip()
    alias = _grafana_alert_node_alias(node)
    instance = str(labels.get("instance") or "").strip()
    pod = str(labels.get("pod") or "").strip()
    container = str(labels.get("container") or "").strip()
    job = str(labels.get("job") or "").strip()

    parts: list[str] = []
    if alias and alias != node:
        parts.append(alias)
    if node:
        parts.append(node)
    if instance:
        parts.append(instance)
    if pod:
        parts.append(pod)
    if container and container != "POD":
        parts.append(container)
    if job and not parts:
        parts.append(job)
    return parts


@router.post(
    "/otp",
    response_model=GrafanaOtpCreated,
    dependencies=[Depends(require_api_scope(ApiScope.GRAFANA_OTP))],
)
async def create_grafana_otp(
    payload: GrafanaOtpCreate, session: AsyncSession = Depends(db_session)
) -> GrafanaOtpCreated:
    settings = get_settings()
    if not settings.grafana_enabled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Grafana is disabled"
        )

    user = await session.get(User, payload.telegram_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    requested_scope_raw = (
        str(payload.scope or GrafanaSessionScope.USER.value).strip().lower()
    )
    requested_scope = (
        GrafanaSessionScope.ADMIN
        if requested_scope_raw == GrafanaSessionScope.ADMIN.value
        else GrafanaSessionScope.USER
    )
    is_admin_role = user.role in {UserRole.ADMIN, UserRole.SUPERADMIN}
    effective_scope = (
        GrafanaSessionScope.ADMIN
        if (requested_scope == GrafanaSessionScope.ADMIN and is_admin_role)
        else GrafanaSessionScope.USER
    )

    # Best-effort user provisioning in Grafana (role mapping is needed for admin dashboards).
    try:
        await _ensure_grafana_user_role(user.telegram_id, user.role)
    except Exception:
        pass

    # Clean up old OTPs for this user (keep table small).
    now = datetime.now(timezone.utc)
    await session.execute(
        delete(GrafanaOtp).where(
            GrafanaOtp.telegram_id == user.telegram_id,
            or_(GrafanaOtp.used_at.is_not(None), GrafanaOtp.expires_at < now),
        )
    )

    code = secrets.token_urlsafe(16)
    code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
    expires_at = now + timedelta(seconds=int(settings.grafana_otp_ttl_seconds))

    row = GrafanaOtp(
        telegram_id=user.telegram_id,
        code_hash=code_hash,
        expires_at=expires_at,
        used_at=None,
        created_at=now,
    )
    session.add(row)
    await session.commit()

    public = _grafana_public_base_url(settings)
    if not public:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GRAFANA_PUBLIC_BASE_URL or PUBLIC_BASE_URL is not set",
        )
    login_url = _grafana_otp_login_url(
        public_base_url=public, code=code, scope=effective_scope
    )
    return GrafanaOtpCreated(
        code=code,
        expires_at=expires_at,
        login_url=login_url,
        scope=effective_scope.value,
    )


async def _consume_grafana_otp(
    *,
    request: Request,
    code: str | None,
    scope: str,
    session: AsyncSession,
) -> Response:
    settings = get_settings()
    if not settings.grafana_enabled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Grafana is disabled"
        )

    code = str(code or "").strip()
    if len(code) < 8:
        existing_raw = request.cookies.get("tg_grafana_session") or ""
        existing_session = (
            _session_data_from_cookie(existing_raw) if existing_raw else None
        )
        if existing_session:
            existing_telegram_id, existing_scope = existing_session
            existing_user = await session.get(User, existing_telegram_id)
            if existing_user is not None:
                existing_is_admin = existing_user.role in {
                    UserRole.ADMIN,
                    UserRole.SUPERADMIN,
                }
                existing_admin_scope = (
                    existing_scope == GrafanaSessionScope.ADMIN and existing_is_admin
                )
                return RedirectResponse(
                    url=_grafana_landing_url(admin_scope=existing_admin_scope),
                    status_code=status.HTTP_302_FOUND,
                )
        return _grafana_login_problem_response(
            title="Grafana OTP required",
            message="Open Grafana from a fresh one-time link issued by the Tracegate bot.",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    now = datetime.now(timezone.utc)
    code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
    row = await session.scalar(
        select(GrafanaOtp).where(GrafanaOtp.code_hash == code_hash)
    )
    if row is None:
        return _grafana_login_problem_response(
            title="Grafana OTP rejected",
            message="This one-time link is invalid. Request a new Grafana link in the Tracegate bot.",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    if row.expires_at < now:
        return _grafana_login_problem_response(
            title="Grafana OTP expired",
            message="This one-time link is older than its allowed window. Request a new Grafana link in the Tracegate bot.",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    user = await session.get(User, row.telegram_id)
    if user is None:
        return _grafana_login_problem_response(
            title="Grafana user not found",
            message="Tracegate could not resolve this Grafana session. Open the bot and request a new link.",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    is_admin_role = user.role in {UserRole.ADMIN, UserRole.SUPERADMIN}
    requested_scope = str(scope or GrafanaSessionScope.USER.value).strip().lower()
    session_scope = (
        GrafanaSessionScope.ADMIN
        if (requested_scope == GrafanaSessionScope.ADMIN.value and is_admin_role)
        else GrafanaSessionScope.USER
    )

    # Telegram/CF preview bots may hit the login URL before the real user.
    # Keep login idempotent within OTP TTL so a prefetch does not burn the link.
    if row.used_at is None:
        row.used_at = now
        await session.commit()

    cookie_value = _session_cookie_value(
        telegram_id=row.telegram_id,
        ttl_seconds=int(settings.grafana_session_ttl_seconds),
        scope=session_scope,
    )
    landing = _grafana_landing_url(
        admin_scope=session_scope == GrafanaSessionScope.ADMIN
    )
    return _grafana_session_established_response(
        request=request,
        cookie_value=cookie_value,
        landing=landing,
        ttl_seconds=int(settings.grafana_session_ttl_seconds),
    )


@router.head("/login")
@router.get("/login")
async def grafana_login(
    request: Request,
    code: str | None = Query(default=None),
    scope: str = Query(default=GrafanaSessionScope.USER.value),
    session: AsyncSession = Depends(db_session),
) -> Response:
    return await _consume_grafana_otp(
        request=request, code=code, scope=scope, session=session
    )


@router.head("/otp/{code}")
@router.get("/otp/{code}")
@router.head("/otp/{code}/{scope}")
@router.get("/otp/{code}/{scope}")
async def grafana_login_path(
    request: Request,
    code: str,
    scope: str = GrafanaSessionScope.USER.value,
    session: AsyncSession = Depends(db_session),
) -> Response:
    return await _consume_grafana_otp(
        request=request, code=code, scope=scope, session=session
    )


@router.get("/logout")
async def grafana_logout(request: Request) -> Response:
    resp = RedirectResponse(url="/grafana/", status_code=status.HTTP_302_FOUND)
    resp.delete_cookie("tg_grafana_session", path="/grafana")
    return resp


@router.post(
    "/bootstrap/internal",
    response_model=GrafanaBootstrapResult,
    dependencies=[Depends(require_bootstrap_token)],
)
async def grafana_bootstrap_internal() -> GrafanaBootstrapResult:
    settings = get_settings()
    if not settings.grafana_enabled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Grafana is disabled"
        )
    if not settings.grafana_admin_password:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GRAFANA_ADMIN_PASSWORD is not set",
        )

    report = await bootstrap_with_config(
        base_url=settings.grafana_internal_url,
        admin_user=settings.grafana_admin_user or "admin",
        admin_password=settings.grafana_admin_password,
        prometheus_url=settings.dispatcher_ops_alerts_prometheus_url,
        slo_webhook_url=(settings.grafana_alerts_webhook_url or None),
        slo_webhook_token=(settings.grafana_alerts_webhook_token or None),
    )
    return GrafanaBootstrapResult(
        ok=True,
        operator_dashboard_uid=str(
            report.get("operator_dashboard_uid") or "tracegate-admin-ops"
        ),
        slo_rule_count=int(report.get("slo_rule_count") or 0),
        contact_point_uid=(
            str(report["contact_point_uid"])
            if report.get("contact_point_uid")
            else None
        ),
    )


@router.post("/alerting/webhook", response_model=GrafanaAlertWebhookAccepted)
async def grafana_alerting_webhook(
    request: Request,
    session: AsyncSession = Depends(db_session),
    token: str = Query(default=""),
) -> GrafanaAlertWebhookAccepted:
    settings = get_settings()
    expected = (settings.grafana_alerts_webhook_token or "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Grafana alert webhook is disabled",
        )
    if token != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid webhook token"
        )
    if not settings.bot_token:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="BOT_TOKEN is not configured",
        )

    try:
        raw = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON payload"
        ) from None
    payload = raw if isinstance(raw, dict) else {"payload": raw}

    text, alert_count, status_raw = _format_grafana_alert_webhook_message(payload)
    if not _grafana_alert_webhook_has_critical(payload):
        logger.info(
            "grafana_alert_webhook_non_critical_ignored alerts=%s status=%s",
            alert_count,
            status_raw or "unknown",
        )
        return GrafanaAlertWebhookAccepted(
            ok=True, recipients=0, alerts=alert_count, status=status_raw or "unknown"
        )

    recipients = await _load_admin_chat_ids(session)
    if not recipients:
        logger.warning("grafana_alert_webhook_no_recipients")
        return GrafanaAlertWebhookAccepted(
            ok=True, recipients=0, alerts=alert_count, status=status_raw or "unknown"
        )

    sent_ok = True
    timeout = httpx.Timeout(connect=5, read=10, write=10, pool=10)
    async with httpx.AsyncClient(timeout=timeout) as http_client:
        for chat_id in recipients:
            ok = await _send_telegram_message(
                http_client=http_client,
                bot_token=settings.bot_token,
                chat_id=chat_id,
                text=text,
            )
            sent_ok = sent_ok and ok
    if not sent_ok:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to deliver alert to one or more recipients",
        )
    return GrafanaAlertWebhookAccepted(
        ok=True,
        recipients=len(recipients),
        alerts=alert_count,
        status=status_raw or "unknown",
    )


@router.api_route(
    "/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
)
async def grafana_proxy(
    path: str, request: Request, session: AsyncSession = Depends(db_session)
) -> Response:
    settings = get_settings()
    if not settings.grafana_enabled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Grafana is disabled"
        )

    raw = request.cookies.get("tg_grafana_session") or ""
    session_data = _session_data_from_cookie(raw)
    if not session_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Grafana session required (get OTP in bot)",
        )
    telegram_id, session_scope = session_data
    # Resolve role for each request to avoid stale privileges after role changes.
    user = await session.get(User, telegram_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
        )
    is_admin_role = user.role in {UserRole.ADMIN, UserRole.SUPERADMIN}
    admin_scope = session_scope == GrafanaSessionScope.ADMIN and is_admin_role

    upstream = settings.grafana_internal_url.rstrip("/")
    if not upstream:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GRAFANA_INTERNAL_URL is not set",
        )

    normalized_path = (path or "").lstrip("/")
    admin_only_prefixes = (
        "d/tracegate-admin-dashboard",
        "d-solo/tracegate-admin-dashboard",
        "api/dashboards/uid/tracegate-admin-dashboard",
        "d/tracegate-admin",
        "d-solo/tracegate-admin",
        "api/dashboards/uid/tracegate-admin",
        "api/folders/tracegate-admin",
        "dashboards/f/tracegate-admin",
    )
    if not admin_scope and normalized_path.startswith(admin_only_prefixes):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin dashboard scope required",
        )

    if not normalized_path:
        landing = _grafana_landing_url(admin_scope=admin_scope)
        return RedirectResponse(url=landing, status_code=status.HTTP_302_FOUND)

    upstream_path = "/grafana" if not normalized_path else f"/grafana/{normalized_path}"
    url = upstream + upstream_path

    # Forward cookies except our own session marker.
    cookie_header = request.headers.get("cookie") or ""
    filtered_cookies = []
    for part in cookie_header.split(";"):
        k, sep, v = part.strip().partition("=")
        if not sep:
            continue
        if k == "tg_grafana_session":
            continue
        filtered_cookies.append(f"{k}={v}")
    out_cookie_header = "; ".join(filtered_cookies)

    headers = {
        k: v
        for (k, v) in request.headers.items()
        if k.lower()
        not in {
            "accept-encoding",
            "content-length",
            "cookie",
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
        }
    }
    headers["x-webauth-user"] = user_pid(settings, telegram_id)
    if out_cookie_header:
        headers["cookie"] = out_cookie_header

    body = await request.body()
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.request(
            method=request.method,
            url=url,
            headers=headers,
            params=request.query_params,
            content=body if body else None,
            follow_redirects=False,
        )
        raw_body = await r.aread()

    if not admin_scope and normalized_path == "api/search":
        try:
            body_json = r.json()
        except Exception:
            body_json = None
        if isinstance(body_json, list):
            filtered = [
                row
                for row in body_json
                if isinstance(row, dict)
                and str(row.get("uid") or "")
                not in {"tracegate-admin", "tracegate-admin-dashboard"}
                and str(row.get("folderUid") or "") != "tracegate-admin"
                and "tracegate-admin" not in str(row.get("url") or "")
            ]
            return Response(
                content=json.dumps(filtered, separators=(",", ":"), ensure_ascii=True),
                status_code=r.status_code,
                media_type="application/json",
            )

    response_headers = {
        k: v
        for (k, v) in r.headers.items()
        if k.lower()
        not in {
            "content-encoding",
            "transfer-encoding",
            "connection",
            "content-length",
            "content-type",
            "date",
            "server",
        }
    }
    return Response(
        content=raw_body,
        status_code=r.status_code,
        headers=response_headers,
        media_type=r.headers.get("content-type"),
    )
