from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse, StreamingResponse
from pydantic import BaseModel
from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.api.deps import db_session
from tracegate.enums import UserRole
from tracegate.models import GrafanaOtp, User
from tracegate.security import require_internal_api_token
from tracegate.settings import get_settings

router = APIRouter(prefix="/grafana", tags=["grafana"])


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
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="GRAFANA_COOKIE_SECRET is not set")
    return secret


def _session_cookie_value(*, telegram_id: int, ttl_seconds: int, scope: GrafanaSessionScope) -> str:
    now = int(datetime.now(timezone.utc).timestamp())
    payload = {"telegram_id": int(telegram_id), "exp": now + int(ttl_seconds), "scope": scope.value}
    return _sign(payload, _cookie_secret())


def _session_data_from_cookie(raw: str) -> tuple[int, GrafanaSessionScope] | None:
    payload = _verify(raw, _cookie_secret())
    if not payload:
        return None
    try:
        exp = int(payload.get("exp") or 0)
        telegram_id = int(payload.get("telegram_id") or 0)
        scope_raw = str(payload.get("scope") or GrafanaSessionScope.USER.value).strip().lower()
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
    login = str(telegram_id)

    async with httpx.AsyncClient(base_url=base_url, auth=(settings.grafana_admin_user, settings.grafana_admin_password), timeout=10) as client:
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
                json={"name": login, "email": f"{login}@tracegate.local", "login": login, "password": password},
            )
            if create.status_code in {200, 201}:
                body = create.json()
                user_id = int(body.get("id") or 0) or None
        if not user_id:
            return

        # Set role within the current org.
        await client.patch(f"/api/org/users/{user_id}", json={"role": target_role})


@router.post("/otp", response_model=GrafanaOtpCreated, dependencies=[Depends(require_internal_api_token)])
async def create_grafana_otp(payload: GrafanaOtpCreate, session: AsyncSession = Depends(db_session)) -> GrafanaOtpCreated:
    settings = get_settings()
    if not settings.grafana_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Grafana is disabled")

    user = await session.get(User, payload.telegram_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    requested_scope_raw = str(payload.scope or GrafanaSessionScope.USER.value).strip().lower()
    requested_scope = GrafanaSessionScope.ADMIN if requested_scope_raw == GrafanaSessionScope.ADMIN.value else GrafanaSessionScope.USER
    is_admin_role = user.role in {UserRole.ADMIN, UserRole.SUPERADMIN}
    effective_scope = GrafanaSessionScope.ADMIN if (requested_scope == GrafanaSessionScope.ADMIN and is_admin_role) else GrafanaSessionScope.USER

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

    row = GrafanaOtp(telegram_id=user.telegram_id, code_hash=code_hash, expires_at=expires_at, used_at=None, created_at=now)
    session.add(row)
    await session.commit()

    public = settings.public_base_url.rstrip("/")
    if not public:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="PUBLIC_BASE_URL is not set")
    login_url = f"{public}/grafana/login?code={code}&scope={effective_scope.value}"
    return GrafanaOtpCreated(code=code, expires_at=expires_at, login_url=login_url, scope=effective_scope.value)


@router.get("/login")
async def grafana_login(
    request: Request,
    code: str = Query(min_length=8),
    scope: str = Query(default=GrafanaSessionScope.USER.value),
    session: AsyncSession = Depends(db_session),
) -> Response:
    settings = get_settings()
    if not settings.grafana_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Grafana is disabled")

    now = datetime.now(timezone.utc)
    code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
    row = await session.scalar(select(GrafanaOtp).where(GrafanaOtp.code_hash == code_hash))
    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid OTP")
    if row.expires_at < now:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="OTP expired")

    user = await session.get(User, row.telegram_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    is_admin_role = user.role in {UserRole.ADMIN, UserRole.SUPERADMIN}
    requested_scope = str(scope or GrafanaSessionScope.USER.value).strip().lower()
    session_scope = GrafanaSessionScope.ADMIN if (requested_scope == GrafanaSessionScope.ADMIN.value and is_admin_role) else GrafanaSessionScope.USER

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
    landing = "/grafana/d/tracegate-admin/tracegate-admin" if session_scope == GrafanaSessionScope.ADMIN else "/grafana/d/tracegate-user/tracegate-user"
    resp = RedirectResponse(url=landing, status_code=status.HTTP_302_FOUND)
    resp.set_cookie(
        "tg_grafana_session",
        cookie_value,
        httponly=True,
        secure=_cookie_secure(request),
        samesite="lax",
        path="/grafana",
        max_age=int(settings.grafana_session_ttl_seconds),
    )
    return resp


@router.get("/logout")
async def grafana_logout(request: Request) -> Response:
    resp = RedirectResponse(url="/grafana/", status_code=status.HTTP_302_FOUND)
    resp.delete_cookie("tg_grafana_session", path="/grafana")
    return resp


@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def grafana_proxy(path: str, request: Request, session: AsyncSession = Depends(db_session)) -> Response:
    settings = get_settings()
    if not settings.grafana_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Grafana is disabled")

    raw = request.cookies.get("tg_grafana_session") or ""
    session_data = _session_data_from_cookie(raw)
    if not session_data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Grafana session required (get OTP in bot)")
    telegram_id, session_scope = session_data
    # Resolve role for each request to avoid stale privileges after role changes.
    user = await session.get(User, telegram_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    is_admin_role = user.role in {UserRole.ADMIN, UserRole.SUPERADMIN}
    admin_scope = session_scope == GrafanaSessionScope.ADMIN and is_admin_role

    upstream = settings.grafana_internal_url.rstrip("/")
    if not upstream:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="GRAFANA_INTERNAL_URL is not set")

    normalized_path = (path or "").lstrip("/")
    admin_only_prefixes = (
        "d/tracegate-admin",
        "d-solo/tracegate-admin",
        "api/dashboards/uid/tracegate-admin",
        "api/folders/tracegate-admin",
        "dashboards/f/tracegate-admin",
    )
    if not admin_scope and normalized_path.startswith(admin_only_prefixes):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin dashboard scope required")

    if not normalized_path:
        landing = "/grafana/d/tracegate-admin/tracegate-admin" if admin_scope else "/grafana/d/tracegate-user/tracegate-user"
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
    headers["x-webauth-user"] = str(telegram_id)
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
                and str(row.get("uid") or "") != "tracegate-admin"
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
        if k.lower() not in {"content-encoding", "transfer-encoding", "connection"}
    }
    return StreamingResponse(
        content=r.aiter_bytes(),
        status_code=r.status_code,
        headers=response_headers,
        media_type=r.headers.get("content-type"),
    )
