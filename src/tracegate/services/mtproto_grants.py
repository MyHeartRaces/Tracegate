from __future__ import annotations

from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.enums import EntitlementStatus, NodeRole, RecordStatus
from tracegate.models import MTProtoAccessGrant, NodeEndpoint, User
from tracegate.settings import Settings


class MTProtoGrantError(RuntimeError):
    def __init__(self, *, status_code: int, detail: str) -> None:
        self.status_code = int(status_code)
        self.detail = detail
        super().__init__(detail)


def _http_client_kwargs(settings: Settings) -> dict:
    cert = None
    if settings.dispatcher_client_cert and settings.dispatcher_client_key:
        cert = (settings.dispatcher_client_cert, settings.dispatcher_client_key)
    return {
        "cert": cert,
        "verify": settings.dispatcher_ca_cert or True,
        "timeout": 20,
    }


def _detail_from_response(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except Exception:
        payload = None
    if isinstance(payload, dict):
        detail = str(payload.get("detail") or "").strip()
        if detail:
            return detail
    return (response.text or "").strip() or f"Transit agent request failed with status {response.status_code}"


async def _request_transit_agent(
    settings: Settings,
    *,
    node: NodeEndpoint,
    method: str,
    path: str,
    json_payload: dict | None = None,
) -> dict:
    if not settings.agent_auth_token:
        raise MTProtoGrantError(status_code=500, detail="AGENT_AUTH_TOKEN is not configured")

    url = f"{node.base_url.rstrip('/')}{path}"
    async with httpx.AsyncClient(**_http_client_kwargs(settings)) as client:
        response = await client.request(
            method,
            url,
            json=json_payload,
            headers={"x-agent-token": settings.agent_auth_token},
        )
    if response.status_code >= 400:
        raise MTProtoGrantError(status_code=response.status_code, detail=_detail_from_response(response))
    if response.status_code == 204:
        return {}
    payload = response.json()
    return payload if isinstance(payload, dict) else {}


async def resolve_transit_node(session: AsyncSession) -> NodeEndpoint:
    rows = (
        await session.execute(
            select(NodeEndpoint)
            .where(NodeEndpoint.active.is_(True), NodeEndpoint.role == NodeRole.TRANSIT)
            .order_by(NodeEndpoint.created_at.asc(), NodeEndpoint.name.asc())
        )
    ).scalars().all()
    if not rows:
        raise MTProtoGrantError(status_code=503, detail="Active Transit node is not configured")
    if len(rows) > 1:
        raise MTProtoGrantError(status_code=409, detail="Multiple active Transit nodes are configured")
    return rows[0]


def default_mtproto_label(user: User) -> str | None:
    username = str(user.telegram_username or "").strip()
    if username:
        return f"@{username.lstrip('@')}"
    full_name = " ".join(
        part for part in [str(user.telegram_first_name or "").strip(), str(user.telegram_last_name or "").strip()] if part
    ).strip()
    if full_name:
        return full_name[:128]
    return None


async def issue_mtproto_grant(
    session: AsyncSession,
    *,
    settings: Settings,
    telegram_id: int,
    label: str | None = None,
    rotate: bool = False,
    issued_by: str | None = None,
) -> tuple[MTProtoAccessGrant, dict, bool, str]:
    user = await session.get(User, telegram_id)
    if user is None:
        raise MTProtoGrantError(status_code=404, detail="User not found")
    if user.entitlement_status == EntitlementStatus.BLOCKED:
        raise MTProtoGrantError(status_code=403, detail="User entitlement is blocked")

    node = await resolve_transit_node(session)
    effective_label = str(label or "").strip() or default_mtproto_label(user)
    effective_issued_by = str(issued_by or "").strip()
    payload = {
        "telegram_id": int(telegram_id),
        "label": effective_label,
        "rotate": bool(rotate),
        "issued_by": effective_issued_by,
    }
    response = await _request_transit_agent(
        settings,
        node=node,
        method="POST",
        path="/v1/mtproto/access/issue",
        json_payload=payload,
    )
    profile = response.get("profile")
    if not isinstance(profile, dict):
        raise MTProtoGrantError(status_code=502, detail="Transit agent returned invalid MTProto profile payload")

    now = datetime.now(timezone.utc)
    grant = await session.get(MTProtoAccessGrant, telegram_id)
    if grant is None:
        grant = MTProtoAccessGrant(
            telegram_id=int(telegram_id),
            status=RecordStatus.ACTIVE,
            label=effective_label,
            issued_by=effective_issued_by or None,
            last_sync_at=now,
        )
        session.add(grant)
    else:
        grant.status = RecordStatus.ACTIVE
        grant.label = effective_label
        grant.issued_by = effective_issued_by or None
        grant.last_sync_at = now

    return grant, profile, bool(response.get("changed", False)), node.name


async def revoke_mtproto_grant(
    session: AsyncSession,
    *,
    settings: Settings,
    telegram_id: int,
    ignore_missing: bool = False,
) -> tuple[MTProtoAccessGrant | None, bool, str]:
    grant = await session.get(MTProtoAccessGrant, telegram_id)
    node = await resolve_transit_node(session)

    removed_remote = False
    try:
        response = await _request_transit_agent(
            settings,
            node=node,
            method="DELETE",
            path=f"/v1/mtproto/access/{int(telegram_id)}",
        )
        removed_remote = bool(response.get("removed", True))
    except MTProtoGrantError as exc:
        if exc.status_code != 404 or not ignore_missing:
            raise

    had_local = grant is not None and grant.status == RecordStatus.ACTIVE
    if grant is not None:
        grant.status = RecordStatus.REVOKED
        grant.last_sync_at = datetime.now(timezone.utc)

    removed = bool(had_local or removed_remote)
    if not removed and not ignore_missing:
        raise MTProtoGrantError(status_code=404, detail="MTProto access grant not found")
    return grant, removed, node.name
