from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.api.deps import db_session
from tracegate.client_export.bundle import (
    ClientConfigBundleItem,
    build_client_config_bundle,
    render_subscription_base64,
    render_subscription_text,
)
from tracegate.enums import RecordStatus
from tracegate.models import Connection, ConnectionRevision, Device
from tracegate.services.client_config_tokens import (
    ClientConfigTokenError,
    client_config_token_secret,
    parse_client_config_token,
)
from tracegate.settings import get_settings

router = APIRouter(prefix="/client-config", tags=["client-config"])


def _uuid(raw: str, *, label: str) -> UUID:
    try:
        return UUID(str(raw))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{label} not found") from exc


def _bundle_item(revision: ConnectionRevision, connection: Connection, device: Device) -> ClientConfigBundleItem:
    return ClientConfigBundleItem(
        revision_id=str(revision.id),
        connection_id=str(connection.id),
        device_id=str(device.id),
        effective_config=dict(revision.effective_config_json or {}),
        protocol=str(connection.protocol.value if hasattr(connection.protocol, "value") else connection.protocol),
        mode=str(connection.mode.value if hasattr(connection.mode, "value") else connection.mode),
        variant=str(connection.variant.value if hasattr(connection.variant, "value") else connection.variant),
        profile_name=str(connection.profile_name or ""),
        label=str(connection.profile_name or ""),
    )


async def _load_revision_item(session: AsyncSession, revision_id: str) -> tuple[list[ClientConfigBundleItem], str, str]:
    revision_uuid = _uuid(revision_id, label="Revision")
    row = (
        await session.execute(
            select(ConnectionRevision, Connection, Device)
            .join(Connection, ConnectionRevision.connection_id == Connection.id)
            .join(Device, Connection.device_id == Device.id)
            .where(
                ConnectionRevision.id == revision_uuid,
                ConnectionRevision.status == RecordStatus.ACTIVE,
                Connection.status == RecordStatus.ACTIVE,
                Device.status == RecordStatus.ACTIVE,
            )
        )
    ).first()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Revision not found")
    revision, connection, device = row
    return [_bundle_item(revision, connection, device)], "revision", str(revision.id)


async def _load_device_items(session: AsyncSession, device_id: str) -> tuple[list[ClientConfigBundleItem], str, str]:
    device_uuid = _uuid(device_id, label="Device")
    rows = (
        await session.execute(
            select(ConnectionRevision, Connection, Device)
            .join(Connection, ConnectionRevision.connection_id == Connection.id)
            .join(Device, Connection.device_id == Device.id)
            .where(
                Device.id == device_uuid,
                Device.status == RecordStatus.ACTIVE,
                Connection.status == RecordStatus.ACTIVE,
                ConnectionRevision.status == RecordStatus.ACTIVE,
                ConnectionRevision.slot == 0,
            )
            .order_by(Connection.created_at.asc(), ConnectionRevision.created_at.desc())
        )
    ).all()
    if not rows:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device config not found")
    return [_bundle_item(revision, connection, device) for revision, connection, device in rows], "device", str(device_uuid)


@router.get("/{token}")
async def get_client_config(
    token: str,
    format: str = Query(default="subscription", pattern="^(subscription|plain|base64|json|bundle|singbox)$"),
    session: AsyncSession = Depends(db_session),
):
    settings = get_settings()
    secret = client_config_token_secret(settings)
    if not secret:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Client config token secret is not configured")
    try:
        claims = parse_client_config_token(token, secret=secret)
    except ClientConfigTokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    subject_type = str(claims["subject_type"])
    subject_id = str(claims["subject_id"])
    if subject_type == "revision":
        items, bundle_subject_type, bundle_subject_id = await _load_revision_item(session, subject_id)
    else:
        items, bundle_subject_type, bundle_subject_id = await _load_device_items(session, subject_id)

    bundle = build_client_config_bundle(
        items,
        subject_type=bundle_subject_type,
        subject_id=bundle_subject_id,
    )
    normalized_format = format.strip().lower()
    if normalized_format in {"json", "bundle"}:
        return JSONResponse(bundle)
    if normalized_format == "singbox":
        return JSONResponse(bundle["singbox"])
    if normalized_format == "base64":
        return PlainTextResponse(render_subscription_base64(bundle), media_type="text/plain; charset=utf-8")
    return PlainTextResponse(render_subscription_text(bundle), media_type="text/plain; charset=utf-8")
