from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.api.deps import db_session
from tracegate.enums import NodeRole, OutboxEventType, RecordStatus
from tracegate.models import Connection, ConnectionRevision, OutboxDelivery, OutboxEvent, WireguardPeer
from tracegate.schemas import OutboxDeliveryRead, OutboxEventRead, ReapplyBaseRequest, ReissueRequest
from tracegate.security import require_internal_api_token
from tracegate.services.outbox import create_outbox_event

router = APIRouter(prefix="/dispatch", tags=["dispatch"], dependencies=[Depends(require_internal_api_token)])


def _bundle_path(name: str) -> Path:
    return Path(__file__).resolve().parents[4] / "bundles" / name


def _load_bundle_files(name: str) -> dict[str, str]:
    root = _bundle_path(name)
    files: dict[str, str] = {}
    if not root.exists():
        return files
    for path in root.rglob("*"):
        if path.is_file():
            files[str(path.relative_to(root))] = path.read_text(encoding="utf-8")
    return files


@router.get("/events", response_model=list[OutboxEventRead])
async def list_events(session: AsyncSession = Depends(db_session)) -> list[OutboxEventRead]:
    rows = (await session.execute(select(OutboxEvent).order_by(OutboxEvent.created_at.desc()).limit(200))).scalars().all()
    return [OutboxEventRead.model_validate(row, from_attributes=True) for row in rows]


@router.get("/deliveries", response_model=list[OutboxDeliveryRead])
async def list_deliveries(session: AsyncSession = Depends(db_session)) -> list[OutboxDeliveryRead]:
    rows = (await session.execute(select(OutboxDelivery).order_by(OutboxDelivery.created_at.desc()).limit(200))).scalars().all()
    return [OutboxDeliveryRead.model_validate(row, from_attributes=True) for row in rows]


@router.post("/reapply-base", response_model=list[OutboxEventRead])
async def reapply_base(payload: ReapplyBaseRequest, session: AsyncSession = Depends(db_session)) -> list[OutboxEventRead]:
    roles = [payload.role] if payload.role else [NodeRole.VPS_T, NodeRole.VPS_E]
    created: list[OutboxEvent] = []

    for role in roles:
        bundle_name = "base-vps-t" if role == NodeRole.VPS_T else "base-vps-e"
        files = _load_bundle_files(bundle_name)
        event = await create_outbox_event(
            session,
            event_type=OutboxEventType.APPLY_BUNDLE,
            aggregate_id=f"{bundle_name}:{datetime.now(timezone.utc).isoformat()}",
            payload={
                "bundle_name": bundle_name,
                "files": files,
                "commands": ["systemctl daemon-reload"],
            },
            role_target=role,
        )
        created.append(event)

    await session.commit()
    for event in created:
        await session.refresh(event)
    return [OutboxEventRead.model_validate(event, from_attributes=True) for event in created]


@router.post("/reissue-current-revisions", response_model=list[OutboxEventRead])
async def reissue_current_revisions(payload: ReissueRequest, session: AsyncSession = Depends(db_session)) -> list[OutboxEventRead]:
    query = select(Connection).where(Connection.status == RecordStatus.ACTIVE)
    if payload.user_id is not None:
        query = query.where(Connection.user_id == payload.user_id)

    connections = (await session.execute(query)).scalars().all()
    created: list[OutboxEvent] = []

    for conn in connections:
        revision = await session.scalar(
            select(ConnectionRevision).where(
                and_(
                    ConnectionRevision.connection_id == conn.id,
                    ConnectionRevision.status == RecordStatus.ACTIVE,
                    ConnectionRevision.slot == 0,
                )
            )
        )
        if revision is None:
            continue

        roles = [NodeRole.VPS_T]
        event_type = OutboxEventType.WG_PEER_UPSERT if conn.protocol.value == "wireguard" else OutboxEventType.UPSERT_USER
        wg_peer: WireguardPeer | None = None
        if event_type == OutboxEventType.WG_PEER_UPSERT:
            wg_peer = await session.scalar(
                select(WireguardPeer).where(
                    WireguardPeer.device_id == conn.device_id,
                    WireguardPeer.status == RecordStatus.ACTIVE,
                )
            )
        for role in roles:
            payload = {
                "user_id": str(conn.user_id),
                "device_id": str(conn.device_id),
                "connection_id": str(conn.id),
                "revision_id": str(revision.id),
                "protocol": conn.protocol.value,
                "variant": conn.variant.value,
                "config": revision.effective_config_json,
            }
            if wg_peer is not None:
                payload.update(
                    {
                        "peer_public_key": wg_peer.peer_public_key,
                        "preshared_key": wg_peer.preshared_key,
                        "peer_ip": (revision.effective_config_json or {}).get("assigned_ip"),
                    }
                )
            created.append(
                await create_outbox_event(
                    session,
                    event_type=event_type,
                    aggregate_id=str(conn.id),
                    payload=payload,
                    role_target=role,
                    idempotency_suffix=f"reissue:{revision.id}:{role.value}",
                )
            )

    await session.commit()
    for event in created:
        await session.refresh(event)
    return [OutboxEventRead.model_validate(event, from_attributes=True) for event in created]
