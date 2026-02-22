from __future__ import annotations

from datetime import datetime, timezone
import json
import hashlib
from pathlib import Path

from fastapi import APIRouter, Depends
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.api.deps import db_session
from tracegate.enums import ApiScope, ConnectionProtocol, NodeRole, OutboxEventType, RecordStatus
from tracegate.models import Connection, ConnectionRevision, Device, OutboxDelivery, OutboxEvent, User, WireguardPeer
from tracegate.schemas import OutboxDeliveryRead, OutboxEventRead, ReapplyBaseRequest, ReissueRequest
from tracegate.security import require_api_scope
from tracegate.services.aliases import connection_alias, user_display
from tracegate.services.outbox import create_outbox_event
from tracegate.services.role_targeting import target_roles_for_connection
from tracegate.settings import get_settings

router = APIRouter(prefix="/dispatch", tags=["dispatch"], dependencies=[Depends(require_api_scope(ApiScope.DISPATCH_RW))])


def _bundle_path(name: str) -> Path:
    settings = get_settings()
    root = Path(settings.bundle_root)
    if not root.is_absolute():
        root = Path.cwd() / root
    return root / name


def _load_bundle_files(name: str) -> dict[str, str]:
    root = _bundle_path(name)
    files: dict[str, str] = {}
    if not root.exists():
        return files
    for path in root.rglob("*"):
        if path.is_file():
            files[str(path.relative_to(root))] = path.read_text(encoding="utf-8")
    return files


def _stable_payload_hash(payload: dict) -> str:
    # Mirrors tracegate.services.outbox._stable_payload_hash() but kept local to avoid importing a private helper.
    dumped = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(dumped.encode("utf-8")).hexdigest()[:24]


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
                "commands": [],
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
        user = await session.get(User, conn.user_id)
        device = await session.get(Device, conn.device_id)
        user_label = (
            user_display(
                telegram_id=conn.user_id,
                telegram_username=user.telegram_username if user else None,
                telegram_first_name=user.telegram_first_name if user else None,
                telegram_last_name=user.telegram_last_name if user else None,
            )
            if user is not None
            else str(conn.user_id)
        )
        device_name = (device.name if device else "").strip() or str(conn.device_id)
        conn_alias = connection_alias(
            telegram_id=conn.user_id,
            telegram_username=user.telegram_username if user else None,
            telegram_first_name=user.telegram_first_name if user else None,
            telegram_last_name=user.telegram_last_name if user else None,
            device_name=device_name,
            connection_id=str(conn.id),
        )
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

        roles = target_roles_for_connection(conn.protocol, conn.variant)
        is_wireguard = conn.protocol == ConnectionProtocol.WIREGUARD
        event_type = OutboxEventType.WG_PEER_UPSERT if is_wireguard else OutboxEventType.UPSERT_USER
        wg_peer: WireguardPeer | None = None
        if is_wireguard:
            wg_peer = await session.scalar(
                select(WireguardPeer).where(
                    WireguardPeer.device_id == conn.device_id,
                    WireguardPeer.status == RecordStatus.ACTIVE,
                )
            )
        for role in roles:
            if is_wireguard:
                # Privacy: nodes only need peer public key + assigned IP for server config sync.
                event_payload: dict = {
                    "device_id": str(conn.device_id),
                    "op_ts": revision.created_at.isoformat(),
                }
            else:
                event_payload = {
                    "user_id": str(conn.user_id),
                    "user_display": user_label,
                    "telegram_username": user.telegram_username if user else None,
                    "device_id": str(conn.device_id),
                    "device_name": device_name,
                    "connection_id": str(conn.id),
                    "connection_alias": conn_alias,
                    "revision_id": str(revision.id),
                    "op_ts": revision.created_at.isoformat(),
                    "protocol": conn.protocol.value,
                    "variant": conn.variant.value,
                    # Ensure per-role idempotency keys never collide for B2 (VPS-E + VPS-T).
                    # This also lets reissue create a fresh event when payload changes.
                    "role_target": role.value,
                }

            if is_wireguard:
                # Never send client private keys to nodes. Nodes only need peer public key + assigned IP.
                cfg = revision.effective_config_json or {}
                peer_pub = str(cfg.get("device_public_key") or "").strip()
                peer_ip = str(cfg.get("assigned_ip") or "").strip()
                if wg_peer is not None:
                    peer_pub = str(wg_peer.peer_public_key or "").strip() or peer_pub
                if not peer_pub or not peer_ip:
                    # Broken/legacy state: cannot build a valid WG peer event.
                    continue
                event_payload.update(
                    {
                        "peer_public_key": peer_pub,
                        "preshared_key": wg_peer.preshared_key if wg_peer is not None else None,
                        "peer_ip": peer_ip,
                    }
                )
            else:
                event_payload["config"] = revision.effective_config_json

            created.append(
                await create_outbox_event(
                    session,
                    event_type=event_type,
                    aggregate_id=str(conn.id),
                    payload=event_payload,
                    role_target=role,
                    # Include payload hash to:
                    # - avoid reusing legacy events that may contain WireGuard private keys (older reissue impl)
                    # - allow reissue to update alias labels over time when user/device metadata changes
                    idempotency_suffix=f"reissue2:{revision.id}:{role.value}:{_stable_payload_hash(event_payload)}",
                )
            )

    await session.commit()
    for event in created:
        await session.refresh(event)
    return [OutboxEventRead.model_validate(event, from_attributes=True) for event in created]
