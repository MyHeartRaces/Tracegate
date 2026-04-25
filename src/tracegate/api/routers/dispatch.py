from __future__ import annotations

from datetime import datetime, timezone
import json
import hashlib
from pathlib import Path

from fastapi import APIRouter, Depends
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.api.deps import db_session
from tracegate.enums import ApiScope, NodeRole, OutboxEventType, RecordStatus
from tracegate.models import Connection, ConnectionRevision, Device, OutboxDelivery, OutboxEvent, User
from tracegate.schemas import OutboxDeliveryRead, OutboxEventRead, ReapplyBaseRequest, ReissueRequest
from tracegate.security import require_api_scope
from tracegate.services.aliases import connection_alias, user_display
from tracegate.services.bundle_files import BundleFilePayload, load_bundle_file
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


def _materialized_bundle_path(name: str) -> Path | None:
    settings = get_settings()
    materialized_root = str(settings.bundle_materialized_root or "").strip()
    if not materialized_root:
        return None
    root = Path(materialized_root)
    if not root.is_absolute():
        root = Path.cwd() / root
    return root / name


def _load_bundle_files(name: str) -> dict[str, BundleFilePayload]:
    def _read_tree(root: Path) -> dict[str, BundleFilePayload]:
        loaded: dict[str, BundleFilePayload] = {}
        if not root.exists():
            return loaded
        for path in root.rglob("*"):
            if path.is_file():
                loaded[str(path.relative_to(root))] = load_bundle_file(path)
        return loaded

    files = _read_tree(_bundle_path(name))
    materialized_path = _materialized_bundle_path(name)
    if materialized_path is not None:
        # Materialized files (Helm-rendered secrets) override repo bundle templates.
        files.update(_read_tree(materialized_path))
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
    roles = [payload.role] if payload.role else [NodeRole.TRANSIT, NodeRole.ENTRY]
    created: list[OutboxEvent] = []

    for role in roles:
        bundle_name = "base-transit" if role == NodeRole.TRANSIT else "base-entry"
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
        for role in roles:
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
                # Ensure per-role idempotency keys never collide for V2 (Entry + Transit).
                # This also lets reissue create a fresh event when payload changes.
                "role_target": role.value,
                "config": revision.effective_config_json,
            }

            created.append(
                await create_outbox_event(
                    session,
                    event_type=OutboxEventType.UPSERT_USER,
                    aggregate_id=str(conn.id),
                    payload=event_payload,
                    role_target=role,
                    # Include payload hash to:
                    # - allow reissue to update alias labels over time when user/device metadata changes
                    idempotency_suffix=f"reissue2:{revision.id}:{role.value}:{_stable_payload_hash(event_payload)}",
                )
            )

    await session.commit()
    for event in created:
        await session.refresh(event)
    return [OutboxEventRead.model_validate(event, from_attributes=True) for event in created]
