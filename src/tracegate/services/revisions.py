from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from tracegate.enums import ConnectionProtocol, ConnectionVariant, NodeRole, OutboxEventType, RecordStatus
from tracegate.models import Connection, ConnectionRevision, NodeEndpoint, SniDomain, User
from tracegate.services.config_builder import EndpointSet, build_effective_config
from tracegate.services.grace import ensure_can_issue_new_config
from tracegate.services.outbox import create_outbox_event
from tracegate.services.overrides import validate_overrides
from tracegate.settings import get_settings


class RevisionError(RuntimeError):
    pass


async def _load_connection(session: AsyncSession, connection_id: UUID) -> Connection:
    connection = await session.scalar(
        select(Connection)
        .where(Connection.id == connection_id)
        .options(selectinload(Connection.device), selectinload(Connection.revisions))
    )
    if connection is None:
        raise RevisionError("Connection not found")
    return connection


async def _load_user(session: AsyncSession, user_id: UUID) -> User:
    user = await session.get(User, user_id)
    if user is None:
        raise RevisionError("User not found")
    return user


async def _resolve_sni(
    session: AsyncSession,
    protocol: ConnectionProtocol,
    requested_sni_id: int | None,
    overrides: dict,
) -> SniDomain | None:
    if protocol != ConnectionProtocol.VLESS_REALITY:
        return None

    sni_id = requested_sni_id or overrides.get("camouflage_sni_id")
    if sni_id is None:
        sni = await session.scalar(select(SniDomain).where(SniDomain.enabled.is_(True)).order_by(SniDomain.id.asc()))
        if sni is None:
            raise RevisionError("No enabled SNI domains available")
        return sni

    sni = await session.scalar(select(SniDomain).where(SniDomain.id == sni_id, SniDomain.enabled.is_(True)))
    if sni is None:
        raise RevisionError("Requested SNI is unavailable")
    return sni


async def _resolve_endpoints(session: AsyncSession) -> EndpointSet:
    settings = get_settings()
    vps_t = await session.scalar(
        select(NodeEndpoint).where(NodeEndpoint.active.is_(True), NodeEndpoint.role == NodeRole.VPS_T).order_by(NodeEndpoint.created_at.asc())
    )
    vps_e = await session.scalar(
        select(NodeEndpoint).where(NodeEndpoint.active.is_(True), NodeEndpoint.role == NodeRole.VPS_E).order_by(NodeEndpoint.created_at.asc())
    )

    return EndpointSet(
        vps_t_host=(vps_t.fqdn or vps_t.public_ipv4) if vps_t else settings.default_vps_t_host,
        vps_e_host=(vps_e.fqdn or vps_e.public_ipv4) if vps_e else settings.default_vps_e_host,
    )


def _slot_target_role(variant: ConnectionVariant) -> list[NodeRole]:
    if variant == ConnectionVariant.B2:
        return [NodeRole.VPS_E, NodeRole.VPS_T]
    return [NodeRole.VPS_T]


def _event_type_for_protocol(protocol: ConnectionProtocol) -> OutboxEventType:
    if protocol == ConnectionProtocol.WIREGUARD:
        return OutboxEventType.WG_PEER_UPSERT
    return OutboxEventType.UPSERT_USER


async def _compact_slots(connection: Connection) -> None:
    active = [rev for rev in connection.revisions if rev.status == RecordStatus.ACTIVE]
    active.sort(key=lambda r: (r.slot, r.created_at))
    for idx, rev in enumerate(active[:3]):
        rev.slot = idx
    for rev in active[3:]:
        rev.status = RecordStatus.REVOKED
        rev.slot = 2


async def create_revision(
    session: AsyncSession,
    *,
    connection_id: UUID,
    camouflage_sni_id: int | None,
    force: bool,
) -> ConnectionRevision:
    connection = await _load_connection(session, connection_id)
    user = await _load_user(session, connection.user_id)

    ensure_can_issue_new_config(user, force=force)
    validate_overrides(connection.protocol, connection.custom_overrides_json)

    selected_sni = await _resolve_sni(session, connection.protocol, camouflage_sni_id, connection.custom_overrides_json)
    endpoints = await _resolve_endpoints(session)

    for rev in sorted(
        [r for r in connection.revisions if r.status == RecordStatus.ACTIVE],
        key=lambda r: r.slot,
        reverse=True,
    ):
        next_slot = rev.slot + 1
        if next_slot > 2:
            rev.status = RecordStatus.REVOKED
            rev.slot = 2
        else:
            rev.slot = next_slot

    effective_config = build_effective_config(
        user=user,
        device=connection.device,
        connection=connection,
        selected_sni=selected_sni,
        endpoints=endpoints,
    )
    revision = ConnectionRevision(
        connection_id=connection.id,
        slot=0,
        status=RecordStatus.ACTIVE,
        camouflage_sni_id=selected_sni.id if selected_sni else None,
        effective_config_json=effective_config,
        created_at=datetime.now(timezone.utc),
    )
    session.add(revision)
    await session.flush()

    event_type = _event_type_for_protocol(connection.protocol)
    payload = {
        "user_id": str(user.id),
        "device_id": str(connection.device_id),
        "connection_id": str(connection.id),
        "revision_id": str(revision.id),
        "protocol": connection.protocol.value,
        "variant": connection.variant.value,
        "config": effective_config,
        "camouflage_sni": selected_sni.fqdn if selected_sni else None,
    }

    for role in _slot_target_role(connection.variant):
        await create_outbox_event(
            session,
            event_type=event_type,
            aggregate_id=str(connection.id),
            payload=payload,
            role_target=role,
            idempotency_suffix=f"{revision.id}:{role.value}",
        )

    await _compact_slots(connection)
    await session.flush()
    return revision


async def activate_revision(session: AsyncSession, revision_id: UUID) -> ConnectionRevision:
    revision = await session.get(ConnectionRevision, revision_id)
    if revision is None:
        raise RevisionError("Revision not found")

    connection = await _load_connection(session, revision.connection_id)
    revision.status = RecordStatus.ACTIVE
    revision.slot = 0

    others = [r for r in connection.revisions if r.id != revision.id and r.status == RecordStatus.ACTIVE]
    others.sort(key=lambda r: r.slot)
    for idx, rev in enumerate(others, start=1):
        if idx > 2:
            rev.status = RecordStatus.REVOKED
            rev.slot = 2
        else:
            rev.slot = idx

    await session.flush()
    return revision


async def revoke_revision(session: AsyncSession, revision_id: UUID) -> ConnectionRevision:
    revision = await session.get(ConnectionRevision, revision_id)
    if revision is None:
        raise RevisionError("Revision not found")

    revision.status = RecordStatus.REVOKED

    connection = await _load_connection(session, revision.connection_id)
    await _compact_slots(connection)
    await session.flush()

    payload = {
        "connection_id": str(connection.id),
        "revision_id": str(revision.id),
        "user_id": str(connection.user_id),
        "device_id": str(connection.device_id),
    }
    roles = [NodeRole.VPS_T] if connection.variant != ConnectionVariant.B2 else [NodeRole.VPS_E, NodeRole.VPS_T]
    for role in roles:
        await create_outbox_event(
            session,
            event_type=OutboxEventType.REVOKE_USER,
            aggregate_id=str(connection.id),
            payload=payload,
            role_target=role,
            idempotency_suffix=f"{revision.id}:{role.value}",
        )

    await session.flush()
    return revision
