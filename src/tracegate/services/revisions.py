from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from tracegate.enums import ConnectionProtocol, ConnectionVariant, NodeRole, OutboxEventType, RecordStatus
from tracegate.enums import OwnerType
from tracegate.models import Connection, ConnectionRevision, IpamLease, NodeEndpoint, SniDomain, User, WireguardPeer
from tracegate.services.config_builder import EndpointSet, build_effective_config
from tracegate.services.ipam import allocate_lease, ensure_pool_exists
from tracegate.services.grace import ensure_can_issue_new_config
from tracegate.services.outbox import create_outbox_event
from tracegate.services.overrides import validate_overrides
from tracegate.services.wireguard import generate_keypair
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
        reality_public_key=settings.reality_public_key,
        reality_short_id=settings.reality_short_id,
        wireguard_server_public_key=settings.wireguard_server_public_key,
    )


def _slot_target_role(variant: ConnectionVariant) -> list[NodeRole]:
    if variant == ConnectionVariant.B2:
        # In v0.1 kubernetes deploy, VPS-E can be an L4 forwarder to VPS-T, so it does not need user mapping.
        return [NodeRole.VPS_T]
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

    wg_lease: IpamLease | None = None
    wg_private_key: str | None = None
    wg_public_key: str | None = None
    if connection.protocol == ConnectionProtocol.WIREGUARD:
        pool = await ensure_pool_exists(session)
        wg_lease = await allocate_lease(session, pool, OwnerType.DEVICE, connection.device_id)
        wg_private_key, wg_public_key = generate_keypair()

        # Revoke any previous peers on this device (new revision => new keypair).
        previous = (
            await session.execute(
                select(WireguardPeer).where(
                    WireguardPeer.device_id == connection.device_id,
                    WireguardPeer.status == RecordStatus.ACTIVE,
                )
            )
        ).scalars().all()
        for row in previous:
            row.status = RecordStatus.REVOKED

        peer = WireguardPeer(
            user_id=user.id,
            device_id=connection.device_id,
            peer_public_key=wg_public_key,
            lease_id=wg_lease.id,
            preshared_key=None,
            allowed_ips=connection.custom_overrides_json.get("allowed_ips", ["0.0.0.0/0"]),
            status=RecordStatus.ACTIVE,
        )
        session.add(peer)
        await session.flush()

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

    if connection.protocol == ConnectionProtocol.WIREGUARD and wg_lease and wg_private_key and wg_public_key:
        effective_config = {
            **effective_config,
            "interface": {
                **(effective_config.get("interface") or {}),
                "addresses": [f"{wg_lease.ip}/32"],
                "private_key": wg_private_key,
            },
            "peer": {
                **(effective_config.get("peer") or {}),
                "public_key": endpoints.wireguard_server_public_key,
                "endpoint": f"{endpoints.vps_t_host}:51820",
            },
            "assigned_ip": wg_lease.ip,
            "device_public_key": wg_public_key,
        }
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
        if event_type == OutboxEventType.WG_PEER_UPSERT:
            if not wg_lease or not wg_public_key:
                raise RevisionError("wireguard peer state is missing")
            wg_payload = {
                **payload,
                "peer_public_key": wg_public_key,
                "preshared_key": None,
                "peer_ip": wg_lease.ip,
            }
            await create_outbox_event(
                session,
                event_type=event_type,
                aggregate_id=str(connection.id),
                payload=wg_payload,
                role_target=role,
                idempotency_suffix=f"{revision.id}:{role.value}",
            )
            continue
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
    event_type = OutboxEventType.WG_PEER_REMOVE if connection.protocol == ConnectionProtocol.WIREGUARD else OutboxEventType.REVOKE_USER
    for role in [NodeRole.VPS_T]:
        await create_outbox_event(
            session,
            event_type=event_type,
            aggregate_id=str(connection.id),
            payload=payload,
            role_target=role,
            idempotency_suffix=f"{revision.id}:{role.value}",
        )

    await session.flush()
    return revision
