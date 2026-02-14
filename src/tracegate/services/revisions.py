from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from tracegate.enums import ConnectionProtocol, IpamLeaseStatus, NodeRole, OutboxEventType, RecordStatus
from tracegate.enums import OwnerType
from tracegate.models import Connection, ConnectionRevision, IpamLease, NodeEndpoint, User, WireguardPeer
from tracegate.services.aliases import connection_alias, user_display
from tracegate.services.config_builder import EndpointSet, build_effective_config
from tracegate.services.ipam import allocate_lease, ensure_pool_exists, release_lease
from tracegate.services.grace import ensure_can_issue_new_config
from tracegate.services.outbox import create_outbox_event
from tracegate.services.overrides import validate_overrides
from tracegate.services.role_targeting import target_roles_for_connection
from tracegate.services.sni_catalog import SniCatalogEntry, get_by_id, load_catalog
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


async def _load_user(session: AsyncSession, user_id: int) -> User:
    user = await session.get(User, user_id)
    if user is None:
        raise RevisionError("User not found")
    return user


async def _resolve_sni(
    session: AsyncSession,
    protocol: ConnectionProtocol,
    requested_sni_id: int | None,
    overrides: dict,
) -> SniCatalogEntry | None:
    if protocol != ConnectionProtocol.VLESS_REALITY:
        return None

    sni_id = requested_sni_id or overrides.get("camouflage_sni_id")
    if sni_id is None:
        for row in load_catalog():
            if row.enabled:
                return row
        raise RevisionError("No enabled SNI domains available")

    row = get_by_id(int(sni_id))
    if row is None or not row.enabled:
        raise RevisionError("Requested SNI is unavailable")
    return row


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
        vps_t_proxy_host=vps_t.proxy_fqdn if vps_t else None,
        vps_e_proxy_host=vps_e.proxy_fqdn if vps_e else None,
        reality_public_key=settings.reality_public_key,
        reality_short_id=settings.reality_short_id,
        reality_public_key_vps_t=settings.reality_public_key_vps_t,
        reality_short_id_vps_t=settings.reality_short_id_vps_t,
        reality_public_key_vps_e=settings.reality_public_key_vps_e,
        reality_short_id_vps_e=settings.reality_short_id_vps_e,
        wireguard_server_public_key=settings.wireguard_server_public_key,
        vless_ws_path=settings.vless_ws_path,
        vless_ws_tls_port=settings.vless_ws_tls_port,
    )


def _is_allowed_reality_sni(fqdn: str) -> bool:
    settings = get_settings()
    suffixes = [s.lower().strip() for s in settings.reality_sni_allow_suffixes if s and s.strip()]
    if not suffixes:
        return True
    name = fqdn.lower().strip()
    for s in suffixes:
        if s.startswith("."):
            if name.endswith(s):
                return True
        else:
            if name == s or name.endswith("." + s):
                return True
    return False


def _event_type_for_protocol(protocol: ConnectionProtocol) -> OutboxEventType:
    if protocol == ConnectionProtocol.WIREGUARD:
        return OutboxEventType.WG_PEER_UPSERT
    return OutboxEventType.UPSERT_USER


def _wg_peer_fields_from_revision(revision: ConnectionRevision) -> tuple[str, str, list[str]]:
    cfg = revision.effective_config_json or {}
    peer_pub = (cfg.get("device_public_key") or "").strip()
    peer_ip = (cfg.get("assigned_ip") or "").strip()
    allowed_ips = ((cfg.get("peer") or {}).get("allowed_ips") or ["0.0.0.0/0"]) if isinstance(cfg.get("peer"), dict) else ["0.0.0.0/0"]
    allowed_ips = [str(x).strip() for x in (allowed_ips or []) if str(x).strip()]
    if not peer_pub or not peer_ip:
        raise RevisionError("wireguard revision is missing device_public_key/assigned_ip")
    return peer_pub, peer_ip, allowed_ips


async def _sync_wireguard_peer_state(
    session: AsyncSession,
    *,
    user: User,
    connection: Connection,
    peer_public_key: str,
    peer_ip: str,
    allowed_ips: list[str],
) -> WireguardPeer:
    """
    Keep DB peer state consistent with the currently active slot0 revision.

    This is important because other control-plane actions (like /dispatch/reissue-current-revisions)
    read the peer public key from DB.
    """
    pool = await ensure_pool_exists(session)
    lease = await session.scalar(
        select(IpamLease).where(
            and_(
                IpamLease.pool_id == pool.id,
                IpamLease.owner_type == OwnerType.DEVICE,
                IpamLease.owner_id == connection.device_id,
                IpamLease.status == IpamLeaseStatus.ACTIVE,
            )
        )
    )
    if lease is None:
        lease = await allocate_lease(session, pool, OwnerType.DEVICE, connection.device_id)

    if lease.ip != peer_ip:
        raise RevisionError(f"wireguard peer_ip mismatch: revision={peer_ip} lease={lease.ip}")

    # A recycled lease can still be referenced by an old revoked peer row.
    # Reuse whichever row matches current device or current lease to avoid unique(lease_id) conflicts.
    peers = (
        await session.execute(
            select(WireguardPeer).where(
                or_(
                    WireguardPeer.device_id == connection.device_id,
                    WireguardPeer.lease_id == lease.id,
                )
            )
        )
    ).scalars().all()
    peer = next((row for row in peers if row.device_id == connection.device_id), None)
    if peer is None:
        peer = next((row for row in peers if row.lease_id == lease.id), None)

    if peer is None:
        peer = WireguardPeer(
            user_id=user.telegram_id,
            device_id=connection.device_id,
            peer_public_key=peer_public_key,
            lease_id=lease.id,
            preshared_key=None,
            allowed_ips=allowed_ips,
            status=RecordStatus.ACTIVE,
        )
        session.add(peer)
        await session.flush()
        return peer

    peer.user_id = user.telegram_id
    peer.device_id = connection.device_id
    peer.status = RecordStatus.ACTIVE
    peer.peer_public_key = peer_public_key
    peer.lease_id = lease.id
    peer.preshared_key = None
    peer.allowed_ips = allowed_ips
    await session.flush()
    return peer


async def _emit_apply_for_revision(
    session: AsyncSession,
    *,
    connection: Connection,
    revision: ConnectionRevision,
    idempotency_prefix: str,
) -> None:
    user = await _load_user(session, connection.user_id)
    event_type = _event_type_for_protocol(connection.protocol)
    device_name = (connection.device.name if connection.device else "").strip() or str(connection.device_id)
    user_label = user_display(
        telegram_id=user.telegram_id,
        telegram_username=user.telegram_username,
        telegram_first_name=user.telegram_first_name,
        telegram_last_name=user.telegram_last_name,
    )
    conn_alias = connection_alias(
        telegram_id=user.telegram_id,
        telegram_username=user.telegram_username,
        telegram_first_name=user.telegram_first_name,
        telegram_last_name=user.telegram_last_name,
        device_name=device_name,
        connection_id=str(connection.id),
    )

    payload: dict = {
        "user_id": str(user.telegram_id),
        "user_display": user_label,
        "telegram_username": user.telegram_username,
        "device_id": str(connection.device_id),
        "device_name": device_name,
        "connection_id": str(connection.id),
        "connection_alias": conn_alias,
        "revision_id": str(revision.id),
        # Revision timestamp is used by nodes to make applying state robust against
        # out-of-order delivery (dispatcher concurrency).
        "op_ts": revision.created_at.isoformat(),
        "protocol": connection.protocol.value,
        "variant": connection.variant.value,
    }

    if connection.protocol == ConnectionProtocol.WIREGUARD:
        # Do NOT send any client private keys to nodes; the node only needs peer public key + assigned IP.
        peer_pub, peer_ip, _allowed_ips = _wg_peer_fields_from_revision(revision)
        payload.update(
            {
                "peer_public_key": peer_pub,
                "preshared_key": None,
                "peer_ip": peer_ip,
            }
        )
    else:
        # vless/hysteria: nodes need the full config to reconcile xray/hysteria auth/users.
        cfg = revision.effective_config_json or {}
        payload["config"] = cfg
        if connection.protocol == ConnectionProtocol.VLESS_REALITY:
            payload["camouflage_sni"] = cfg.get("sni")

    for role in target_roles_for_connection(connection.protocol, connection.variant):
        await create_outbox_event(
            session,
            event_type=event_type,
            aggregate_id=str(connection.id),
            payload=payload,
            role_target=role,
            idempotency_suffix=f"{idempotency_prefix}:{revision.id}:{role.value}",
        )


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
    if selected_sni is not None and not _is_allowed_reality_sni(selected_sni.fqdn):
        raise RevisionError("Selected SNI is blocked by REALITY SNI policy (reality_sni_allow_suffixes).")
    endpoints = await _resolve_endpoints(session)

    wg_lease: IpamLease | None = None
    wg_private_key: str | None = None
    wg_public_key: str | None = None
    if connection.protocol == ConnectionProtocol.WIREGUARD:
        pool = await ensure_pool_exists(session)
        wg_lease = await allocate_lease(session, pool, OwnerType.DEVICE, connection.device_id)
        wg_private_key, wg_public_key = generate_keypair()

    active_revisions = sorted(
        [r for r in connection.revisions if r.status == RecordStatus.ACTIVE],
        key=lambda r: r.slot,
        reverse=True,
    )
    # Two-phase shift avoids transient unique collisions on (connection_id, slot)
    # for active revisions when multiple slots are present.
    for rev in active_revisions:
        rev.slot = rev.slot + 10
    await session.flush()

    for rev in active_revisions:
        prev_slot = rev.slot - 10
        next_slot = prev_slot + 1
        if next_slot > 2:
            rev.status = RecordStatus.REVOKED
            rev.slot = 2
        else:
            rev.slot = next_slot
    await session.flush()

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
    # Keep ORM collection consistent for _compact_slots() in the same transaction.
    connection.revisions.append(revision)
    await session.flush()

    # For WireGuard keep DB peer state consistent with slot0 immediately.
    if connection.protocol == ConnectionProtocol.WIREGUARD and wg_public_key and wg_lease:
        allowed_ips = ((effective_config.get("peer") or {}).get("allowed_ips") or ["0.0.0.0/0"]) if isinstance(effective_config.get("peer"), dict) else ["0.0.0.0/0"]
        await _sync_wireguard_peer_state(
            session,
            user=user,
            connection=connection,
            peer_public_key=wg_public_key,
            peer_ip=wg_lease.ip,
            allowed_ips=[str(x).strip() for x in allowed_ips if str(x).strip()],
        )

    event_type = _event_type_for_protocol(connection.protocol)
    device_name = (connection.device.name if connection.device else "").strip() or str(connection.device_id)
    user_label = user_display(
        telegram_id=user.telegram_id,
        telegram_username=user.telegram_username,
        telegram_first_name=user.telegram_first_name,
        telegram_last_name=user.telegram_last_name,
    )
    conn_alias = connection_alias(
        telegram_id=user.telegram_id,
        telegram_username=user.telegram_username,
        telegram_first_name=user.telegram_first_name,
        telegram_last_name=user.telegram_last_name,
        device_name=device_name,
        connection_id=str(connection.id),
    )
    payload = {
        "user_id": str(user.telegram_id),
        "user_display": user_label,
        "telegram_username": user.telegram_username,
        "device_id": str(connection.device_id),
        "device_name": device_name,
        "connection_id": str(connection.id),
        "connection_alias": conn_alias,
        "revision_id": str(revision.id),
        # Revision timestamp is used by nodes to make applying state robust against
        # out-of-order delivery (dispatcher concurrency).
        "op_ts": revision.created_at.isoformat(),
        "protocol": connection.protocol.value,
        "variant": connection.variant.value,
        "config": effective_config,
        "camouflage_sni": selected_sni.fqdn if selected_sni else None,
    }

    for role in target_roles_for_connection(connection.protocol, connection.variant):
        if event_type == OutboxEventType.WG_PEER_UPSERT:
            if not wg_lease or not wg_public_key:
                raise RevisionError("wireguard peer state is missing")
            # Never send the client private key to nodes. Nodes only need peer pubkey + assigned IP.
            wg_payload = {
                k: v for (k, v) in payload.items() if k != "config"
            } | {
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

    # If slot0 changes for WireGuard, ensure DB peer state matches it.
    if connection.protocol == ConnectionProtocol.WIREGUARD:
        peer_pub, peer_ip, allowed_ips = _wg_peer_fields_from_revision(revision)
        await _sync_wireguard_peer_state(
            session,
            user=await _load_user(session, connection.user_id),
            connection=connection,
            peer_public_key=peer_pub,
            peer_ip=peer_ip,
            allowed_ips=allowed_ips,
        )
    await _emit_apply_for_revision(
        session,
        connection=connection,
        revision=revision,
        idempotency_prefix="activate",
    )
    return revision


async def revoke_revision(session: AsyncSession, revision_id: UUID) -> ConnectionRevision:
    revision = await session.get(ConnectionRevision, revision_id)
    if revision is None:
        raise RevisionError("Revision not found")

    revision.status = RecordStatus.REVOKED

    connection = await _load_connection(session, revision.connection_id)
    await _compact_slots(connection)
    await session.flush()

    active_now = [r for r in connection.revisions if r.status == RecordStatus.ACTIVE]
    active_slot0 = next((r for r in active_now if r.slot == 0), None)
    if active_slot0 is not None:
        if connection.protocol == ConnectionProtocol.WIREGUARD:
            peer_pub, peer_ip, allowed_ips = _wg_peer_fields_from_revision(active_slot0)
            await _sync_wireguard_peer_state(
                session,
                user=await _load_user(session, connection.user_id),
                connection=connection,
                peer_public_key=peer_pub,
                peer_ip=peer_ip,
                allowed_ips=allowed_ips,
            )
        # Keep the connection active by re-applying the current slot0 revision to nodes.
        await _emit_apply_for_revision(
            session,
            connection=connection,
            revision=active_slot0,
            idempotency_prefix=f"revoke-promote:{revision.id}",
        )
    else:
        op_ts = datetime.now(timezone.utc).isoformat()
        payload = {
            "connection_id": str(connection.id),
            "revision_id": str(revision.id),
            "user_id": str(connection.user_id),
            "device_id": str(connection.device_id),
            "op_ts": op_ts,
        }
        event_type = (
            OutboxEventType.WG_PEER_REMOVE
            if connection.protocol == ConnectionProtocol.WIREGUARD
            else OutboxEventType.REVOKE_CONNECTION
        )
        if connection.protocol == ConnectionProtocol.WIREGUARD:
            peer = await session.scalar(select(WireguardPeer).where(WireguardPeer.device_id == connection.device_id))
            if peer is not None:
                peer.status = RecordStatus.REVOKED
                lease: IpamLease | None = await session.get(IpamLease, peer.lease_id)
                if lease is not None:
                    await release_lease(session, lease)

        # No active revisions left => the connection is effectively revoked.
        connection.status = RecordStatus.REVOKED
        for role in target_roles_for_connection(connection.protocol, connection.variant):
            await create_outbox_event(
                session,
                event_type=event_type,
                aggregate_id=str(connection.id),
                payload=payload,
                role_target=role,
                idempotency_suffix=f"revoke-final:{revision.id}:{role.value}",
            )

    await session.flush()
    return revision
