from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.enums import ConnectionProtocol, NodeRole, OutboxEventType, RecordStatus
from tracegate.models import Connection, ConnectionRevision, Device, IpamLease, WireguardPeer
from tracegate.services.ipam import release_lease
from tracegate.services.outbox import create_outbox_event


class ConnectionRevokeError(RuntimeError):
    pass


async def revoke_connection(session: AsyncSession, connection_id: UUID) -> None:
    conn = await session.get(Connection, connection_id)
    if conn is None:
        raise ConnectionRevokeError("Connection not found")

    op_ts = datetime.now(timezone.utc).isoformat()
    conn.status = RecordStatus.REVOKED

    # Mark all revisions revoked (keep history).
    revisions = (
        await session.execute(
            select(ConnectionRevision).where(ConnectionRevision.connection_id == conn.id)
        )
    ).scalars().all()
    for rev in revisions:
        rev.status = RecordStatus.REVOKED

    # Revoke artifacts on node.
    if conn.protocol == ConnectionProtocol.WIREGUARD:
        # Revoke DB peer row for this device.
        peer = await session.scalar(
            select(WireguardPeer).where(
                WireguardPeer.device_id == conn.device_id,
                WireguardPeer.status == RecordStatus.ACTIVE,
            )
        )
        if peer is not None:
            peer.status = RecordStatus.REVOKED
            lease: IpamLease | None = await session.get(IpamLease, peer.lease_id)
            if lease is not None:
                await release_lease(session, lease)

        await create_outbox_event(
            session,
            event_type=OutboxEventType.WG_PEER_REMOVE,
            aggregate_id=str(conn.id),
            payload={
                "user_id": str(conn.user_id),
                "device_id": str(conn.device_id),
                "connection_id": str(conn.id),
                "op_ts": op_ts,
            },
            role_target=NodeRole.VPS_T,
            idempotency_suffix=f"conn-revoke:{conn.id}",
        )
        return

    await create_outbox_event(
        session,
        event_type=OutboxEventType.REVOKE_CONNECTION,
        aggregate_id=str(conn.id),
        payload={
            "user_id": str(conn.user_id),
            "device_id": str(conn.device_id),
            "connection_id": str(conn.id),
            "op_ts": op_ts,
        },
        role_target=NodeRole.VPS_T,
        idempotency_suffix=f"conn-revoke:{conn.id}",
    )


async def revoke_user_access(session: AsyncSession, user_id: int) -> tuple[int, int]:
    """
    Revoke all active user connections and mark all user devices as revoked.

    Returns:
      (revoked_connections_count, revoked_devices_count)
    """
    connections = (
        await session.execute(
            select(Connection).where(
                Connection.user_id == user_id,
                Connection.status == RecordStatus.ACTIVE,
            )
        )
    ).scalars().all()
    for conn in connections:
        await revoke_connection(session, connection_id=conn.id)

    devices = (
        await session.execute(
            select(Device).where(
                Device.user_id == user_id,
                Device.status == RecordStatus.ACTIVE,
            )
        )
    ).scalars().all()
    for device in devices:
        device.status = RecordStatus.REVOKED

    return len(connections), len(devices)
