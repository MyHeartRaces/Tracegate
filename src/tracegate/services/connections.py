from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.enums import ConnectionProtocol, NodeRole, OutboxEventType, RecordStatus
from tracegate.models import Connection, ConnectionRevision, WireguardPeer
from tracegate.services.outbox import create_outbox_event


class ConnectionRevokeError(RuntimeError):
    pass


async def revoke_connection(session: AsyncSession, connection_id: UUID) -> None:
    conn = await session.get(Connection, connection_id)
    if conn is None:
        raise ConnectionRevokeError("Connection not found")

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

        await create_outbox_event(
            session,
            event_type=OutboxEventType.WG_PEER_REMOVE,
            aggregate_id=str(conn.id),
            payload={
                "user_id": str(conn.user_id),
                "device_id": str(conn.device_id),
                "connection_id": str(conn.id),
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
        },
        role_target=NodeRole.VPS_T,
        idempotency_suffix=f"conn-revoke:{conn.id}",
    )

