from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.enums import DeliveryStatus, NodeRole, OutboxEventType, OutboxStatus
from tracegate.models import NodeEndpoint, OutboxDelivery, OutboxEvent


def _stable_payload_hash(payload: dict) -> str:
    dumped = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(dumped.encode("utf-8")).hexdigest()[:24]


async def create_outbox_event(
    session: AsyncSession,
    *,
    event_type: OutboxEventType,
    aggregate_id: str,
    payload: dict,
    role_target: NodeRole | None = None,
    node_id: UUID | None = None,
    idempotency_suffix: str | None = None,
) -> OutboxEvent:
    suffix = idempotency_suffix or _stable_payload_hash(payload)
    idempotency_key = f"{event_type}:{aggregate_id}:{suffix}"

    existing = await session.scalar(select(OutboxEvent).where(OutboxEvent.idempotency_key == idempotency_key))
    if existing:
        return existing

    event = OutboxEvent(
        event_type=event_type,
        aggregate_id=aggregate_id,
        payload_json=payload,
        role_target=role_target,
        node_id=node_id,
        idempotency_key=idempotency_key,
        status=OutboxStatus.PENDING,
    )
    session.add(event)
    await session.flush()

    await fanout_deliveries(session, event)
    return event


async def fanout_deliveries(session: AsyncSession, event: OutboxEvent) -> list[OutboxDelivery]:
    nodes_query = select(NodeEndpoint).where(NodeEndpoint.active.is_(True))
    if event.node_id:
        nodes_query = nodes_query.where(NodeEndpoint.id == event.node_id)
    elif event.role_target:
        nodes_query = nodes_query.where(NodeEndpoint.role == event.role_target)

    nodes = (await session.execute(nodes_query)).scalars().all()
    deliveries: list[OutboxDelivery] = []
    if not nodes:
        event.status = OutboxStatus.FAILED
        event.last_error = "no active node targets for event fanout"
        await session.flush()
        return deliveries

    for node in nodes:
        exists = await session.scalar(
            select(OutboxDelivery).where(
                and_(OutboxDelivery.outbox_event_id == event.id, OutboxDelivery.node_id == node.id)
            )
        )
        if exists:
            deliveries.append(exists)
            continue

        delivery = OutboxDelivery(
            outbox_event_id=event.id,
            node_id=node.id,
            status=DeliveryStatus.PENDING,
            next_attempt_at=datetime.now(timezone.utc),
        )
        session.add(delivery)
        deliveries.append(delivery)

    await session.flush()
    return deliveries
