from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import and_, or_, select

from tracegate.db import get_sessionmaker
from tracegate.enums import DeliveryStatus, OutboxStatus
from tracegate.models import NodeEndpoint, OutboxDelivery, OutboxEvent
from tracegate.settings import get_settings


def _backoff_seconds(attempt: int) -> int:
    return min(300, 2 ** min(attempt, 8))


async def _send_to_agent(client: httpx.AsyncClient, node: NodeEndpoint, event: OutboxEvent, token: str) -> None:
    url = f"{node.base_url.rstrip('/')}/v1/events"
    payload = {
        "event_id": str(event.id),
        "idempotency_key": event.idempotency_key,
        "event_type": event.event_type.value,
        "payload": event.payload_json,
    }
    response = await client.post(url, json=payload, headers={"x-agent-token": token}, timeout=20)
    response.raise_for_status()


async def _process_delivery(client: httpx.AsyncClient, delivery: OutboxDelivery, token: str) -> None:
    now = datetime.now(timezone.utc)
    async with get_sessionmaker() as session:
        row = await session.get(OutboxDelivery, delivery.id)
        if row is None:
            return

        event = await session.get(OutboxEvent, row.outbox_event_id)
        node = await session.get(NodeEndpoint, row.node_id)
        if event is None or node is None:
            row.status = DeliveryStatus.FAILED
            row.last_error = "missing event/node"
            row.attempts += 1
            row.next_attempt_at = now + timedelta(seconds=_backoff_seconds(row.attempts))
            await session.commit()
            return

        try:
            await _send_to_agent(client, node, event, token)
            row.status = DeliveryStatus.SENT
            row.last_error = None
        except Exception as exc:  # noqa: BLE001
            row.status = DeliveryStatus.FAILED
            row.attempts += 1
            row.last_error = str(exc)
            row.next_attempt_at = now + timedelta(seconds=_backoff_seconds(row.attempts))

        await session.flush()

        pending_or_failed = await session.scalar(
            select(OutboxDelivery.id)
            .where(
                and_(
                    OutboxDelivery.outbox_event_id == event.id,
                    OutboxDelivery.status.in_([DeliveryStatus.PENDING, DeliveryStatus.FAILED]),
                )
            )
            .limit(1)
        )

        if pending_or_failed is None:
            event.status = OutboxStatus.SENT
        else:
            event.status = OutboxStatus.FAILED if row.status == DeliveryStatus.FAILED else OutboxStatus.PENDING
            event.attempts += 1
            event.last_error = row.last_error

        await session.commit()


async def dispatcher_loop() -> None:
    settings = get_settings()
    if not settings.agent_auth_token:
        raise RuntimeError("AGENT_AUTH_TOKEN is required")
    cert = None
    if settings.dispatcher_client_cert and settings.dispatcher_client_key:
        cert = (settings.dispatcher_client_cert, settings.dispatcher_client_key)
    verify = settings.dispatcher_ca_cert or True

    async with httpx.AsyncClient(cert=cert, verify=verify) as client:
        while True:
            now = datetime.now(timezone.utc)
            async with get_sessionmaker() as session:
                deliveries = (
                    await session.execute(
                        select(OutboxDelivery)
                        .where(
                            and_(
                                OutboxDelivery.next_attempt_at <= now,
                                or_(
                                    OutboxDelivery.status == DeliveryStatus.PENDING,
                                    OutboxDelivery.status == DeliveryStatus.FAILED,
                                ),
                            )
                        )
                        .order_by(OutboxDelivery.created_at.asc())
                        .limit(settings.dispatcher_batch_size)
                    )
                ).scalars().all()

            for delivery in deliveries:
                await _process_delivery(client, delivery, settings.agent_auth_token)

            await asyncio.sleep(settings.dispatcher_poll_seconds)


def run() -> None:
    asyncio.run(dispatcher_loop())


if __name__ == "__main__":
    run()
