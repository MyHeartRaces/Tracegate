from __future__ import annotations

import asyncio
import os
import socket
import uuid
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import and_, func, or_, select

from tracegate.db import get_sessionmaker
from tracegate.enums import DeliveryStatus, OutboxStatus
from tracegate.models import NodeEndpoint, OutboxDelivery, OutboxEvent
from tracegate.settings import get_settings


def _backoff_seconds(attempt: int) -> int:
    return min(300, 2 ** min(attempt, 8))


def _dispatcher_id() -> str:
    # Stable identifier for delivery locks (helps debugging & safe requeue).
    host = os.getenv("HOSTNAME") or socket.gethostname()
    return f"{host}:{os.getpid()}"


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


async def _claim_deliveries(
    *,
    now: datetime,
    dispatcher_id: str,
    batch_size: int,
    lock_ttl_seconds: int,
) -> list[uuid.UUID]:
    """
    Claim deliveries for processing.

    This makes the dispatcher horizontally scalable: multiple dispatcher replicas can run without
    double-sending the same OutboxDelivery in parallel.
    """
    lock_until = now + timedelta(seconds=lock_ttl_seconds)
    async with get_sessionmaker() as session:
        rows = (
            await session.execute(
                select(OutboxDelivery)
                .where(
                    and_(
                        OutboxDelivery.next_attempt_at <= now,
                        or_(
                            OutboxDelivery.status == DeliveryStatus.PENDING,
                            OutboxDelivery.status == DeliveryStatus.FAILED,
                        ),
                        or_(OutboxDelivery.locked_until.is_(None), OutboxDelivery.locked_until <= now),
                    )
                )
                .order_by(OutboxDelivery.created_at.asc())
                .limit(batch_size)
                .with_for_update(skip_locked=True)
            )
        ).scalars().all()

        for row in rows:
            row.locked_until = lock_until
            row.locked_by = dispatcher_id

        await session.commit()
        return [r.id for r in rows]


async def _recompute_event_status(session, event: OutboxEvent, *, last_error: str | None) -> None:
    counts = dict(
        (
            await session.execute(
                select(OutboxDelivery.status, func.count())
                .where(OutboxDelivery.outbox_event_id == event.id)
                .group_by(OutboxDelivery.status)
            )
        ).all()
    )

    total = sum(int(v) for v in counts.values()) if counts else 0
    sent = int(counts.get(DeliveryStatus.SENT, 0))
    dead = int(counts.get(DeliveryStatus.DEAD, 0))

    if total > 0 and sent == total:
        event.status = OutboxStatus.SENT
        event.last_error = None
        return

    if dead > 0:
        event.status = OutboxStatus.FAILED
        if last_error:
            event.last_error = last_error
        return

    event.status = OutboxStatus.PENDING
    if last_error:
        event.last_error = last_error


async def _process_delivery(
    *,
    client: httpx.AsyncClient,
    delivery_id: uuid.UUID,
    dispatcher_id: str,
    token: str,
    max_attempts: int,
) -> None:
    now = datetime.now(timezone.utc)
    async with get_sessionmaker() as session:
        row = await session.get(OutboxDelivery, delivery_id)
        if row is None:
            return
        if row.locked_by != dispatcher_id:
            return
        if row.locked_until is not None and row.locked_until < now:
            return

        event = await session.get(OutboxEvent, row.outbox_event_id)
        node = await session.get(NodeEndpoint, row.node_id)
        if event is None or node is None:
            row.status = DeliveryStatus.DEAD
            row.last_error = "missing event/node"
            row.attempts += 1
            row.next_attempt_at = now
            row.locked_until = None
            row.locked_by = None
            await session.commit()
            return

        last_error: str | None = None
        try:
            await _send_to_agent(client, node, event, token)
            row.status = DeliveryStatus.SENT
            row.last_error = None
        except Exception as exc:  # noqa: BLE001
            row.attempts += 1
            last_error = str(exc)
            row.last_error = last_error
            if row.attempts >= max_attempts:
                row.status = DeliveryStatus.DEAD
                row.next_attempt_at = now
            else:
                row.status = DeliveryStatus.FAILED
                row.next_attempt_at = now + timedelta(seconds=_backoff_seconds(row.attempts))

        row.locked_until = None
        row.locked_by = None

        if row.status in {DeliveryStatus.FAILED, DeliveryStatus.DEAD}:
            event.attempts += 1

        await _recompute_event_status(session, event, last_error=row.last_error)
        await session.commit()


async def dispatcher_loop() -> None:
    settings = get_settings()
    if not settings.agent_auth_token:
        raise RuntimeError("AGENT_AUTH_TOKEN is required")

    cert = None
    if settings.dispatcher_client_cert and settings.dispatcher_client_key:
        cert = (settings.dispatcher_client_cert, settings.dispatcher_client_key)
    verify = settings.dispatcher_ca_cert or True

    dispatcher_id = _dispatcher_id()
    sem = asyncio.Semaphore(max(1, int(settings.dispatcher_concurrency)))

    async with httpx.AsyncClient(cert=cert, verify=verify) as client:
        while True:
            now = datetime.now(timezone.utc)
            delivery_ids = await _claim_deliveries(
                now=now,
                dispatcher_id=dispatcher_id,
                batch_size=settings.dispatcher_batch_size,
                lock_ttl_seconds=settings.dispatcher_lock_ttl_seconds,
            )

            async def _run(delivery_id: uuid.UUID) -> None:
                async with sem:
                    await _process_delivery(
                        client=client,
                        delivery_id=delivery_id,
                        dispatcher_id=dispatcher_id,
                        token=settings.agent_auth_token,
                        max_attempts=int(settings.dispatcher_max_attempts),
                    )

            if delivery_ids:
                await asyncio.gather(*[_run(did) for did in delivery_ids])

            await asyncio.sleep(settings.dispatcher_poll_seconds)


def run() -> None:
    asyncio.run(dispatcher_loop())


if __name__ == "__main__":
    run()

