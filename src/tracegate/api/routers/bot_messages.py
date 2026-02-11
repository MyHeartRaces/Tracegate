from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.api.deps import db_session
from tracegate.enums import ApiScope
from tracegate.models import BotMessageRef
from tracegate.schemas import BotMessageCleanupRequest, BotMessageRefCreate, BotMessageRefRead
from tracegate.security import require_api_scope

router = APIRouter(
    prefix="/bot-messages",
    tags=["bot-messages"],
    dependencies=[Depends(require_api_scope(ApiScope.BOT_MESSAGES_RW))],
)


def _build_filters(
    *,
    connection_id: UUID | None,
    device_id: UUID | None,
    revision_id: UUID | None,
) -> list:
    filters = []
    if connection_id is not None:
        filters.append(BotMessageRef.connection_id == connection_id)
    if device_id is not None:
        filters.append(BotMessageRef.device_id == device_id)
    if revision_id is not None:
        filters.append(BotMessageRef.revision_id == revision_id)
    return filters


@router.post("", response_model=BotMessageRefRead, status_code=status.HTTP_201_CREATED)
async def create_bot_message_ref(payload: BotMessageRefCreate, session: AsyncSession = Depends(db_session)) -> BotMessageRefRead:
    row = await session.scalar(
        select(BotMessageRef).where(
            BotMessageRef.chat_id == payload.chat_id,
            BotMessageRef.message_id == payload.message_id,
        )
    )
    if row is None:
        row = BotMessageRef(
            telegram_id=payload.telegram_id,
            chat_id=payload.chat_id,
            message_id=payload.message_id,
            connection_id=payload.connection_id,
            device_id=payload.device_id,
            revision_id=payload.revision_id,
            removed_at=None,
        )
        session.add(row)
    else:
        row.telegram_id = payload.telegram_id
        row.connection_id = payload.connection_id
        row.device_id = payload.device_id
        row.revision_id = payload.revision_id
        row.removed_at = None

    await session.commit()
    await session.refresh(row)
    return BotMessageRefRead.model_validate(row, from_attributes=True)


@router.get("", response_model=list[BotMessageRefRead])
async def list_bot_message_refs(
    connection_id: UUID | None = Query(default=None),
    device_id: UUID | None = Query(default=None),
    revision_id: UUID | None = Query(default=None),
    include_removed: bool = Query(default=False),
    session: AsyncSession = Depends(db_session),
) -> list[BotMessageRefRead]:
    q = select(BotMessageRef)
    filters = _build_filters(connection_id=connection_id, device_id=device_id, revision_id=revision_id)
    if filters:
        q = q.where(and_(*filters))
    if not include_removed:
        q = q.where(BotMessageRef.removed_at.is_(None))
    q = q.order_by(BotMessageRef.created_at.asc())
    rows = (await session.execute(q)).scalars().all()
    return [BotMessageRefRead.model_validate(row, from_attributes=True) for row in rows]


@router.post("/cleanup", response_model=list[BotMessageRefRead])
async def cleanup_bot_message_refs(
    payload: BotMessageCleanupRequest,
    session: AsyncSession = Depends(db_session),
) -> list[BotMessageRefRead]:
    filters = _build_filters(
        connection_id=payload.connection_id,
        device_id=payload.device_id,
        revision_id=payload.revision_id,
    )
    if not filters:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="At least one filter is required")

    q = (
        select(BotMessageRef)
        .where(and_(BotMessageRef.removed_at.is_(None), *filters))
        .order_by(BotMessageRef.created_at.asc())
    )
    rows = (await session.execute(q)).scalars().all()
    if not rows:
        return []

    now = datetime.now(timezone.utc)
    for row in rows:
        row.removed_at = now
    await session.commit()
    return [BotMessageRefRead.model_validate(row, from_attributes=True) for row in rows]
