from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.api.deps import db_session
from tracegate.enums import ApiScope, RecordStatus
from tracegate.models import MTProtoAccessGrant
from tracegate.schemas import (
    MTProtoAccessIssueRequest,
    MTProtoAccessIssueResult,
    MTProtoAccessRead,
    MTProtoAccessRevokeResult,
)
from tracegate.security import require_api_scope
from tracegate.services.mtproto_grants import MTProtoGrantError, issue_mtproto_grant, revoke_mtproto_grant
from tracegate.settings import get_settings

router = APIRouter(
    prefix="/mtproto/access",
    tags=["mtproto"],
    dependencies=[Depends(require_api_scope(ApiScope.USERS_RW))],
)


def _to_read(grant: MTProtoAccessGrant) -> MTProtoAccessRead:
    return MTProtoAccessRead.model_validate(grant, from_attributes=True)


@router.get("", response_model=list[MTProtoAccessRead])
async def list_mtproto_access(
    include_revoked: bool = Query(default=False),
    session: AsyncSession = Depends(db_session),
) -> list[MTProtoAccessRead]:
    query = select(MTProtoAccessGrant).order_by(MTProtoAccessGrant.updated_at.desc())
    if not include_revoked:
        query = query.where(MTProtoAccessGrant.status == RecordStatus.ACTIVE)
    rows = (await session.execute(query)).scalars().all()
    return [_to_read(row) for row in rows]


@router.get("/by-user/{telegram_id}", response_model=MTProtoAccessRead)
async def get_mtproto_access(telegram_id: int, session: AsyncSession = Depends(db_session)) -> MTProtoAccessRead:
    grant = await session.get(MTProtoAccessGrant, telegram_id)
    if grant is None or grant.status != RecordStatus.ACTIVE:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="MTProto access grant not found")
    return _to_read(grant)


@router.post("/issue", response_model=MTProtoAccessIssueResult)
async def issue_mtproto_access(
    payload: MTProtoAccessIssueRequest,
    session: AsyncSession = Depends(db_session),
) -> MTProtoAccessIssueResult:
    try:
        grant, profile, changed, node = await issue_mtproto_grant(
            session,
            settings=get_settings(),
            telegram_id=payload.telegram_id,
            label=payload.label,
            rotate=payload.rotate,
            issued_by=payload.issued_by,
        )
    except MTProtoGrantError as exc:
        await session.rollback()
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    await session.commit()
    await session.refresh(grant)
    return MTProtoAccessIssueResult(grant=_to_read(grant), profile=profile, changed=changed, node=node)


@router.delete("/{telegram_id}", response_model=MTProtoAccessRevokeResult)
async def revoke_mtproto_access(
    telegram_id: int,
    response: Response,
    session: AsyncSession = Depends(db_session),
) -> MTProtoAccessRevokeResult:
    try:
        grant, removed, node = await revoke_mtproto_grant(
            session,
            settings=get_settings(),
            telegram_id=telegram_id,
            ignore_missing=False,
        )
    except MTProtoGrantError as exc:
        await session.rollback()
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    await session.commit()
    if grant is None and not removed:
        response.status_code = status.HTTP_404_NOT_FOUND
    return MTProtoAccessRevokeResult(telegram_id=telegram_id, removed=removed, node=node)
