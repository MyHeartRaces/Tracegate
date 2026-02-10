from __future__ import annotations

import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.api.deps import db_session
from tracegate.enums import RecordStatus
from tracegate.models import ApiToken
from tracegate.schemas import ApiTokenCreate, ApiTokenCreated, ApiTokenRead
from tracegate.security import _hash_token, require_bootstrap_token, require_internal_api_token

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/tokens", response_model=list[ApiTokenRead], dependencies=[Depends(require_internal_api_token)])
async def list_tokens(session: AsyncSession = Depends(db_session)) -> list[ApiTokenRead]:
    rows = (await session.execute(select(ApiToken).order_by(ApiToken.created_at.desc()))).scalars().all()
    return [ApiTokenRead.model_validate(row, from_attributes=True) for row in rows]


@router.post(
    "/tokens",
    response_model=ApiTokenCreated,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_bootstrap_token)],
)
async def create_token(payload: ApiTokenCreate, session: AsyncSession = Depends(db_session)) -> ApiTokenCreated:
    existing = await session.scalar(select(ApiToken).where(ApiToken.name == payload.name))
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token name already exists")

    token = secrets.token_urlsafe(32)
    row = ApiToken(
        name=payload.name,
        token_hash=_hash_token(token),
        status=RecordStatus.ACTIVE,
        created_at=datetime.now(timezone.utc),
        last_used_at=None,
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return ApiTokenCreated(token=token, token_meta=ApiTokenRead.model_validate(row, from_attributes=True))


@router.delete("/tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_bootstrap_token)])
async def revoke_token(token_id: str, session: AsyncSession = Depends(db_session)) -> None:
    row = await session.get(ApiToken, token_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token not found")
    row.status = RecordStatus.REVOKED
    await session.commit()

