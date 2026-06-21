from __future__ import annotations

import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.api.deps import db_session
from tracegate.enums import ApiScope, RecordStatus
from tracegate.models import ApiToken
from tracegate.schemas import ApiTokenCreate, ApiTokenCreated, ApiTokenRead
from tracegate.security import _hash_token, require_api_scope

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/scopes", response_model=list[str], dependencies=[Depends(require_api_scope(ApiScope.TOKENS_READ))])
async def list_scopes() -> list[str]:
    return [scope.value for scope in ApiScope]


@router.get("/tokens", response_model=list[ApiTokenRead], dependencies=[Depends(require_api_scope(ApiScope.TOKENS_READ))])
async def list_tokens(session: AsyncSession = Depends(db_session)) -> list[ApiTokenRead]:
    rows = (await session.execute(select(ApiToken).order_by(ApiToken.created_at.desc()))).scalars().all()
    return [ApiTokenRead.model_validate(row, from_attributes=True) for row in rows]


@router.post(
    "/tokens",
    response_model=ApiTokenCreated,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_api_scope(ApiScope.TOKENS_WRITE))],
)
async def create_token(payload: ApiTokenCreate, session: AsyncSession = Depends(db_session)) -> ApiTokenCreated:
    existing = await session.scalar(select(ApiToken).where(ApiToken.name == payload.name))
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token name already exists")

    token = secrets.token_urlsafe(32)
    scopes = sorted({scope.value for scope in payload.scopes}, key=str)
    row = ApiToken(
        name=payload.name,
        token_hash=_hash_token(token),
        scopes=scopes,
        status=RecordStatus.ACTIVE,
        created_at=datetime.now(timezone.utc),
        last_used_at=None,
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return ApiTokenCreated(token=token, token_meta=ApiTokenRead.model_validate(row, from_attributes=True))


@router.delete(
    "/tokens/{token_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_api_scope(ApiScope.TOKENS_WRITE))],
)
async def revoke_token(token_id: str, session: AsyncSession = Depends(db_session)) -> None:
    row = await session.get(ApiToken, token_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token not found")
    row.status = RecordStatus.REVOKED
    await session.commit()
