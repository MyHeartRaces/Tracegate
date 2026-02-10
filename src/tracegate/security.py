from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.api.deps import db_session
from tracegate.enums import RecordStatus
from tracegate.models import ApiToken
from tracegate.settings import get_settings


def _extract_token(x_api_token: str | None, authorization: str | None) -> str | None:
    if authorization:
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() == "bearer":
            token = value.strip()
            return token or None
    if x_api_token:
        token = x_api_token.strip()
        return token or None
    return None


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def require_internal_api_token(
    x_api_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
    session: AsyncSession = Depends(db_session),
) -> None:
    """
    Accepts either:
    - `x-api-token: <bootstrap or issued token>`
    - `Authorization: Bearer <issued token>`
    """
    token = _extract_token(x_api_token, authorization)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing API token")

    settings = get_settings()
    if settings.api_internal_token and token == settings.api_internal_token:
        return

    row = await session.scalar(
        select(ApiToken).where(ApiToken.token_hash == _hash_token(token), ApiToken.status == RecordStatus.ACTIVE)
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API token")

    row.last_used_at = datetime.now(timezone.utc)
    await session.commit()


async def require_bootstrap_token(
    x_api_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> None:
    token = _extract_token(x_api_token, authorization)
    settings = get_settings()
    if not settings.api_internal_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bootstrap token is not configured")
    if token != settings.api_internal_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bootstrap token required")


async def require_agent_token(x_agent_token: str | None = Header(default=None)) -> None:
    expected = get_settings().agent_auth_token
    if not expected:
        return
    if x_agent_token != expected:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent token")

