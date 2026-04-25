from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.api.deps import db_session
from tracegate.enums import ApiScope, RecordStatus
from tracegate.models import ApiToken
from tracegate.settings import get_settings


@dataclass(frozen=True)
class ApiPrincipal:
    token_id: str | None
    token_name: str
    scopes: frozenset[str]
    is_bootstrap: bool


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


def _normalize_scopes(raw: Any) -> frozenset[str]:
    if not isinstance(raw, list):
        return frozenset({ApiScope.ALL.value})
    values = {str(item).strip().lower() for item in raw if str(item).strip()}
    if not values:
        values = {ApiScope.ALL.value}
    return frozenset(values)


def _scope_matches(scope: str, required_scope: str) -> bool:
    if scope == ApiScope.ALL.value or required_scope == ApiScope.ALL.value:
        return True
    if scope == required_scope:
        return True
    if scope.endswith(":rw"):
        prefix = scope[:-3]
        return required_scope in {f"{prefix}:read", f"{prefix}:write", f"{prefix}:rw"}
    return False


def _has_scope(scopes: frozenset[str], required_scope: str) -> bool:
    required = required_scope.strip().lower()
    if not required:
        return True
    return any(_scope_matches(scope, required) for scope in scopes)


async def require_internal_api_token(
    x_api_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
    session: AsyncSession = Depends(db_session),
) -> ApiPrincipal:
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
        return ApiPrincipal(
            token_id=None,
            token_name="bootstrap",
            scopes=frozenset({ApiScope.ALL.value}),
            is_bootstrap=True,
        )

    row = await session.scalar(
        select(ApiToken).where(ApiToken.token_hash == _hash_token(token), ApiToken.status == RecordStatus.ACTIVE)
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API token")

    row.last_used_at = datetime.now(timezone.utc)
    await session.commit()
    return ApiPrincipal(
        token_id=str(row.id),
        token_name=row.name,
        scopes=_normalize_scopes(row.scopes),
        is_bootstrap=False,
    )


def require_api_scope(*required_scopes: str | ApiScope):
    required = [str(scope.value if isinstance(scope, ApiScope) else scope).strip().lower() for scope in required_scopes if str(scope).strip()]

    async def _dependency(principal: ApiPrincipal = Depends(require_internal_api_token)) -> ApiPrincipal:
        if not required:
            return principal
        if any(_has_scope(principal.scopes, item) for item in required):
            return principal
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Insufficient API token scope, required one of: {', '.join(required)}",
        )

    return _dependency


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


async def require_agent_token(
    x_agent_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> None:
    expected = get_settings().agent_auth_token
    if not expected:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Agent token is not configured")

    token = x_agent_token.strip() if x_agent_token else None
    if not token and authorization:
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() == "bearer":
            token = value.strip() or None

    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing agent token")
    if token != expected:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent token")
