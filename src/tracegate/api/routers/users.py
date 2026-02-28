from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import delete, select
from sqlalchemy.sql import or_
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.api.deps import db_session
from tracegate.enums import ApiScope, EntitlementStatus, UserRole
from tracegate.models import User
from tracegate.schemas import (
    UserBotBlockUpdate,
    UserCreate,
    UserEntitlementUpdate,
    UserProfileUpdate,
    UserRead,
    UserRoleUpdate,
)
from tracegate.security import require_api_scope
from tracegate.services.connections import revoke_user_access
from tracegate.services.user_cleanup import user_without_artifacts_predicate, user_without_connections_predicate
from tracegate.settings import get_settings

router = APIRouter(prefix="/users", tags=["users"], dependencies=[Depends(require_api_scope(ApiScope.USERS_RW))])


def _normalize_profile_part(value: str | None, *, strip_at: bool = False) -> str | None:
    if value is None:
        return None
    out = value.strip()
    if strip_at:
        out = out.lstrip("@")
    return out or None


def _clear_expired_bot_block(user: User, now: datetime) -> bool:
    if user.bot_blocked_until is None:
        return False
    if user.bot_blocked_until > now:
        return False
    user.bot_blocked_until = None
    user.bot_block_reason = None
    return True


@router.get("", response_model=list[UserRead])
async def list_users(
    role: UserRole | None = Query(default=None),
    blocked_only: bool = Query(default=False),
    include_empty: bool = Query(
        default=False,
        description="Include users without connections.",
    ),
    prune_empty: bool | None = Query(
        default=None,
        description="Override auto-prune for users without devices/connections.",
    ),
    limit: int = Query(default=200, ge=1, le=1000),
    session: AsyncSession = Depends(db_session),
) -> list[UserRead]:
    settings = get_settings()
    effective_prune_empty = settings.users_auto_prune_empty if prune_empty is None else bool(prune_empty)
    user_without_artifacts = user_without_artifacts_predicate()
    user_without_connections = user_without_connections_predicate()

    changed = False
    should_touch_regular_users = role in (None, UserRole.USER)
    if effective_prune_empty and should_touch_regular_users:
        delete_result = await session.execute(
            delete(User).where(
                User.role == UserRole.USER,
                user_without_artifacts,
            )
        )
        changed = int(delete_result.rowcount or 0) > 0

    q = select(User).order_by(User.created_at.desc()).limit(limit)
    if role is not None:
        q = q.where(User.role == role)
    if blocked_only:
        q = q.where(User.bot_blocked_until.is_not(None))
    if (not include_empty) and should_touch_regular_users:
        if role is None:
            q = q.where(or_(User.role != UserRole.USER, ~user_without_connections))
        else:
            q = q.where(~user_without_connections)

    rows = (await session.execute(q)).scalars().all()
    now = datetime.now(timezone.utc)
    for user in rows:
        changed = _clear_expired_bot_block(user, now) or changed
    if changed:
        await session.commit()
    return [UserRead.model_validate(r, from_attributes=True) for r in rows]


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def create_user(payload: UserCreate, session: AsyncSession = Depends(db_session)) -> UserRead:
    existing = await session.get(User, payload.telegram_id)
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exists")

    settings = get_settings()
    role = UserRole.SUPERADMIN if payload.telegram_id in (settings.superadmin_telegram_ids or []) else UserRole.USER
    user = User(telegram_id=payload.telegram_id, devices_max=payload.devices_max, role=role)
    session.add(user)

    await session.commit()
    await session.refresh(user)
    return UserRead.model_validate(user, from_attributes=True)


@router.get("/{telegram_id}", response_model=UserRead)
async def get_user(telegram_id: int, session: AsyncSession = Depends(db_session)) -> UserRead:
    user = await session.get(User, telegram_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if _clear_expired_bot_block(user, datetime.now(timezone.utc)):
        await session.commit()
    return UserRead.model_validate(user, from_attributes=True)


@router.get("/telegram/{telegram_id}", response_model=UserRead)
async def get_user_by_telegram(telegram_id: int, session: AsyncSession = Depends(db_session)) -> UserRead:
    user = await session.get(User, telegram_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if _clear_expired_bot_block(user, datetime.now(timezone.utc)):
        await session.commit()
    return UserRead.model_validate(user, from_attributes=True)


@router.patch("/{telegram_id}/profile", response_model=UserRead)
async def update_profile(
    telegram_id: int,
    payload: UserProfileUpdate,
    session: AsyncSession = Depends(db_session),
) -> UserRead:
    user = await session.get(User, telegram_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if payload.telegram_username is not None:
        user.telegram_username = _normalize_profile_part(payload.telegram_username, strip_at=True)
    if payload.telegram_first_name is not None:
        user.telegram_first_name = _normalize_profile_part(payload.telegram_first_name)
    if payload.telegram_last_name is not None:
        user.telegram_last_name = _normalize_profile_part(payload.telegram_last_name)

    await session.commit()
    await session.refresh(user)
    return UserRead.model_validate(user, from_attributes=True)


@router.patch("/{telegram_id}/entitlement", response_model=UserRead)
async def set_entitlement(
    telegram_id: int,
    payload: UserEntitlementUpdate,
    session: AsyncSession = Depends(db_session),
) -> UserRead:
    user = await session.get(User, telegram_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.entitlement_status = payload.entitlement_status
    if payload.entitlement_status == EntitlementStatus.GRACE:
        user.grace_ends_at = payload.grace_ends_at or (datetime.now(timezone.utc) + timedelta(days=7))
    else:
        user.grace_ends_at = payload.grace_ends_at
    if payload.entitlement_status == EntitlementStatus.BLOCKED:
        await revoke_user_access(session, user.telegram_id)

    await session.commit()
    await session.refresh(user)
    return UserRead.model_validate(user, from_attributes=True)


@router.patch(
    "/{telegram_id}/role",
    response_model=UserRead,
    dependencies=[Depends(require_api_scope(ApiScope.USERS_ROLE))],
)
async def set_role(
    telegram_id: int,
    payload: UserRoleUpdate,
    session: AsyncSession = Depends(db_session),
) -> UserRead:
    user = await session.get(User, telegram_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.role = payload.role
    await session.commit()
    await session.refresh(user)
    return UserRead.model_validate(user, from_attributes=True)


@router.patch("/{telegram_id}/bot-block", response_model=UserRead)
async def bot_block_user(
    telegram_id: int,
    payload: UserBotBlockUpdate,
    session: AsyncSession = Depends(db_session),
) -> UserRead:
    user = await session.get(User, telegram_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.role == UserRole.SUPERADMIN:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot block superadmin")

    now = datetime.now(timezone.utc)
    user.bot_blocked_until = now + timedelta(hours=int(payload.hours))
    user.bot_block_reason = _normalize_profile_part(payload.reason)

    if payload.revoke_access:
        await revoke_user_access(session, user.telegram_id)

    await session.commit()
    await session.refresh(user)
    return UserRead.model_validate(user, from_attributes=True)


@router.post("/{telegram_id}/bot-unblock", response_model=UserRead)
async def bot_unblock_user(telegram_id: int, session: AsyncSession = Depends(db_session)) -> UserRead:
    user = await session.get(User, telegram_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.bot_blocked_until = None
    user.bot_block_reason = None

    await session.commit()
    await session.refresh(user)
    return UserRead.model_validate(user, from_attributes=True)
