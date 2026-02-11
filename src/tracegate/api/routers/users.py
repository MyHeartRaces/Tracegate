from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.api.deps import db_session
from tracegate.enums import EntitlementStatus, UserRole
from tracegate.models import User
from tracegate.schemas import UserCreate, UserEntitlementUpdate, UserRead, UserRoleUpdate
from tracegate.security import require_internal_api_token
from tracegate.settings import get_settings

router = APIRouter(prefix="/users", tags=["users"], dependencies=[Depends(require_internal_api_token)])


@router.get("", response_model=list[UserRead])
async def list_users(
    role: UserRole | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
    session: AsyncSession = Depends(db_session),
) -> list[UserRead]:
    q = select(User).order_by(User.created_at.desc()).limit(limit)
    if role is not None:
        q = q.where(User.role == role)
    rows = (await session.execute(q)).scalars().all()
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
    return UserRead.model_validate(user, from_attributes=True)


@router.get("/telegram/{telegram_id}", response_model=UserRead)
async def get_user_by_telegram(telegram_id: int, session: AsyncSession = Depends(db_session)) -> UserRead:
    user = await session.get(User, telegram_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
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

    await session.commit()
    await session.refresh(user)
    return UserRead.model_validate(user, from_attributes=True)


@router.patch("/{telegram_id}/role", response_model=UserRead)
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
