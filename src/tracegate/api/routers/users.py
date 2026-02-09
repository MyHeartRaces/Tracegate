from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.api.deps import db_session
from tracegate.enums import EntitlementStatus
from tracegate.models import User
from tracegate.schemas import UserCreate, UserEntitlementUpdate, UserRead
from tracegate.security import require_internal_api_token

router = APIRouter(prefix="/users", tags=["users"], dependencies=[Depends(require_internal_api_token)])


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def create_user(payload: UserCreate, session: AsyncSession = Depends(db_session)) -> UserRead:
    existing = await session.scalar(select(User).where(User.telegram_id == payload.telegram_id))
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exists")

    user = User(telegram_id=payload.telegram_id, devices_max=payload.devices_max)
    session.add(user)

    await session.commit()
    await session.refresh(user)
    return UserRead.model_validate(user, from_attributes=True)


@router.get("/{user_id}", response_model=UserRead)
async def get_user(user_id: str, session: AsyncSession = Depends(db_session)) -> UserRead:
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserRead.model_validate(user, from_attributes=True)


@router.get("/telegram/{telegram_id}", response_model=UserRead)
async def get_user_by_telegram(telegram_id: int, session: AsyncSession = Depends(db_session)) -> UserRead:
    user = await session.scalar(select(User).where(User.telegram_id == telegram_id))
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserRead.model_validate(user, from_attributes=True)


@router.patch("/{user_id}/entitlement", response_model=UserRead)
async def set_entitlement(
    user_id: str,
    payload: UserEntitlementUpdate,
    session: AsyncSession = Depends(db_session),
) -> UserRead:
    user = await session.get(User, user_id)
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
