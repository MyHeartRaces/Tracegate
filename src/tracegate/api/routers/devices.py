from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.api.deps import db_session
from tracegate.enums import ApiScope, EntitlementStatus, RecordStatus
from tracegate.models import Connection, Device, User
from tracegate.schemas import DeviceCreate, DeviceRead, DeviceRename
from tracegate.security import require_api_scope
from tracegate.services.connections import revoke_connection

router = APIRouter(prefix="/devices", tags=["devices"], dependencies=[Depends(require_api_scope(ApiScope.DEVICES_RW))])


def _blocked_by_grace(user: User) -> bool:
    if user.entitlement_status != EntitlementStatus.GRACE:
        return False
    if user.grace_ends_at is None:
        return True
    return user.grace_ends_at >= datetime.now(timezone.utc)


@router.get("/by-user/{user_id}", response_model=list[DeviceRead])
async def list_user_devices(user_id: int, session: AsyncSession = Depends(db_session)) -> list[DeviceRead]:
    rows = (
        await session.execute(
            select(Device).where(Device.user_id == user_id, Device.status == RecordStatus.ACTIVE).order_by(Device.created_at.asc())
        )
    ).scalars().all()
    return [DeviceRead.model_validate(row, from_attributes=True) for row in rows]


@router.post("", response_model=DeviceRead, status_code=status.HTTP_201_CREATED)
async def create_device(payload: DeviceCreate, session: AsyncSession = Depends(db_session)) -> DeviceRead:
    user = await session.get(User, payload.user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if user.entitlement_status == EntitlementStatus.BLOCKED or _blocked_by_grace(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot issue new device in grace/blocked state")

    count = await session.scalar(
        select(func.count(Device.id)).where(and_(Device.user_id == user.telegram_id, Device.status == RecordStatus.ACTIVE))
    )
    if count >= user.devices_max:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Device limit reached ({user.devices_max})")

    row = Device(user_id=user.telegram_id, name=payload.name)
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return DeviceRead.model_validate(row, from_attributes=True)


@router.patch("/{device_id}", response_model=DeviceRead)
async def rename_device(device_id: str, payload: DeviceRename, session: AsyncSession = Depends(db_session)) -> DeviceRead:
    row = await session.get(Device, device_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    row.name = payload.name
    await session.commit()
    await session.refresh(row)
    return DeviceRead.model_validate(row, from_attributes=True)


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(device_id: str, session: AsyncSession = Depends(db_session)) -> None:
    row = await session.get(Device, device_id)
    if row is None:
        return

    # Revoke all active connections for this device so access is actually removed on nodes.
    connections = (
        await session.execute(
            select(Connection).where(Connection.device_id == row.id, Connection.status == RecordStatus.ACTIVE)
        )
    ).scalars().all()
    for conn in connections:
        await revoke_connection(session, connection_id=conn.id)

    row.status = RecordStatus.REVOKED
    await session.commit()
