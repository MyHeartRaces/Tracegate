from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.api.deps import db_session
from tracegate.enums import ConnectionMode, ConnectionProtocol, ConnectionVariant
from tracegate.models import Connection, Device, User
from tracegate.schemas import ConnectionCreate, ConnectionRead, ConnectionUpdate
from tracegate.security import require_internal_api_token
from tracegate.services.connections import ConnectionRevokeError, revoke_connection
from tracegate.services.overrides import OverrideValidationError, validate_overrides

router = APIRouter(prefix="/connections", tags=["connections"], dependencies=[Depends(require_internal_api_token)])


class ConnectionValidationError(ValueError):
    pass


def validate_variant(protocol: ConnectionProtocol, mode: ConnectionMode, variant: ConnectionVariant) -> None:
    if protocol == ConnectionProtocol.VLESS_REALITY and (mode, variant) in {
        (ConnectionMode.DIRECT, ConnectionVariant.B1),
        (ConnectionMode.CHAIN, ConnectionVariant.B2),
    }:
        return

    if protocol == ConnectionProtocol.HYSTERIA2 and mode == ConnectionMode.DIRECT and variant == ConnectionVariant.B3:
        return

    if protocol == ConnectionProtocol.WIREGUARD and mode == ConnectionMode.DIRECT and variant == ConnectionVariant.B5:
        return

    raise ConnectionValidationError("Unsupported protocol/mode/variant combination for v0.1")


@router.get("/by-device/{device_id}", response_model=list[ConnectionRead])
async def list_connections(device_id: str, session: AsyncSession = Depends(db_session)) -> list[ConnectionRead]:
    rows = (await session.execute(select(Connection).where(Connection.device_id == device_id))).scalars().all()
    return [ConnectionRead.model_validate(row, from_attributes=True) for row in rows]


@router.get("/{connection_id}", response_model=ConnectionRead)
async def get_connection(connection_id: str, session: AsyncSession = Depends(db_session)) -> ConnectionRead:
    row = await session.get(Connection, connection_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")
    return ConnectionRead.model_validate(row, from_attributes=True)


@router.post("", response_model=ConnectionRead, status_code=status.HTTP_201_CREATED)
async def create_connection(payload: ConnectionCreate, session: AsyncSession = Depends(db_session)) -> ConnectionRead:
    user = await session.get(User, payload.user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    device = await session.get(Device, payload.device_id)
    if device is None or device.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Device does not belong to user")

    try:
        validate_variant(payload.protocol, payload.mode, payload.variant)
        validate_overrides(payload.protocol, payload.custom_overrides_json)
    except (ConnectionValidationError, OverrideValidationError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    row = Connection(
        user_id=user.id,
        device_id=device.id,
        protocol=payload.protocol,
        mode=payload.mode,
        variant=payload.variant,
        profile_name=payload.profile_name,
        custom_overrides_json=payload.custom_overrides_json,
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return ConnectionRead.model_validate(row, from_attributes=True)


@router.patch("/{connection_id}", response_model=ConnectionRead)
async def update_connection(
    connection_id: str,
    payload: ConnectionUpdate,
    session: AsyncSession = Depends(db_session),
) -> ConnectionRead:
    row = await session.get(Connection, connection_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")

    protocol = row.protocol
    mode = payload.mode if payload.mode is not None else row.mode
    variant = payload.variant if payload.variant is not None else row.variant
    overrides = payload.custom_overrides_json if payload.custom_overrides_json is not None else row.custom_overrides_json

    try:
        validate_variant(protocol, mode, variant)
        validate_overrides(protocol, overrides)
    except (ConnectionValidationError, OverrideValidationError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    if payload.mode is not None:
        row.mode = payload.mode
    if payload.variant is not None:
        row.variant = payload.variant
    if payload.profile_name is not None:
        row.profile_name = payload.profile_name
    if payload.custom_overrides_json is not None:
        row.custom_overrides_json = payload.custom_overrides_json
    if payload.status is not None:
        row.status = payload.status

    await session.commit()
    await session.refresh(row)
    return ConnectionRead.model_validate(row, from_attributes=True)


@router.delete("/{connection_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_connection(connection_id: str, session: AsyncSession = Depends(db_session)) -> None:
    try:
        await revoke_connection(session, connection_id=connection_id)  # type: ignore[arg-type]
        await session.commit()
    except ConnectionRevokeError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
