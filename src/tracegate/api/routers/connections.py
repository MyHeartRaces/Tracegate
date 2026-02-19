from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import and_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.api.deps import db_session
from tracegate.enums import ApiScope, ConnectionMode, ConnectionProtocol, ConnectionVariant, RecordStatus
from tracegate.models import Connection, Device, User
from tracegate.schemas import ConnectionCreate, ConnectionRead, ConnectionUpdate
from tracegate.security import require_api_scope
from tracegate.services.aliases import connection_alias, user_display
from tracegate.services.connections import ConnectionRevokeError, revoke_connection
from tracegate.services.overrides import OverrideValidationError, validate_overrides

router = APIRouter(
    prefix="/connections",
    tags=["connections"],
    dependencies=[Depends(require_api_scope(ApiScope.CONNECTIONS_RW))],
)


class ConnectionValidationError(ValueError):
    pass


def _to_connection_read(connection: Connection, *, user: User | None, device: Device | None) -> ConnectionRead:
    username = user.telegram_username if user else None
    first_name = user.telegram_first_name if user else None
    last_name = user.telegram_last_name if user else None
    device_name = device.name if device else None
    user_label = (
        user_display(
            telegram_id=connection.user_id,
            telegram_username=username,
            telegram_first_name=first_name,
            telegram_last_name=last_name,
        )
        if user is not None
        else str(connection.user_id)
    )
    alias = (
        connection_alias(
            telegram_id=connection.user_id,
            telegram_username=username,
            telegram_first_name=first_name,
            telegram_last_name=last_name,
            device_name=device_name or str(connection.device_id),
            connection_id=str(connection.id),
        )
        if user is not None
        else f"{connection.user_id} - {connection.device_id} - {connection.id}"
    )
    return ConnectionRead(
        id=connection.id,
        user_id=connection.user_id,
        device_id=connection.device_id,
        device_name=device_name,
        user_display=user_label,
        alias=alias,
        protocol=connection.protocol,
        mode=connection.mode,
        variant=connection.variant,
        profile_name=connection.profile_name,
        custom_overrides_json=connection.custom_overrides_json,
        status=connection.status,
    )


def validate_variant(protocol: ConnectionProtocol, mode: ConnectionMode, variant: ConnectionVariant) -> None:
    if protocol == ConnectionProtocol.VLESS_REALITY and (mode, variant) in {
        (ConnectionMode.DIRECT, ConnectionVariant.B1),
        (ConnectionMode.CHAIN, ConnectionVariant.B2),
    }:
        return

    if protocol == ConnectionProtocol.VLESS_WS_TLS and (mode, variant) == (ConnectionMode.DIRECT, ConnectionVariant.B1):
        return

    if protocol == ConnectionProtocol.HYSTERIA2 and mode == ConnectionMode.DIRECT and variant == ConnectionVariant.B3:
        return

    if protocol == ConnectionProtocol.WIREGUARD and mode == ConnectionMode.DIRECT and variant == ConnectionVariant.B5:
        return

    raise ConnectionValidationError("Unsupported protocol/mode/variant combination")


@router.get("/by-device/{device_id}", response_model=list[ConnectionRead])
async def list_connections(
    device_id: str,
    include_revoked: bool = False,
    session: AsyncSession = Depends(db_session),
) -> list[ConnectionRead]:
    q = select(Connection).where(Connection.device_id == device_id)
    if not include_revoked:
        q = q.where(Connection.status == RecordStatus.ACTIVE)
    rows = (await session.execute(q)).scalars().all()
    device = await session.get(Device, device_id)
    user = await session.get(User, device.user_id) if device is not None else None
    return [_to_connection_read(row, user=user, device=device) for row in rows]


@router.get("/{connection_id}", response_model=ConnectionRead)
async def get_connection(connection_id: str, session: AsyncSession = Depends(db_session)) -> ConnectionRead:
    row = await session.get(Connection, connection_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found")
    device = await session.get(Device, row.device_id)
    user = await session.get(User, row.user_id)
    return _to_connection_read(row, user=user, device=device)


@router.post("", response_model=ConnectionRead, status_code=status.HTTP_201_CREATED)
async def create_connection(payload: ConnectionCreate, session: AsyncSession = Depends(db_session)) -> ConnectionRead:
    user = await session.get(User, payload.user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    device = await session.get(Device, payload.device_id)
    if device is None or device.user_id != user.telegram_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Device does not belong to user")

    # WireGuard is effectively device-scoped; keep exactly one active WG connection per device.
    if payload.protocol == ConnectionProtocol.WIREGUARD:
        existing_wg = await session.scalar(
            select(Connection.id).where(
                and_(
                    Connection.device_id == device.id,
                    Connection.protocol == ConnectionProtocol.WIREGUARD,
                    Connection.status == RecordStatus.ACTIVE,
                )
            )
        )
        if existing_wg is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="WireGuard connection already exists for this device",
            )

    try:
        validate_variant(payload.protocol, payload.mode, payload.variant)
        validate_overrides(payload.protocol, payload.custom_overrides_json)
    except (ConnectionValidationError, OverrideValidationError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    row = Connection(
        user_id=user.telegram_id,
        device_id=device.id,
        protocol=payload.protocol,
        mode=payload.mode,
        variant=payload.variant,
        profile_name=payload.profile_name,
        custom_overrides_json=payload.custom_overrides_json,
    )
    session.add(row)
    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Connection conflicts with current state") from exc
    await session.refresh(row)
    return _to_connection_read(row, user=user, device=device)


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
    device = await session.get(Device, row.device_id)
    user = await session.get(User, row.user_id)
    return _to_connection_read(row, user=user, device=device)


@router.delete("/{connection_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_connection(connection_id: str, session: AsyncSession = Depends(db_session)) -> None:
    try:
        await revoke_connection(session, connection_id=connection_id)  # type: ignore[arg-type]
        await session.commit()
    except ConnectionRevokeError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
