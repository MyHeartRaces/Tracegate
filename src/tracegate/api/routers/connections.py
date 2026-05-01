from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.api.deps import db_session
from tracegate.enums import ApiScope, ConnectionMode, ConnectionProtocol, ConnectionVariant, RecordStatus
from tracegate.models import Connection, Device, User
from tracegate.schemas import ConnectionCreate, ConnectionRead, ConnectionUpdate
from tracegate.security import require_api_scope
from tracegate.services.connection_profiles import (
    MAX_CONNECTIONS_PER_DEVICE,
    connection_profile_sort_key,
    is_enabled_profile,
    is_supported_profile,
)
from tracegate.services.aliases import connection_alias, user_display
from tracegate.services.connections import ConnectionRevokeError, revoke_connection
from tracegate.services.overrides import OverrideValidationError, validate_overrides
from tracegate.settings import get_settings

router = APIRouter(
    prefix="/connections",
    tags=["connections"],
    dependencies=[Depends(require_api_scope(ApiScope.CONNECTIONS_RW))],
)


class ConnectionValidationError(ValueError):
    pass


_SENSITIVE_OVERRIDE_KEY_FRAGMENTS = (
    "password",
    "private_key",
    "preshared_key",
    "secret",
    "token",
)
_REDACTED_OVERRIDE_VALUE = "REDACTED"
_ENABLED_CLIENT_PROFILES_UNSET = object()


def _is_sensitive_override_key(key: object) -> bool:
    key_lower = str(key).lower()
    return any(fragment in key_lower for fragment in _SENSITIVE_OVERRIDE_KEY_FRAGMENTS)


def _is_redacted_override_value(value: object) -> bool:
    return isinstance(value, str) and value.strip().upper() == _REDACTED_OVERRIDE_VALUE


def _contains_redacted_sensitive_value(value: object) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if _is_sensitive_override_key(key) and _is_redacted_override_value(item):
                return True
            if _contains_redacted_sensitive_value(item):
                return True
    elif isinstance(value, list):
        return any(_contains_redacted_sensitive_value(item) for item in value)
    return False


def _merge_redacted_overrides(existing: object, incoming: object) -> dict:
    existing_dict = existing if isinstance(existing, dict) else {}
    incoming_dict = incoming if isinstance(incoming, dict) else {}
    merged: dict = {}

    for key, item in incoming_dict.items():
        if _is_sensitive_override_key(key) and _is_redacted_override_value(item):
            if key not in existing_dict or existing_dict[key] is None:
                raise ConnectionValidationError("redacted override values require an existing stored value")
            merged[key] = existing_dict[key]
        elif isinstance(item, dict):
            merged[key] = _merge_redacted_overrides(existing_dict.get(key), item)
        elif isinstance(item, list):
            existing_list = existing_dict.get(key)
            if not isinstance(existing_list, list):
                existing_list = []
            merged[key] = [
                _merge_redacted_overrides(existing_list[index] if index < len(existing_list) else {}, child)
                if isinstance(child, dict)
                else child
                for index, child in enumerate(item)
            ]
        else:
            merged[key] = item
    return merged


def _redact_custom_overrides(value: object) -> dict:
    if not isinstance(value, dict):
        return {}
    redacted: dict = {}
    for key, item in value.items():
        if _is_sensitive_override_key(key):
            redacted[key] = _REDACTED_OVERRIDE_VALUE
        elif isinstance(item, dict):
            redacted[key] = _redact_custom_overrides(item)
        elif isinstance(item, list):
            redacted[key] = [
                _redact_custom_overrides(child) if isinstance(child, dict) else child
                for child in item
            ]
        else:
            redacted[key] = item
    return redacted


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
        custom_overrides_json=_redact_custom_overrides(connection.custom_overrides_json),
        status=connection.status,
    )


def validate_variant(
    protocol: ConnectionProtocol,
    mode: ConnectionMode,
    variant: ConnectionVariant,
    *,
    enabled_client_profiles: list[str] | None | object = _ENABLED_CLIENT_PROFILES_UNSET,
) -> None:
    if not is_supported_profile(protocol, mode, variant):
        raise ConnectionValidationError("Unsupported protocol/mode/variant combination")

    configured_profiles = (
        get_settings().enabled_client_profiles
        if enabled_client_profiles is _ENABLED_CLIENT_PROFILES_UNSET
        else enabled_client_profiles
    )
    if not is_enabled_profile(protocol, mode, variant, configured_profiles):  # type: ignore[arg-type]
        raise ConnectionValidationError("Connection profile is disabled in this deployment")


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
    rows = sorted(
        rows,
        key=lambda row: (
            *connection_profile_sort_key(row.protocol, row.mode, row.variant),
            str(row.created_at or ""),
            str(row.id),
        ),
    )
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

    active_count = await session.scalar(
        select(func.count(Connection.id)).where(
            Connection.device_id == device.id,
            Connection.status == RecordStatus.ACTIVE,
        )
    )
    if int(active_count or 0) >= MAX_CONNECTIONS_PER_DEVICE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Connection limit reached for device ({MAX_CONNECTIONS_PER_DEVICE})",
        )

    try:
        validate_variant(payload.protocol, payload.mode, payload.variant)
        if _contains_redacted_sensitive_value(payload.custom_overrides_json):
            raise ConnectionValidationError("redacted override values cannot be used when creating a connection")
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

    try:
        overrides = (
            _merge_redacted_overrides(row.custom_overrides_json, payload.custom_overrides_json)
            if payload.custom_overrides_json is not None
            else row.custom_overrides_json
        )
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
        row.custom_overrides_json = overrides
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
