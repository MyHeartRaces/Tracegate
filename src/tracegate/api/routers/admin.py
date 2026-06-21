from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.api.deps import db_session
from tracegate.enums import ApiScope, RecordStatus, UserRole
from tracegate.models import Connection, MTProtoAccessGrant, User
from tracegate.schemas import (
    AdminResetConnectionsRequest,
    AdminResetConnectionsResult,
    AdminRevokeUserAccessRequest,
    AdminRevokeUserAccessResult,
)
from tracegate.security import require_api_scope
from tracegate.services.connections import UserAccessRevokeError, revoke_connection, revoke_user_access
from tracegate.services.mtproto_grants import MTProtoGrantError, revoke_mtproto_grant
from tracegate.services.user_roles import can_manage_user
from tracegate.settings import get_settings

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(require_api_scope(ApiScope.CONNECTIONS_RW))],
)


@router.post("/reset-connections", response_model=AdminResetConnectionsResult)
async def reset_connections(
    payload: AdminResetConnectionsRequest,
    session: AsyncSession = Depends(db_session),
) -> AdminResetConnectionsResult:
    actor = await session.get(User, payload.actor_telegram_id)
    if actor is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Actor not found")
    if actor.role not in {UserRole.ADMIN, UserRole.SUPERADMIN}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")

    connection_query = (
        select(Connection.id)
        .join(User, User.telegram_id == Connection.user_id)
        .where(Connection.status == RecordStatus.ACTIVE)
    )
    mtproto_query = (
        select(MTProtoAccessGrant.telegram_id)
        .join(User, User.telegram_id == MTProtoAccessGrant.telegram_id)
        .where(MTProtoAccessGrant.status == RecordStatus.ACTIVE)
    )
    if actor.role != UserRole.SUPERADMIN:
        connection_query = connection_query.where(User.role != UserRole.SUPERADMIN)
        mtproto_query = mtproto_query.where(User.role != UserRole.SUPERADMIN)

    ids = (await session.execute(connection_query)).scalars().all()
    mtproto_user_ids = (await session.execute(mtproto_query)).scalars().all()

    count = 0
    mtproto_count = 0
    for connection_id in ids:
        await revoke_connection(session, connection_id=connection_id)
        count += 1
    for telegram_id in mtproto_user_ids:
        try:
            _grant, removed, _node = await revoke_mtproto_grant(
                session,
                settings=get_settings(),
                telegram_id=int(telegram_id),
                ignore_missing=True,
            )
            if removed:
                mtproto_count += 1
        except MTProtoGrantError as exc:
            await session.rollback()
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    await session.commit()

    return AdminResetConnectionsResult(
        revoked_connections=count,
        revoked_mtproto_accesses=mtproto_count,
        revoked_connection_ids=list(ids),
    )


@router.post("/revoke-user-access", response_model=AdminRevokeUserAccessResult)
async def revoke_user_access_by_telegram_id(
    payload: AdminRevokeUserAccessRequest,
    session: AsyncSession = Depends(db_session),
) -> AdminRevokeUserAccessResult:
    actor = await session.get(User, payload.actor_telegram_id)
    if actor is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Actor not found")
    if actor.role not in {UserRole.ADMIN, UserRole.SUPERADMIN}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")

    target = await session.get(User, payload.target_telegram_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target user not found")
    if not can_manage_user(actor_role=actor.role, target_role=target.role):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient rights for target role")

    active_connection_ids = (
        await session.execute(
            select(Connection.id).where(
                Connection.user_id == target.telegram_id,
                Connection.status == RecordStatus.ACTIVE,
            )
        )
    ).scalars().all()

    try:
        revoked_connections, revoked_devices = await revoke_user_access(session, target.telegram_id)
    except UserAccessRevokeError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    try:
        _grant, revoked_mtproto_access, _node = await revoke_mtproto_grant(
            session,
            settings=get_settings(),
            telegram_id=target.telegram_id,
            ignore_missing=True,
        )
    except MTProtoGrantError as exc:
        await session.rollback()
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    await session.commit()
    return AdminRevokeUserAccessResult(
        target_telegram_id=target.telegram_id,
        revoked_connections=revoked_connections,
        revoked_devices=revoked_devices,
        revoked_mtproto_access=bool(revoked_mtproto_access),
        revoked_connection_ids=list(active_connection_ids),
    )
