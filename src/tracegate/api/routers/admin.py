from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.api.deps import db_session
from tracegate.enums import ApiScope, RecordStatus, UserRole
from tracegate.models import Connection, User
from tracegate.schemas import AdminResetConnectionsRequest, AdminResetConnectionsResult
from tracegate.security import require_api_scope
from tracegate.services.connections import revoke_connection

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

    ids = (
        await session.execute(select(Connection.id).where(Connection.status == RecordStatus.ACTIVE))
    ).scalars().all()

    count = 0
    for connection_id in ids:
        await revoke_connection(session, connection_id=connection_id)
        count += 1
    await session.commit()

    return AdminResetConnectionsResult(revoked_connections=count)

