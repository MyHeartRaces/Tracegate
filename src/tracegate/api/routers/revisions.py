from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.api.deps import db_session
from tracegate.models import ConnectionRevision
from tracegate.schemas import RevisionCreate, RevisionRead
from tracegate.security import require_internal_api_token
from tracegate.services.grace import GraceError
from tracegate.services.revisions import RevisionError, activate_revision, create_revision, revoke_revision

router = APIRouter(prefix="/revisions", tags=["revisions"], dependencies=[Depends(require_internal_api_token)])


@router.get("/by-connection/{connection_id}", response_model=list[RevisionRead])
async def list_revisions(connection_id: str, session: AsyncSession = Depends(db_session)) -> list[RevisionRead]:
    rows = (
        await session.execute(
            select(ConnectionRevision)
            .where(ConnectionRevision.connection_id == connection_id)
            .order_by(ConnectionRevision.created_at.desc())
        )
    ).scalars().all()
    return [RevisionRead.model_validate(row, from_attributes=True) for row in rows]


@router.post("/by-connection/{connection_id}", response_model=RevisionRead, status_code=status.HTTP_201_CREATED)
async def issue_revision(
    connection_id: UUID,
    payload: RevisionCreate,
    session: AsyncSession = Depends(db_session),
) -> RevisionRead:
    try:
        revision = await create_revision(
            session,
            connection_id=connection_id,
            camouflage_sni_id=payload.camouflage_sni_id,
            force=payload.force,
        )
        await session.commit()
    except (RevisionError, GraceError, ValueError) as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    await session.refresh(revision)
    return RevisionRead.model_validate(revision, from_attributes=True)


@router.post("/{revision_id}/activate", response_model=RevisionRead)
async def set_active_revision(revision_id: UUID, session: AsyncSession = Depends(db_session)) -> RevisionRead:
    try:
        revision = await activate_revision(session, revision_id)
        await session.commit()
    except RevisionError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    await session.refresh(revision)
    return RevisionRead.model_validate(revision, from_attributes=True)


@router.post("/{revision_id}/revoke", response_model=RevisionRead)
async def revoke_revision_endpoint(revision_id: UUID, session: AsyncSession = Depends(db_session)) -> RevisionRead:
    try:
        revision = await revoke_revision(session, revision_id)
        await session.commit()
    except RevisionError as exc:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    await session.refresh(revision)
    return RevisionRead.model_validate(revision, from_attributes=True)
