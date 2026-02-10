from fastapi import Query
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.api.deps import db_session
from tracegate.models import SniDomain
from tracegate.schemas import SniDomainCreate, SniDomainRead, SniDomainUpdate
from tracegate.security import require_internal_api_token

router = APIRouter(prefix="/sni", tags=["sni"], dependencies=[Depends(require_internal_api_token)])


@router.get("", response_model=list[SniDomainRead])
async def list_sni(
    provider: str | None = Query(default=None),
    enabled_only: bool = Query(default=True),
    session: AsyncSession = Depends(db_session),
) -> list[SniDomainRead]:
    query = select(SniDomain)
    if enabled_only:
        query = query.where(SniDomain.enabled.is_(True))
    rows = (await session.execute(query.order_by(SniDomain.fqdn.asc()))).scalars().all()

    if provider:
        p = provider.strip().lower()
        if p in {"other", "unknown", "none"}:
            rows = [r for r in rows if not (r.providers or [])]
        else:
            rows = [r for r in rows if p in (r.providers or [])]

    return [SniDomainRead.model_validate(row, from_attributes=True) for row in rows]


@router.post("", response_model=SniDomainRead, status_code=status.HTTP_201_CREATED)
async def create_sni(payload: SniDomainCreate, session: AsyncSession = Depends(db_session)) -> SniDomainRead:
    existing = await session.scalar(select(SniDomain).where(SniDomain.fqdn == payload.fqdn))
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="SNI domain already exists")

    row = SniDomain(
        fqdn=payload.fqdn,
        enabled=payload.enabled,
        is_test=payload.is_test,
        note=payload.note,
        providers=payload.providers or [],
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return SniDomainRead.model_validate(row, from_attributes=True)


@router.patch("/{sni_id}", response_model=SniDomainRead)
async def update_sni(sni_id: int, payload: SniDomainUpdate, session: AsyncSession = Depends(db_session)) -> SniDomainRead:
    row = await session.get(SniDomain, sni_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SNI domain not found")

    if payload.enabled is not None:
        row.enabled = payload.enabled
    if payload.is_test is not None:
        row.is_test = payload.is_test
    if payload.note is not None:
        row.note = payload.note
    if payload.providers is not None:
        row.providers = payload.providers

    await session.commit()
    await session.refresh(row)
    return SniDomainRead.model_validate(row, from_attributes=True)
