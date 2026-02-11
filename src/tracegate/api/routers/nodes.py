from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.api.deps import db_session
from tracegate.enums import ApiScope
from tracegate.models import NodeEndpoint
from tracegate.schemas import NodeEndpointCreate, NodeEndpointRead, NodeEndpointUpdate
from tracegate.security import require_api_scope

router = APIRouter(prefix="/nodes", tags=["nodes"], dependencies=[Depends(require_api_scope(ApiScope.NODES_RW))])


@router.get("", response_model=list[NodeEndpointRead])
async def list_nodes(session: AsyncSession = Depends(db_session)) -> list[NodeEndpointRead]:
    rows = (await session.execute(select(NodeEndpoint).order_by(NodeEndpoint.created_at.asc()))).scalars().all()
    return [NodeEndpointRead.model_validate(row, from_attributes=True) for row in rows]


@router.post("", response_model=NodeEndpointRead)
async def create_node(
    payload: NodeEndpointCreate,
    response: Response,
    session: AsyncSession = Depends(db_session),
) -> NodeEndpointRead:
    existing = await session.scalar(select(NodeEndpoint).where(NodeEndpoint.name == payload.name))
    if existing:
        existing.role = payload.role
        existing.base_url = payload.base_url.rstrip("/")
        existing.public_ipv4 = payload.public_ipv4
        existing.fqdn = payload.fqdn
        existing.proxy_fqdn = payload.proxy_fqdn
        existing.active = payload.active
        await session.commit()
        await session.refresh(existing)
        return NodeEndpointRead.model_validate(existing, from_attributes=True)

    row = NodeEndpoint(
        role=payload.role,
        name=payload.name,
        base_url=payload.base_url.rstrip("/"),
        public_ipv4=payload.public_ipv4,
        fqdn=payload.fqdn,
        proxy_fqdn=payload.proxy_fqdn,
        active=payload.active,
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    response.status_code = status.HTTP_201_CREATED
    return NodeEndpointRead.model_validate(row, from_attributes=True)


@router.patch("/{node_id}", response_model=NodeEndpointRead)
async def update_node(node_id: str, payload: NodeEndpointUpdate, session: AsyncSession = Depends(db_session)) -> NodeEndpointRead:
    row = await session.get(NodeEndpoint, node_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")

    if payload.base_url is not None:
        row.base_url = payload.base_url.rstrip("/")
    if payload.public_ipv4 is not None:
        row.public_ipv4 = payload.public_ipv4
    if payload.fqdn is not None:
        row.fqdn = payload.fqdn
    if payload.proxy_fqdn is not None:
        row.proxy_fqdn = payload.proxy_fqdn
    if payload.active is not None:
        row.active = payload.active

    await session.commit()
    await session.refresh(row)
    return NodeEndpointRead.model_validate(row, from_attributes=True)
