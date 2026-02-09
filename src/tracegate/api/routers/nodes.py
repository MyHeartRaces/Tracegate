from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tracegate.api.deps import db_session
from tracegate.models import NodeEndpoint
from tracegate.schemas import NodeEndpointCreate, NodeEndpointRead
from tracegate.security import require_internal_api_token

router = APIRouter(prefix="/nodes", tags=["nodes"], dependencies=[Depends(require_internal_api_token)])


@router.get("", response_model=list[NodeEndpointRead])
async def list_nodes(session: AsyncSession = Depends(db_session)) -> list[NodeEndpointRead]:
    rows = (await session.execute(select(NodeEndpoint).order_by(NodeEndpoint.created_at.asc()))).scalars().all()
    return [NodeEndpointRead.model_validate(row, from_attributes=True) for row in rows]


@router.post("", response_model=NodeEndpointRead, status_code=status.HTTP_201_CREATED)
async def create_node(payload: NodeEndpointCreate, session: AsyncSession = Depends(db_session)) -> NodeEndpointRead:
    existing = await session.scalar(select(NodeEndpoint).where(NodeEndpoint.name == payload.name))
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Node with this name already exists")

    row = NodeEndpoint(
        role=payload.role,
        name=payload.name,
        base_url=payload.base_url.rstrip("/"),
        public_ipv4=payload.public_ipv4,
        fqdn=payload.fqdn,
        active=payload.active,
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return NodeEndpointRead.model_validate(row, from_attributes=True)
