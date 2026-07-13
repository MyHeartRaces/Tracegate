from fastapi import APIRouter, HTTPException, status
from sqlalchemy import text

from tracegate.db import get_sessionmaker
from tracegate.schemas import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get("/ready", response_model=HealthResponse)
async def ready() -> HealthResponse:
    try:
        async with get_sessionmaker()() as session:
            await session.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="database unavailable") from exc
    return HealthResponse(status="ready")
