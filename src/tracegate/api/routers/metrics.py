from __future__ import annotations

from fastapi import APIRouter, Depends, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from tracegate.security import require_internal_api_token

router = APIRouter(tags=["metrics"])


@router.get("/metrics", dependencies=[Depends(require_internal_api_token)])
def metrics() -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

