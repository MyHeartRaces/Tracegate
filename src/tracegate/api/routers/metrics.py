from __future__ import annotations

from fastapi import APIRouter, Depends, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from tracegate.enums import ApiScope
from tracegate.security import require_api_scope

router = APIRouter(tags=["metrics"])


@router.get("/metrics", dependencies=[Depends(require_api_scope(ApiScope.METRICS_READ))])
def metrics() -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
