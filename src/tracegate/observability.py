from __future__ import annotations

import logging
import time
import uuid

from fastapi import FastAPI, Request
from prometheus_client import Counter, Histogram

_HTTP_REQUESTS_TOTAL = Counter(
    "tracegate_http_requests_total",
    "HTTP requests processed by Tracegate services",
    labelnames=["component", "method", "route", "status"],
)
_HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "tracegate_http_request_duration_seconds",
    "HTTP request duration in seconds",
    labelnames=["component", "method", "route"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _route_label(request: Request) -> str:
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    if isinstance(path, str) and path:
        return path
    return request.url.path or "/"


def install_http_observability(app: FastAPI, *, component: str) -> None:
    logger = logging.getLogger(f"tracegate.{component}.http")

    @app.middleware("http")
    async def _tracegate_http_observer(request: Request, call_next):  # noqa: ANN001, ANN202
        request_id = (request.headers.get("x-request-id") or "").strip() or uuid.uuid4().hex[:16]
        started = time.perf_counter()
        method = request.method.upper()
        route = request.url.path or "/"
        status_code = 500

        try:
            response = await call_next(request)
            status_code = int(response.status_code)
            route = _route_label(request)
        except Exception:
            elapsed = max(0.0, time.perf_counter() - started)
            route = _route_label(request)
            _HTTP_REQUESTS_TOTAL.labels(component, method, route, str(status_code)).inc()
            _HTTP_REQUEST_DURATION_SECONDS.labels(component, method, route).observe(elapsed)
            logger.exception(
                "request_failed method=%s route=%s status=%s duration_ms=%.2f request_id=%s",
                method,
                route,
                status_code,
                elapsed * 1000,
                request_id,
            )
            raise

        elapsed = max(0.0, time.perf_counter() - started)
        _HTTP_REQUESTS_TOTAL.labels(component, method, route, str(status_code)).inc()
        _HTTP_REQUEST_DURATION_SECONDS.labels(component, method, route).observe(elapsed)

        response.headers.setdefault("x-request-id", request_id)
        logger.info(
            "request method=%s route=%s status=%s duration_ms=%.2f request_id=%s",
            method,
            route,
            status_code,
            elapsed * 1000,
            request_id,
        )
        return response
