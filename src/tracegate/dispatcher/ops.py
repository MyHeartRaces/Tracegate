from __future__ import annotations

import asyncio
import logging
import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from prometheus_client import Counter, Gauge
from sqlalchemy import delete, func, select

from tracegate.db import get_sessionmaker
from tracegate.enums import DeliveryStatus, OutboxStatus, UserRole
from tracegate.models import OutboxDelivery, OutboxEvent, User
from tracegate.settings import Settings

logger = logging.getLogger("tracegate.dispatcher.ops")

_OPS_CHECKS_TOTAL = Counter(
    "tracegate_dispatcher_ops_checks_total",
    "Number of periodic dispatcher ops checks",
    labelnames=["check", "result"],
)
_OPS_ALERT_MESSAGES_TOTAL = Counter(
    "tracegate_dispatcher_ops_alert_messages_total",
    "Number of ops alert messages sent via Telegram",
    labelnames=["kind", "result"],
)
_OPS_ACTIVE_ALERTS = Gauge(
    "tracegate_dispatcher_ops_active_alerts",
    "Current number of active ops alerts tracked by dispatcher",
)
_OPS_OUTBOX_DELIVERIES = Gauge(
    "tracegate_ops_outbox_deliveries",
    "Current outbox delivery counts by status",
    labelnames=["status"],
)
_OPS_OUTBOX_PENDING_OLDER_THAN_5M = Gauge(
    "tracegate_ops_outbox_pending_older_than_5m_deliveries",
    "Current number of outbox deliveries pending/failed older than five minutes",
)
_OPS_GATEWAY_CONTAINER_RESTARTS = Gauge(
    "tracegate_ops_gateway_container_restart_count",
    "Current gateway container restartCount observed from Kubernetes",
    labelnames=["component", "container"],
)
_OPS_COMPONENT_PODS = Gauge(
    "tracegate_ops_component_pods",
    "Observed and ready pod counts for key components",
    labelnames=["component", "state"],
)
_OPS_NODE_READY = Gauge(
    "tracegate_ops_node_ready",
    "Kubernetes node readiness (1=Ready, 0=NotReady)",
    labelnames=["node"],
)
_OPS_METRICS_SERVER_NODE_AGE_SECONDS = Gauge(
    "tracegate_ops_metrics_server_node_metric_age_seconds",
    "Age of latest metrics-server node metrics sample in seconds",
    labelnames=["node"],
)
_OPS_DISK_USED_PERCENT = Gauge(
    "tracegate_ops_disk_used_percent",
    "Disk usage percent for root filesystem (from node-exporter via Prometheus query)",
    labelnames=["instance"],
)
_OPS_COMPONENT_IMAGE_INFO = Gauge(
    "tracegate_ops_component_image_info",
    "Observed container image for key components (constant 1)",
    labelnames=["component", "image"],
)
_OUTBOX_PURGE_RUNS_TOTAL = Counter(
    "tracegate_dispatcher_outbox_purge_runs_total",
    "Number of outbox retention purge runs",
    labelnames=["result"],
)
_OUTBOX_PURGED_EVENTS_TOTAL = Counter(
    "tracegate_dispatcher_outbox_purged_events_total",
    "Number of outbox events deleted by retention policy",
    labelnames=["status_bucket"],
)

_TELEGRAM_API_BASE = "https://api.telegram.org"
_K8S_SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")
_K8S_TOKEN_FILE = _K8S_SA_DIR / "token"
_K8S_CA_FILE = _K8S_SA_DIR / "ca.crt"
_K8S_NS_FILE = _K8S_SA_DIR / "namespace"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_rfc3339(raw: str | None) -> datetime | None:
    if not raw:
        return None
    value = str(raw).strip()
    if not value:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _safe_pct(value: float) -> str:
    return f"{value:.1f}%"


def _ops_alert_text(kind: str, text: str) -> str:
    body = str(text or "").strip() or "No details"
    headers = {
        "alert": "❗ OPS Alert",
        "repeat": "⏰ OPS Reminder",
        "resolved": "✅ OPS Resolved",
    }
    header = headers.get(kind, "ℹ️ OPS")
    return f"{header}\n\n{body}"


def _bool_env_file(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def _k8s_api_base_url() -> str:
    host = (os.getenv("KUBERNETES_SERVICE_HOST") or "").strip()
    if not host:
        return "https://kubernetes.default.svc"
    port = (os.getenv("KUBERNETES_SERVICE_PORT_HTTPS") or os.getenv("KUBERNETES_SERVICE_PORT") or "443").strip()
    return f"https://{host}:{port}"


def _k8s_namespace() -> str:
    from_file = _bool_env_file(_K8S_NS_FILE)
    if from_file:
        return from_file
    return (os.getenv("POD_NAMESPACE") or "default").strip() or "default"


@dataclass(slots=True)
class _ActiveAlert:
    text: str
    since: datetime
    last_sent_at: datetime | None = None


@dataclass(slots=True)
class _OpsState:
    restart_counts: dict[tuple[str, str], int] = field(default_factory=dict)
    active_alerts: dict[str, _ActiveAlert] = field(default_factory=dict)
    expected_components: set[str] = field(default_factory=set)
    component_image_keys: set[tuple[str, str]] = field(default_factory=set)
    node_ready_keys: set[str] = field(default_factory=set)
    metrics_age_node_keys: set[str] = field(default_factory=set)
    disk_instance_keys: set[str] = field(default_factory=set)
    initialized: bool = False


@dataclass(slots=True)
class _K8sContext:
    namespace: str
    client: httpx.AsyncClient


async def outbox_purge_loop(settings: Settings) -> None:
    if not settings.dispatcher_outbox_retention_enabled:
        logger.info("outbox_retention_disabled")
        return

    logger.info(
        "outbox_retention_enabled interval_s=%s sent_days=%s failed_days=%s batch_size=%s max_batches=%s",
        settings.dispatcher_outbox_retention_interval_seconds,
        settings.dispatcher_outbox_retention_sent_days,
        settings.dispatcher_outbox_retention_failed_days,
        settings.dispatcher_outbox_retention_batch_size,
        settings.dispatcher_outbox_retention_max_batches_per_run,
    )
    while True:
        try:
            deleted_total = await purge_outbox_history_once(settings)
            _OUTBOX_PURGE_RUNS_TOTAL.labels("ok").inc()
            if deleted_total:
                logger.info("outbox_retention_purged deleted=%s", deleted_total)
        except Exception:  # noqa: BLE001
            _OUTBOX_PURGE_RUNS_TOTAL.labels("error").inc()
            logger.exception("outbox_retention_failed")
        await asyncio.sleep(max(60, int(settings.dispatcher_outbox_retention_interval_seconds)))


async def purge_outbox_history_once(settings: Settings) -> int:
    now = _utcnow()
    sent_cutoff = now - timedelta(days=max(1, int(settings.dispatcher_outbox_retention_sent_days)))
    failed_cutoff = now - timedelta(days=max(1, int(settings.dispatcher_outbox_retention_failed_days)))
    batch_size = max(1, int(settings.dispatcher_outbox_retention_batch_size))
    max_batches = max(1, int(settings.dispatcher_outbox_retention_max_batches_per_run))

    deleted_total = 0
    for _ in range(max_batches):
        deleted = await _purge_outbox_batch(
            statuses=[OutboxStatus.SENT],
            updated_before=sent_cutoff,
            batch_size=batch_size,
            status_bucket="sent",
        )
        deleted_total += deleted
        if deleted < batch_size:
            break

    for _ in range(max_batches):
        deleted = await _purge_outbox_batch(
            statuses=[OutboxStatus.FAILED],
            updated_before=failed_cutoff,
            batch_size=batch_size,
            status_bucket="failed",
        )
        deleted_total += deleted
        if deleted < batch_size:
            break

    return deleted_total


async def _purge_outbox_batch(
    *,
    statuses: list[OutboxStatus],
    updated_before: datetime,
    batch_size: int,
    status_bucket: str,
) -> int:
    async with get_sessionmaker()() as session:
        ids = (
            await session.execute(
                select(OutboxEvent.id)
                .where(
                    OutboxEvent.status.in_(statuses),
                    OutboxEvent.updated_at < updated_before,
                )
                .order_by(OutboxEvent.updated_at.asc())
                .limit(batch_size)
            )
        ).scalars().all()
        if not ids:
            return 0

        await session.execute(delete(OutboxEvent).where(OutboxEvent.id.in_(ids)))
        await session.commit()

    _OUTBOX_PURGED_EVENTS_TOTAL.labels(status_bucket).inc(len(ids))
    return len(ids)


async def ops_alert_loop(settings: Settings) -> None:
    if not settings.dispatcher_ops_alerts_enabled:
        logger.info("ops_alerts_disabled")
        return

    state = _OpsState()
    namespace = _k8s_namespace()
    k8s_ctx = await _build_k8s_context(settings, namespace=namespace)
    logger.info(
        "ops_alerts_enabled poll_s=%s namespace=%s prometheus_url=%s",
        settings.dispatcher_ops_alerts_poll_seconds,
        namespace,
        settings.dispatcher_ops_alerts_prometheus_url,
    )

    try:
        async with httpx.AsyncClient(timeout=settings.dispatcher_ops_alerts_http_timeout_seconds) as http_client:
            while True:
                try:
                    active, instant_events = await _collect_alerts(
                        settings=settings,
                        state=state,
                        k8s_ctx=k8s_ctx,
                        http_client=http_client,
                    )
                    _OPS_CHECKS_TOTAL.labels("all", "ok").inc()
                    await _process_alerts(
                        settings=settings,
                        state=state,
                        active_alerts=active,
                        instant_events=instant_events,
                        http_client=http_client,
                    )
                except Exception:  # noqa: BLE001
                    _OPS_CHECKS_TOTAL.labels("all", "error").inc()
                    logger.exception("ops_alerts_tick_failed")
                await asyncio.sleep(max(15, int(settings.dispatcher_ops_alerts_poll_seconds)))
    finally:
        if k8s_ctx is not None:
            await k8s_ctx.client.aclose()


async def _build_k8s_context(settings: Settings, *, namespace: str) -> _K8sContext | None:
    if not any(
        [
            settings.dispatcher_ops_alerts_gateway_restarts_enabled,
            settings.dispatcher_ops_alerts_metrics_server_enabled,
            settings.dispatcher_ops_alerts_node_down_enabled,
            settings.dispatcher_ops_alerts_component_health_enabled,
        ]
    ):
        return None

    token = _bool_env_file(_K8S_TOKEN_FILE)
    if not token:
        logger.warning("ops_alerts_k8s_disabled reason=missing_serviceaccount_token")
        return None

    verify: str | bool = True
    if _K8S_CA_FILE.exists():
        verify = str(_K8S_CA_FILE)

    client = httpx.AsyncClient(
        base_url=_k8s_api_base_url(),
        headers={"Authorization": f"Bearer {token}"},
        verify=verify,
        timeout=max(2, int(settings.dispatcher_ops_alerts_http_timeout_seconds)),
    )
    return _K8sContext(namespace=namespace, client=client)


async def _collect_alerts(
    *,
    settings: Settings,
    state: _OpsState,
    k8s_ctx: _K8sContext | None,
    http_client: httpx.AsyncClient,
) -> tuple[dict[str, str], list[str]]:
    active: dict[str, str] = {}
    instant_events: list[str] = []

    if settings.dispatcher_ops_alerts_outbox_dead_enabled:
        try:
            delivery_counts, pending_old = await _outbox_delivery_health_snapshot()
            _update_outbox_delivery_gauges(delivery_counts, pending_old)
            dead_count = int(delivery_counts.get("DEAD", 0))
            _OPS_CHECKS_TOTAL.labels("outbox_dead", "ok").inc()
            if dead_count > max(0, int(settings.dispatcher_ops_alerts_outbox_dead_threshold)):
                active["outbox_dead"] = (
                    f"Outbox DEAD deliveries > threshold: {dead_count} "
                    f"(threshold={int(settings.dispatcher_ops_alerts_outbox_dead_threshold)})"
                )
        except Exception:  # noqa: BLE001
            _OPS_CHECKS_TOTAL.labels("outbox_dead", "error").inc()
            logger.exception("ops_check_outbox_dead_failed")

    if k8s_ctx is not None:
        k8s_active, k8s_events = await _collect_k8s_alerts(settings=settings, state=state, ctx=k8s_ctx)
        active.update(k8s_active)
        instant_events.extend(k8s_events)

    if settings.dispatcher_ops_alerts_disk_enabled:
        disk_active = await _collect_disk_alerts(settings=settings, state=state, http_client=http_client)
        active.update(disk_active)

    return active, instant_events


async def _outbox_delivery_health_snapshot() -> tuple[dict[str, int], int]:
    now = _utcnow()
    cutoff = now - timedelta(minutes=5)
    async with get_sessionmaker()() as session:
        rows = (
            await session.execute(
                select(OutboxDelivery.status, func.count())
                .group_by(OutboxDelivery.status)
            )
        ).all()
        pending_old = int(
            (
                await session.execute(
                    select(func.count(OutboxDelivery.id)).where(
                        OutboxDelivery.status.in_([DeliveryStatus.PENDING, DeliveryStatus.FAILED]),
                        OutboxDelivery.created_at < cutoff,
                    )
                )
            ).scalar_one()
            or 0
        )
    counts = {str(status.name if hasattr(status, "name") else status): int(count) for (status, count) in rows}
    return counts, pending_old


def _update_outbox_delivery_gauges(counts: dict[str, int], pending_old: int) -> None:
    for status_name in ["PENDING", "SENT", "FAILED", "DEAD"]:
        _OPS_OUTBOX_DELIVERIES.labels(status_name).set(float(int(counts.get(status_name, 0))))
    _OPS_OUTBOX_PENDING_OLDER_THAN_5M.set(float(max(0, int(pending_old))))


async def _collect_k8s_alerts(
    *,
    settings: Settings,
    state: _OpsState,
    ctx: _K8sContext,
) -> tuple[dict[str, str], list[str]]:
    active: dict[str, str] = {}
    instant_events: list[str] = []

    pods_payload: dict[str, Any] | None = None
    nodes_payload: dict[str, Any] | None = None

    need_pods = settings.dispatcher_ops_alerts_gateway_restarts_enabled or settings.dispatcher_ops_alerts_component_health_enabled
    need_nodes = settings.dispatcher_ops_alerts_node_down_enabled or settings.dispatcher_ops_alerts_metrics_server_enabled

    if need_pods:
        try:
            pods_payload = await _k8s_get_json(
                ctx.client,
                f"/api/v1/namespaces/{ctx.namespace}/pods",
                params={"limit": "500"},
            )
            _OPS_CHECKS_TOTAL.labels("k8s_pods", "ok").inc()
        except Exception:  # noqa: BLE001
            _OPS_CHECKS_TOTAL.labels("k8s_pods", "error").inc()
            logger.exception("ops_check_k8s_pods_failed")
            active["k8s_pods_api"] = "Kubernetes API pods list check failed"

    if need_nodes:
        try:
            nodes_payload = await _k8s_get_json(ctx.client, "/api/v1/nodes", params={"limit": "200"})
            _OPS_CHECKS_TOTAL.labels("k8s_nodes", "ok").inc()
        except Exception:  # noqa: BLE001
            _OPS_CHECKS_TOTAL.labels("k8s_nodes", "error").inc()
            logger.exception("ops_check_k8s_nodes_failed")
            active["k8s_nodes_api"] = "Kubernetes API nodes list check failed"

    if pods_payload is not None:
        _update_component_image_info(state=state, pods_payload=pods_payload)
        _collect_gateway_restart_alerts(
            settings=settings,
            state=state,
            pods_payload=pods_payload,
            instant_events=instant_events,
        )
        if settings.dispatcher_ops_alerts_component_health_enabled:
            active.update(_collect_component_health_alerts(state=state, pods_payload=pods_payload))

    node_names: set[str] = set()
    if nodes_payload is not None:
        node_names = _collect_node_down_alerts(settings=settings, state=state, nodes_payload=nodes_payload, active=active)

    if settings.dispatcher_ops_alerts_metrics_server_enabled:
        metrics_alerts = await _collect_metrics_server_alerts(settings=settings, state=state, ctx=ctx, node_names=node_names)
        active.update(metrics_alerts)

    return active, instant_events


async def _k8s_get_json(client: httpx.AsyncClient, path: str, *, params: dict[str, str] | None = None) -> dict[str, Any]:
    response = await client.get(path, params=params)
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError(f"unexpected k8s payload type: {type(payload).__name__}")
    return payload


def _collect_gateway_restart_alerts(
    *,
    settings: Settings,
    state: _OpsState,
    pods_payload: dict[str, Any],
    instant_events: list[str],
) -> None:
    if not settings.dispatcher_ops_alerts_gateway_restarts_enabled:
        return

    seen_keys: set[tuple[str, str]] = set()
    current_restart_counts: dict[tuple[str, str], int] = {}
    for item in pods_payload.get("items", []):
        if not isinstance(item, dict):
            continue
        metadata = item.get("metadata") or {}
        labels = metadata.get("labels") or {}
        component = str(labels.get("app.kubernetes.io/component") or "")
        if component not in {"gateway-vps-t", "gateway-vps-e"}:
            continue
        pod_name = str(metadata.get("name") or "")
        if not pod_name:
            continue
        status = item.get("status") or {}
        for cstat in status.get("containerStatuses") or []:
            if not isinstance(cstat, dict):
                continue
            container_name = str(cstat.get("name") or "")
            restart_count = int(cstat.get("restartCount") or 0)
            key = (pod_name, container_name)
            seen_keys.add(key)
            prev = state.restart_counts.get(key)
            state.restart_counts[key] = restart_count
            current_restart_counts[(component, container_name)] = restart_count
            if prev is None or restart_count <= prev:
                continue
            delta = restart_count - prev
            instant_events.append(
                "Gateway container restart detected: "
                f"{component}/{pod_name} container={container_name} +{delta} (total={restart_count})"
            )

    stale = [key for key in state.restart_counts if key not in seen_keys]
    for key in stale:
        state.restart_counts.pop(key, None)
    for component in ("gateway-vps-t", "gateway-vps-e"):
        for container_name in ("entry-mux", "xray", "hysteria", "wireguard", "agent"):
            restart_count = int(current_restart_counts.get((component, container_name), 0))
            _OPS_GATEWAY_CONTAINER_RESTARTS.labels(component, container_name).set(float(restart_count))


def _update_component_image_info(*, state: _OpsState, pods_payload: dict[str, Any]) -> None:
    image_keys: set[tuple[str, str]] = set()
    target_names = {
        "api": {"api"},
        "bot": {"bot"},
        "dispatcher": {"dispatcher"},
        "gateway-vps-t": {"agent"},
        "gateway-vps-e": {"agent"},
    }

    for item in pods_payload.get("items", []):
        if not isinstance(item, dict):
            continue
        labels = ((item.get("metadata") or {}).get("labels") or {})
        component = str(labels.get("app.kubernetes.io/component") or "")
        if component not in target_names:
            continue
        spec = item.get("spec") or {}
        for container in spec.get("containers") or []:
            if not isinstance(container, dict):
                continue
            cname = str(container.get("name") or "")
            if cname not in target_names[component]:
                continue
            image = str(container.get("image") or "").strip()
            if not image:
                continue
            image_keys.add((component, image))

    for component, image in image_keys:
        _OPS_COMPONENT_IMAGE_INFO.labels(component, image).set(1.0)
    stale = set(state.component_image_keys) - image_keys
    for component, image in stale:
        _OPS_COMPONENT_IMAGE_INFO.remove(component, image)
    state.component_image_keys = image_keys


def _collect_component_health_alerts(*, state: _OpsState, pods_payload: dict[str, Any]) -> dict[str, str]:
    focus = {"api", "dispatcher", "bot", "postgres", "gateway-vps-t", "gateway-vps-e"}
    ready_counts: dict[str, int] = defaultdict(int)
    pod_counts: dict[str, int] = defaultdict(int)
    seen_now: set[str] = set()

    for item in pods_payload.get("items", []):
        if not isinstance(item, dict):
            continue
        metadata = item.get("metadata") or {}
        labels = metadata.get("labels") or {}
        component = str(labels.get("app.kubernetes.io/component") or "")
        if component not in focus:
            continue
        seen_now.add(component)
        status = item.get("status") or {}
        phase = str(status.get("phase") or "")
        if phase in {"Succeeded", "Failed"}:
            continue
        pod_counts[component] += 1
        if _pod_ready(item):
            ready_counts[component] += 1

    if not state.expected_components and seen_now:
        state.expected_components = set(seen_now)
    else:
        state.expected_components.update(seen_now)

    active: dict[str, str] = {}
    for component in sorted(state.expected_components):
        total = int(pod_counts.get(component, 0))
        ready = int(ready_counts.get(component, 0))
        _OPS_COMPONENT_PODS.labels(component, "observed").set(float(total))
        _OPS_COMPONENT_PODS.labels(component, "ready").set(float(ready))
        if total <= 0 or ready <= 0:
            active[f"component_unready:{component}"] = (
                f"Component unhealthy: {component} (ready_pods={ready}, observed_pods={total})"
            )
    return active


def _pod_ready(pod_item: dict[str, Any]) -> bool:
    status = pod_item.get("status") or {}
    conditions = status.get("conditions") or []
    for cond in conditions:
        if not isinstance(cond, dict):
            continue
        if str(cond.get("type")) == "Ready":
            return str(cond.get("status")) == "True"
    return False


def _collect_node_down_alerts(
    *,
    settings: Settings,
    state: _OpsState,
    nodes_payload: dict[str, Any],
    active: dict[str, str],
) -> set[str]:
    node_names: set[str] = set()

    for item in nodes_payload.get("items", []):
        if not isinstance(item, dict):
            continue
        metadata = item.get("metadata") or {}
        node_name = str(metadata.get("name") or "")
        if not node_name:
            continue
        node_names.add(node_name)
        conditions = (item.get("status") or {}).get("conditions") or []
        ready_status = None
        ready_message = ""
        for cond in conditions:
            if not isinstance(cond, dict):
                continue
            if str(cond.get("type")) != "Ready":
                continue
            ready_status = str(cond.get("status") or "")
            msg = str(cond.get("message") or "").strip()
            reason = str(cond.get("reason") or "").strip()
            parts = [part for part in [reason, msg] if part]
            ready_message = " - ".join(parts)
            break

        _OPS_NODE_READY.labels(node_name).set(1.0 if ready_status == "True" else 0.0)
        if settings.dispatcher_ops_alerts_node_down_enabled and ready_status != "True":
            suffix = f" ({ready_message})" if ready_message else ""
            active[f"node_not_ready:{node_name}"] = f"Node not Ready: {node_name}{suffix}"

    stale_nodes = set(state.node_ready_keys) - node_names
    for node in stale_nodes:
        _OPS_NODE_READY.remove(node)
    state.node_ready_keys = set(node_names)
    return node_names


async def _collect_metrics_server_alerts(
    *,
    settings: Settings,
    state: _OpsState,
    ctx: _K8sContext,
    node_names: set[str],
) -> dict[str, str]:
    if not settings.dispatcher_ops_alerts_metrics_server_enabled:
        return {}

    try:
        payload = await _k8s_get_json(ctx.client, "/apis/metrics.k8s.io/v1beta1/nodes")
        _OPS_CHECKS_TOTAL.labels("metrics_server", "ok").inc()
    except Exception:  # noqa: BLE001
        _OPS_CHECKS_TOTAL.labels("metrics_server", "error").inc()
        logger.exception("ops_check_metrics_server_failed")
        return {"metrics_server_api": "metrics-server API scrape failed (nodes metrics unavailable)"}

    active: dict[str, str] = {}
    items = payload.get("items") or []
    seen_metrics_nodes: set[str] = set()
    max_age = max(30, int(settings.dispatcher_ops_alerts_metrics_server_max_age_seconds))
    now = _utcnow()
    stale_nodes: list[str] = []

    for item in items:
        if not isinstance(item, dict):
            continue
        name = str((item.get("metadata") or {}).get("name") or "")
        if not name:
            continue
        seen_metrics_nodes.add(name)
        ts = _parse_rfc3339(item.get("timestamp"))
        if ts is None:
            stale_nodes.append(f"{name}(no-timestamp)")
            _OPS_METRICS_SERVER_NODE_AGE_SECONDS.labels(name).set(float(max_age + 1))
            continue
        age = (now - ts).total_seconds()
        _OPS_METRICS_SERVER_NODE_AGE_SECONDS.labels(name).set(float(max(0.0, age)))
        if age > max_age:
            stale_nodes.append(f"{name}({int(age)}s)")
    stale_age_nodes = set(state.metrics_age_node_keys) - seen_metrics_nodes
    for node in stale_age_nodes:
        _OPS_METRICS_SERVER_NODE_AGE_SECONDS.remove(node)
    state.metrics_age_node_keys = set(seen_metrics_nodes)

    if node_names:
        missing = sorted(node_names - seen_metrics_nodes)
        if missing:
            active["metrics_server_missing_nodes"] = (
                "metrics-server scrape gap: missing node metrics for " + ", ".join(missing)
            )
    if stale_nodes:
        active["metrics_server_stale"] = "metrics-server scrape gap: stale node metrics " + ", ".join(sorted(stale_nodes))
    return active


async def _collect_disk_alerts(*, settings: Settings, state: _OpsState, http_client: httpx.AsyncClient) -> dict[str, str]:
    threshold = float(settings.dispatcher_ops_alerts_disk_threshold_percent)
    prom_url = str(settings.dispatcher_ops_alerts_prometheus_url or "").strip()
    if not prom_url:
        return {"disk_alerts_config": "Disk alert check is enabled but PROMETHEUS URL is empty"}

    query = (
        '100 * (1 - (max by (instance) (node_filesystem_avail_bytes{job="tracegate-node-exporter",mountpoint="/",'
        'fstype!~"tmpfs|overlay|squashfs"}) / max by (instance) (node_filesystem_size_bytes'
        '{job="tracegate-node-exporter",mountpoint="/",fstype!~"tmpfs|overlay|squashfs"})))'
    )
    endpoint = prom_url.rstrip("/") + "/api/v1/query"
    try:
        response = await http_client.get(endpoint, params={"query": query}, timeout=settings.dispatcher_ops_alerts_http_timeout_seconds)
        response.raise_for_status()
        payload = response.json()
        _OPS_CHECKS_TOTAL.labels("disk_prometheus", "ok").inc()
    except Exception:  # noqa: BLE001
        _OPS_CHECKS_TOTAL.labels("disk_prometheus", "error").inc()
        logger.exception("ops_check_disk_prometheus_failed")
        return {"disk_check_prometheus_api": "Prometheus disk query failed"}

    data = payload.get("data") or {}
    if payload.get("status") != "success" or data.get("resultType") != "vector":
        return {"disk_check_prometheus_payload": "Prometheus disk query returned unexpected payload"}

    active: dict[str, str] = {}
    seen_instances: set[str] = set()
    for row in data.get("result") or []:
        if not isinstance(row, dict):
            continue
        metric = row.get("metric") or {}
        instance = str(metric.get("instance") or "unknown")
        seen_instances.add(instance)
        value = row.get("value") or []
        if len(value) < 2:
            continue
        try:
            pct = float(value[1])
        except (TypeError, ValueError):
            continue
        _OPS_DISK_USED_PERCENT.labels(instance).set(float(pct))
        if pct >= threshold:
            active[f"disk_high:{instance}"] = (
                f"Disk usage high on {instance}: {_safe_pct(pct)} (threshold={_safe_pct(threshold)})"
            )
    stale_instances = set(state.disk_instance_keys) - seen_instances
    for instance in stale_instances:
        _OPS_DISK_USED_PERCENT.remove(instance)
    state.disk_instance_keys = set(seen_instances)
    return active


async def _process_alerts(
    *,
    settings: Settings,
    state: _OpsState,
    active_alerts: dict[str, str],
    instant_events: list[str],
    http_client: httpx.AsyncClient,
) -> None:
    now = _utcnow()
    messages: list[tuple[str, str, list[str]]] = []  # (kind, text, active_keys_to_touch)

    for text in instant_events:
        messages.append(("alert", _ops_alert_text("alert", text), []))

    if not state.initialized and settings.dispatcher_ops_alerts_suppress_initial:
        state.active_alerts = {k: _ActiveAlert(text=v, since=now) for (k, v) in active_alerts.items()}
        state.initialized = True
        _OPS_ACTIVE_ALERTS.set(len(state.active_alerts))
        if state.active_alerts:
            logger.info("ops_alerts_baseline_suppressed count=%s", len(state.active_alerts))
        return

    for key, text in sorted(active_alerts.items()):
        existing = state.active_alerts.get(key)
        if existing is None:
            state.active_alerts[key] = _ActiveAlert(text=text, since=now)
            messages.append(("alert", _ops_alert_text("alert", text), [key]))
            continue

        existing.text = text
        repeat_seconds = max(0, int(settings.dispatcher_ops_alerts_repeat_seconds))
        if repeat_seconds <= 0:
            continue
        if existing.last_sent_at is None:
            continue
        if (now - existing.last_sent_at).total_seconds() >= repeat_seconds:
            messages.append(("repeat", _ops_alert_text("repeat", text), [key]))

    resolved_keys = sorted(set(state.active_alerts) - set(active_alerts))
    for key in resolved_keys:
        prev = state.active_alerts.pop(key, None)
        if prev is None:
            continue
        if settings.dispatcher_ops_alerts_send_resolved:
            duration = int(max(0.0, (now - prev.since).total_seconds()))
            messages.append(("resolved", _ops_alert_text("resolved", f"{prev.text} (for {duration}s)"), []))

    state.initialized = True
    _OPS_ACTIVE_ALERTS.set(len(state.active_alerts))

    if not messages:
        return
    if not settings.bot_token:
        logger.warning("ops_alerts_messages_dropped reason=missing_bot_token count=%s", len(messages))
        return

    recipients = await _load_admin_chat_ids(settings)
    if not recipients:
        logger.warning("ops_alerts_messages_dropped reason=no_admin_recipients count=%s", len(messages))
        return

    for kind, text, touched_keys in messages:
        sent = await _send_to_recipients(
            http_client=http_client,
            bot_token=settings.bot_token,
            recipients=recipients,
            text=text,
        )
        if sent:
            for key in touched_keys:
                if key in state.active_alerts:
                    state.active_alerts[key].last_sent_at = now
        _OPS_ALERT_MESSAGES_TOTAL.labels(kind, "ok" if sent else "error").inc()
        if sent:
            logger.info("ops_alert_sent kind=%s recipients=%s text=%s", kind, len(recipients), text)
        else:
            logger.warning("ops_alert_send_failed kind=%s recipients=%s text=%s", kind, len(recipients), text)


async def _load_admin_chat_ids(settings: Settings) -> list[int]:
    role_values = [UserRole.ADMIN, UserRole.SUPERADMIN]
    ids: set[int] = set(int(x) for x in (settings.superadmin_telegram_ids or []) if int(x) > 0)
    async with get_sessionmaker()() as session:
        rows = (
            await session.execute(select(User.telegram_id).where(User.role.in_(role_values)).order_by(User.telegram_id.asc()))
        ).scalars().all()
        ids.update(int(row) for row in rows if int(row) > 0)
    return sorted(ids)


async def _send_to_recipients(
    *,
    http_client: httpx.AsyncClient,
    bot_token: str,
    recipients: list[int],
    text: str,
) -> bool:
    ok_all = True
    for chat_id in recipients:
        ok = await _send_telegram_message(http_client=http_client, bot_token=bot_token, chat_id=chat_id, text=text)
        ok_all = ok_all and ok
    return ok_all


async def _send_telegram_message(
    *,
    http_client: httpx.AsyncClient,
    bot_token: str,
    chat_id: int,
    text: str,
) -> bool:
    payload = {
        "chat_id": int(chat_id),
        "text": (text or "").strip()[:4000],
        "disable_web_page_preview": True,
    }
    url = f"{_TELEGRAM_API_BASE}/bot{bot_token}/sendMessage"

    for attempt in range(2):
        try:
            response = await http_client.post(url, json=payload)
            if response.status_code == 429 and attempt == 0:
                retry_after = 1
                try:
                    retry_after = int((response.json().get("parameters") or {}).get("retry_after") or 1)
                except Exception:  # noqa: BLE001
                    retry_after = 1
                await asyncio.sleep(max(1, min(5, retry_after)))
                continue
            response.raise_for_status()
            body = response.json()
            return bool(body.get("ok"))
        except Exception:  # noqa: BLE001
            logger.exception("telegram_send_failed chat_id=%s", chat_id)
            return False
    return False
