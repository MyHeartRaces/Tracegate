from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

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
_OPS_DISK_USED_PERCENT = Gauge(
    "tracegate_ops_disk_used_percent",
    "Disk usage percent for root filesystem (from node-exporter via Prometheus query)",
    labelnames=["instance"],
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


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


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


def _ops_alert_min_active_seconds(settings: Settings, alert_key: str) -> int:
    return 0


@dataclass(slots=True)
class _ActiveAlert:
    text: str
    since: datetime
    last_sent_at: datetime | None = None


@dataclass(slots=True)
class _OpsState:
    active_alerts: dict[str, _ActiveAlert] = field(default_factory=dict)
    disk_instance_keys: set[str] = field(default_factory=set)
    initialized: bool = False


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
    logger.info(
        "ops_alerts_enabled poll_s=%s prometheus_url=%s",
        settings.dispatcher_ops_alerts_poll_seconds,
        settings.dispatcher_ops_alerts_prometheus_url,
    )

    async with httpx.AsyncClient(timeout=settings.dispatcher_ops_alerts_http_timeout_seconds) as http_client:
        while True:
            try:
                active, instant_events = await _collect_alerts(
                    settings=settings,
                    state=state,
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


async def _collect_alerts(
    *,
    settings: Settings,
    state: _OpsState,
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
        min_active_seconds = _ops_alert_min_active_seconds(settings, key)
        if existing is None:
            state.active_alerts[key] = _ActiveAlert(text=text, since=now)
            if min_active_seconds <= 0:
                messages.append(("alert", _ops_alert_text("alert", text), [key]))
            continue

        existing.text = text
        if existing.last_sent_at is None:
            active_for = (now - existing.since).total_seconds()
            if active_for >= min_active_seconds:
                messages.append(("alert", _ops_alert_text("alert", text), [key]))
            continue

        repeat_seconds = max(0, int(settings.dispatcher_ops_alerts_repeat_seconds))
        if repeat_seconds <= 0:
            continue
        if (now - existing.last_sent_at).total_seconds() >= repeat_seconds:
            messages.append(("repeat", _ops_alert_text("repeat", text), [key]))

    resolved_keys = sorted(set(state.active_alerts) - set(active_alerts))
    for key in resolved_keys:
        prev = state.active_alerts.pop(key, None)
        if prev is None:
            continue
        if settings.dispatcher_ops_alerts_send_resolved and prev.last_sent_at is not None:
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
