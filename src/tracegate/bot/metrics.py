from __future__ import annotations

import logging
import time
from typing import Any

from aiogram import BaseMiddleware
from aiogram.types import CallbackQuery, Message
from prometheus_client import Counter, Gauge, Histogram, start_http_server

logger = logging.getLogger("tracegate.bot.metrics")

_BOT_UPDATES_TOTAL = Counter(
    "tracegate_bot_updates_total",
    "Telegram updates processed by bot middlewares",
    labelnames=["update_type", "result"],
)
_BOT_UPDATE_DURATION_SECONDS = Histogram(
    "tracegate_bot_update_duration_seconds",
    "Telegram update handler execution time in seconds",
    labelnames=["update_type", "result"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20),
)
_BOT_UPDATE_INFLIGHT = Gauge(
    "tracegate_bot_update_inflight",
    "Telegram updates currently processed by the bot",
    labelnames=["update_type"],
)
_BOT_LAST_UPDATE_UNIX_SECONDS = Gauge(
    "tracegate_bot_last_update_unix_seconds",
    "Unix timestamp of the most recent Telegram update processed by the bot",
)


def _update_type(event: Any) -> str:
    if isinstance(event, Message):
        return "message"
    if isinstance(event, CallbackQuery):
        return "callback_query"
    name = type(event).__name__.strip().lower()
    return name or "unknown"


class BotMetricsMiddleware(BaseMiddleware):
    async def __call__(self, handler, event, data):  # noqa: ANN001, ANN204
        update_type = _update_type(event)
        started = time.perf_counter()
        _BOT_UPDATE_INFLIGHT.labels(update_type).inc()
        try:
            result = await handler(event, data)
        except Exception:  # noqa: BLE001
            elapsed = max(0.0, time.perf_counter() - started)
            _BOT_UPDATES_TOTAL.labels(update_type, "error").inc()
            _BOT_UPDATE_DURATION_SECONDS.labels(update_type, "error").observe(elapsed)
            _BOT_LAST_UPDATE_UNIX_SECONDS.set(time.time())
            raise
        finally:
            _BOT_UPDATE_INFLIGHT.labels(update_type).dec()

        elapsed = max(0.0, time.perf_counter() - started)
        _BOT_UPDATES_TOTAL.labels(update_type, "ok").inc()
        _BOT_UPDATE_DURATION_SECONDS.labels(update_type, "ok").observe(elapsed)
        _BOT_LAST_UPDATE_UNIX_SECONDS.set(time.time())
        return result


def maybe_start_bot_metrics_server(*, enabled: bool, host: str, port: int) -> None:
    if not enabled:
        return
    start_http_server(int(port), addr=str(host))
    logger.info("bot_metrics_enabled host=%s port=%s", host, port)
