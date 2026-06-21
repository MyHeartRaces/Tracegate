from __future__ import annotations

import asyncio
import logging

from aiogram import Bot
from aiogram.exceptions import TelegramNetworkError, TelegramRetryAfter

logger = logging.getLogger(__name__)


async def delete_webhook_with_retry(
    bot: Bot,
    *,
    drop_pending_updates: bool,
    attempts: int = 5,
    base_delay_seconds: float = 1.0,
) -> None:
    delay = max(0.1, float(base_delay_seconds))
    last_error: Exception | None = None
    for attempt in range(1, max(1, attempts) + 1):
        try:
            await bot.delete_webhook(drop_pending_updates=drop_pending_updates)
            return
        except TelegramRetryAfter as exc:
            last_error = exc
            wait_s = max(float(exc.retry_after), delay)
            logger.warning(
                "bot_delete_webhook_retry_after attempt=%s/%s wait_s=%.2f",
                attempt,
                attempts,
                wait_s,
            )
        except TelegramNetworkError as exc:
            last_error = exc
            wait_s = delay
            logger.warning(
                "bot_delete_webhook_network_retry attempt=%s/%s wait_s=%.2f error=%s",
                attempt,
                attempts,
                wait_s,
                exc,
            )
        if attempt >= attempts:
            break
        await asyncio.sleep(wait_s)
        delay = min(delay * 2, 30.0)

    if last_error is not None:
        raise last_error
