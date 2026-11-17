"""Shared runtime objects for the bot: settings and the API client.

Modules access these as ``ctx.settings`` / ``ctx.api`` so tests can patch them
in one place.
"""

from __future__ import annotations

from tracegate.bot.client import TracegateApiClient
from tracegate.settings import get_settings

settings = get_settings()
api = TracegateApiClient(settings.bot_api_base_url, settings.bot_api_token)


async def ensure_user(telegram_id: int) -> dict:
    return await api.get_or_create_user(telegram_id)
