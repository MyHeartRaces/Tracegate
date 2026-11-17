"""Access gate: blocked users and the two-step welcome."""

from __future__ import annotations

from aiogram import BaseMiddleware
from aiogram.types import CallbackQuery, Message

from tracegate.bot import callbacks as cb
from tracegate.bot import context as ctx
from tracegate.bot import nav, texts
from tracegate.bot.access import blocked_message, is_bot_blocked
from tracegate.bot.client import ApiClientError
from tracegate.bot.welcome import send_welcome_step, welcome_accepted


class BotAccessMiddleware(BaseMiddleware):
    async def __call__(self, handler, event, data):  # noqa: ANN001, ANN204
        from_user = data.get("event_from_user")
        if from_user is None:
            return await handler(event, data)

        try:
            user = await ctx.api.get_or_create_user(
                from_user.id,
                telegram_username=getattr(from_user, "username", None),
                telegram_first_name=getattr(from_user, "first_name", None),
                telegram_last_name=getattr(from_user, "last_name", None),
            )
        except ApiClientError as exc:
            nav.log_error("access_middleware", exc)
            return await handler(event, data)
        data["tracegate_user"] = user

        if is_bot_blocked(user):
            text = texts.warn(blocked_message(user))
            if isinstance(event, CallbackQuery):
                try:
                    await event.answer(texts.ACCESS_LIMITED_ALERT, show_alert=True)
                except Exception:  # noqa: BLE001
                    pass
                if event.message is not None:
                    await event.message.answer(text)
                return None
            if isinstance(event, Message):
                await event.answer(text)
                return None

        if ctx.settings.bot_welcome_required and not welcome_accepted(user):
            if isinstance(event, CallbackQuery):
                if str(event.data or "") in {cb.WELCOME_1, cb.WELCOME_2}:
                    return await handler(event, data)
                try:
                    await event.answer(texts.WELCOME_REQUIRED_ALERT, show_alert=True)
                except Exception:  # noqa: BLE001
                    pass
                if event.message is not None:
                    await send_welcome_step(event.message, step=1)
                return None
            if isinstance(event, Message):
                if str(event.text or "").strip().startswith("/start"):
                    return await handler(event, data)
                await send_welcome_step(event, step=1)
                return None
        return await handler(event, data)
