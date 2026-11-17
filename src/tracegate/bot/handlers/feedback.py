"""User feedback to admins."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from aiogram import Bot, F, Router
from aiogram.exceptions import TelegramRetryAfter
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from tracegate.bot import callbacks as cb
from tracegate.bot import context as ctx
from tracegate.bot import keyboards, nav, texts
from tracegate.bot.admin_tools import build_feedback_admin_text
from tracegate.bot.handlers.start import current_user, show_menu
from tracegate.bot.states import FeedbackFlow

router = Router(name="feedback")


async def load_admin_chat_ids() -> list[int]:
    ids: set[int] = {int(value) for value in (ctx.settings.superadmin_telegram_ids or []) if int(value) > 0}
    for role in ("admin", "superadmin"):
        rows = await ctx.api.list_users(role=role, limit=500, include_empty=True, prune_empty=False)
        for row in rows:
            telegram_id = int(row.get("telegram_id") or 0)
            if telegram_id > 0:
                ids.add(telegram_id)
    return sorted(ids)


async def send_with_retry(bot: Bot, chat_id: int, text: str, **kwargs) -> bool:  # noqa: ANN003
    """Send one message, retrying once on flood control. Returns delivery success."""

    for attempt in range(2):
        try:
            await bot.send_message(chat_id=chat_id, text=text, **kwargs)
            return True
        except TelegramRetryAfter as exc:
            if attempt:
                return False
            await asyncio.sleep(float(exc.retry_after))
        except Exception as exc:  # noqa: BLE001 - blocked bot, deleted chat, etc.
            nav.logger.info("bot_send_failed chat=%s error=%s", chat_id, type(exc).__name__)
            return False
    return False


@router.callback_query(F.data == cb.FEEDBACK)
async def feedback_start(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await state.set_state(FeedbackFlow.waiting_for_message)
    await nav.show(callback, texts.FEEDBACK_PROMPT, keyboards.feedback_keyboard())


@router.message(FeedbackFlow.waiting_for_message)
async def feedback_message(message: Message, state: FSMContext, tracegate_user: dict | None = None) -> None:
    text = (message.text or message.caption or "").strip()
    if not text:
        await nav.send(message, texts.FEEDBACK_NOT_TEXT, keyboards.feedback_keyboard())
        return
    await state.clear()
    try:
        author = await current_user(message.from_user.id, tracegate_user)
        admin_chat_ids = await load_admin_chat_ids()
    except Exception as exc:  # noqa: BLE001
        nav.log_error("feedback_load", exc)
        await nav.send(message, texts.ERR_FEEDBACK, keyboards.home_keyboard())
        return

    admin_text = build_feedback_admin_text(author=author, feedback_text=text, sent_at=datetime.now(timezone.utc))
    keyboard = keyboards.feedback_admin_keyboard(telegram_id=int(author["telegram_id"]))
    sent = 0
    for chat_id in admin_chat_ids:
        if await send_with_retry(message.bot, chat_id, admin_text, reply_markup=keyboard):
            sent += 1
        await asyncio.sleep(0.04)
    if sent == 0:
        nav.logger.error("bot_feedback_undelivered admins=%s", len(admin_chat_ids))
        await nav.send(message, texts.ERR_FEEDBACK, keyboards.home_keyboard())
        return
    await show_menu(message, author, status=texts.FEEDBACK_SENT)
