"""Welcome, main menu, /start /menu /cancel /clear /welcome and Grafana."""

from __future__ import annotations

import asyncio

from aiogram import Bot, F, Router
from aiogram.exceptions import TelegramBadRequest, TelegramForbiddenError, TelegramRetryAfter
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, InlineKeyboardMarkup, Message

from tracegate.bot import callbacks as cb
from tracegate.bot import context as ctx
from tracegate.bot import keyboards, nav, texts
from tracegate.bot.access import is_admin
from tracegate.bot.client import ApiClientError
from tracegate.bot.welcome import (
    edit_welcome_step,
    send_welcome_step,
    welcome_accepted,
    welcome_text,
    welcome_version,
)

router = Router(name="start")

Screen = tuple[str, InlineKeyboardMarkup]


async def current_user(telegram_id: int, tracegate_user: dict | None = None) -> dict:
    return tracegate_user or await ctx.ensure_user(telegram_id)


def menu_screen(user: dict | None, *, status: str | None = None) -> Screen:
    keyboard = keyboards.main_menu_keyboard(
        is_admin=nav.is_admin_user(user),
        grafana_enabled=bool(ctx.settings.grafana_enabled),
    )
    return texts.with_status(status, texts.MAIN_MENU), keyboard


async def show_menu(target: CallbackQuery | Message, user: dict | None, *, status: str | None = None) -> None:
    text, keyboard = menu_screen(user, status=status)
    await nav.show(target, text, keyboard)


async def show_outdated(target: CallbackQuery | Message, user: dict | None = None) -> None:
    """Stale or malformed buttons land here: short notice plus the main menu."""

    await show_menu(target, user, status=texts.MENU_OUTDATED)


async def show_error(
    target: CallbackQuery | Message,
    exc: BaseException,
    *,
    where: str,
    fallback: str,
    user: dict | None,
    back_callback: str = cb.MENU,
) -> None:
    nav.log_error(where, exc)
    text = nav.user_error_text(exc, fallback=fallback, admin=nav.is_admin_user(user))
    await nav.show(target, text, keyboards.back_home_keyboard(back_callback))


# ------------------------------------------------------------------ start ---


@router.message(CommandStart())
async def start(message: Message, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    user = await current_user(message.from_user.id, tracegate_user)
    if not welcome_accepted(user):
        await send_welcome_step(message, step=1)
        return
    await show_menu(message, user)


@router.message(Command("menu"))
async def menu_command(message: Message, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    await show_menu(message, await current_user(message.from_user.id, tracegate_user))


@router.callback_query(F.data == cb.WELCOME_1)
async def welcome_continue_1(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    user = await current_user(callback.from_user.id, tracegate_user)
    if welcome_accepted(user):
        await show_menu(callback, user)
        return
    await edit_welcome_step(callback, step=2)


@router.callback_query(F.data == cb.WELCOME_2)
async def welcome_continue_2(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    user = await current_user(callback.from_user.id, tracegate_user)
    if not welcome_accepted(user):
        try:
            user = await ctx.api.accept_bot_welcome(int(user["telegram_id"]), version=welcome_version())
        except Exception as exc:  # noqa: BLE001
            await show_error(callback, exc, where="welcome_accept", fallback=texts.ERR_GENERIC, user=user)
            return
    await show_menu(callback, user)


@router.callback_query(F.data == cb.MENU)
async def menu(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    await show_menu(callback, await current_user(callback.from_user.id, tracegate_user))


@router.message(Command("welcome"))
async def welcome(message: Message, state: FSMContext) -> None:
    await state.clear()
    await nav.send(message, welcome_text(), keyboards.home_keyboard())


@router.message(Command("cancel"))
async def cancel(message: Message, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    if message.chat.type != "private":
        await message.answer(texts.PRIVATE_CHAT_ONLY)
        return
    await show_menu(message, await current_user(message.from_user.id, tracegate_user), status=texts.CANCELLED)


async def cleanup_chat_history(bot: Bot, chat_id: int, from_message_id: int, *, limit: int) -> None:
    # Telegram has no "clear chat" API; delete recent messages one by one (best-effort).
    lower = max(1, int(from_message_id) - int(limit) + 1)
    for message_id in range(int(from_message_id), lower - 1, -1):
        try:
            await bot.delete_message(chat_id=chat_id, message_id=message_id)
        except TelegramRetryAfter as exc:
            await asyncio.sleep(float(exc.retry_after))
        except (TelegramBadRequest, TelegramForbiddenError):
            continue
        except Exception:  # noqa: BLE001
            continue
        await asyncio.sleep(0.02)


@router.message(Command("clear"))
async def clear(message: Message, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    if message.chat.type != "private":
        await message.answer(texts.PRIVATE_CHAT_ONLY)
        return
    asyncio.create_task(
        cleanup_chat_history(
            message.bot,
            int(message.chat.id),
            int(message.message_id),
            limit=int(ctx.settings.bot_clean_max_messages),
        )
    )
    await show_menu(message, await current_user(message.from_user.id, tracegate_user))


# ---------------------------------------------------------------- grafana ---


def _is_grafana_disabled_error(error: BaseException) -> bool:
    if not isinstance(error, ApiClientError) or int(error.status_code) != 404:
        return False
    return "grafana is disabled" in str(error.detail or "").strip().lower()


@router.callback_query(F.data == cb.GRAFANA)
async def grafana(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    if not ctx.settings.grafana_enabled:
        await nav.show(callback, texts.GRAFANA_DISABLED, keyboards.home_keyboard())
        return
    user = await current_user(callback.from_user.id, tracegate_user)
    scope = "admin" if is_admin(user) else "user"
    try:
        otp = await ctx.api.create_grafana_otp(int(user["telegram_id"]), scope=scope)
    except Exception as exc:  # noqa: BLE001
        if _is_grafana_disabled_error(exc):
            await nav.show(callback, texts.GRAFANA_DISABLED, keyboards.home_keyboard())
            return
        await show_error(callback, exc, where="grafana_otp", fallback=texts.ERR_GRAFANA, user=user)
        return
    await nav.show(
        callback,
        texts.grafana_screen(scope=scope, expires_at=otp.get("expires_at")),
        keyboards.grafana_keyboard(otp.get("login_url")),
    )
