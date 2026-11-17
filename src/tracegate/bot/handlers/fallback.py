"""Stale / unknown callbacks and stray messages. Must be included last.

Buttons from earlier releases stay in users' chats. Payloads that still make
sense open the matching new screen; everything else (removed SNI catalog,
legacy create flows, old action buttons) shows "Это меню устарело" with the
main menu. Old action buttons never perform their action.
"""

from __future__ import annotations

from aiogram import F, Router
from aiogram.filters import StateFilter
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from tracegate.bot import callbacks as cb
from tracegate.bot import nav, texts
from tracegate.bot.handlers.connections import show_connection_screen
from tracegate.bot.handlers.devices import show_device, show_devices
from tracegate.bot.handlers.guide import show_guide_root
from tracegate.bot.handlers.mtproto import show_tgp
from tracegate.bot.handlers.start import show_menu, show_outdated

router = Router(name="fallback")

# Old exact payloads -> new screen.
LEGACY_EXACT: dict[str, str] = {
    "connections": "devices",
    "devices": "devices",
    "guide_open": "guide",
    "help_open": "guide",
    "mtproto_open": "tgp",
}
# Old "<prefix><uuid>" payloads -> new screen for that id.
LEGACY_PREFIX: dict[str, str] = {
    "device:": "device",
    "revs:": "connection",
}
# "menu" and "admin_menu" keep their payloads and are handled by their own routers.


def resolve_legacy(data: str | None) -> tuple[str, str | None]:
    """Map a callback payload to ("devices"|"device"|"connection"|"guide"|"tgp"|"outdated", id)."""

    raw = str(data or "")
    if raw in LEGACY_EXACT:
        return LEGACY_EXACT[raw], None
    for prefix, screen in LEGACY_PREFIX.items():
        if raw.startswith(prefix):
            object_id = cb.parse_id(raw, prefix)
            return (screen, object_id) if object_id else ("outdated", None)
    return "outdated", None


@router.callback_query()
async def stale_callback(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    screen, object_id = resolve_legacy(callback.data)
    if screen == "devices":
        await show_devices(callback, callback.from_user.id, tracegate_user)
    elif screen == "device" and object_id:
        await show_device(callback, callback.from_user.id, object_id, tracegate_user)
    elif screen == "connection" and object_id:
        await show_connection_screen(callback, object_id, tracegate_user)
    elif screen == "guide":
        await show_guide_root(callback)
    elif screen == "tgp":
        await show_tgp(callback)
    else:
        nav.logger.info("bot_stale_callback prefix=%s", str(callback.data or "").split(":", 1)[0][:32])
        await show_outdated(callback, tracegate_user)


@router.message(StateFilter(None), F.chat.type == "private")
async def stray_message(message: Message, tracegate_user: dict | None = None) -> None:
    await show_menu(message, tracegate_user, status=texts.UNKNOWN_MESSAGE)
