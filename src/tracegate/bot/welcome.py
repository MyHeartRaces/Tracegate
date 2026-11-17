"""Two-step welcome: private welcome text, then the rules to accept."""

from __future__ import annotations

from pathlib import Path

from aiogram.types import CallbackQuery, Message

from tracegate.bot import context as ctx
from tracegate.bot import keyboards, nav, texts

# Used only when BOT_WELCOME_VERSION is set to an empty value. Kept at the
# Tracegate 3 value on purpose: the 4.2.0 copy rewording does not add new
# obligations, so users who already accepted are not asked again.
DEFAULT_WELCOME_VERSION = "tracegate-3.0.0-ui-v1"


def welcome_version() -> str:
    return str(ctx.settings.bot_welcome_version or "").strip() or DEFAULT_WELCOME_VERSION


def welcome_text() -> str:
    message_file = str(ctx.settings.bot_welcome_message_file or "").strip()
    if message_file:
        try:
            text = Path(message_file).read_text(encoding="utf-8").strip()
            if text:
                return text
        except (OSError, UnicodeDecodeError):
            nav.logger.warning("bot_welcome_file_unreadable")
    return str(ctx.settings.bot_welcome_message or "").strip() or texts.WELCOME_FALLBACK


def welcome_accepted(user: dict) -> bool:
    if not ctx.settings.bot_welcome_required:
        return True
    accepted_at = str(user.get("bot_welcome_accepted_at") or "").strip()
    accepted_version = str(user.get("bot_welcome_version") or "").strip()
    return bool(accepted_at and accepted_version == welcome_version())


def welcome_step(step: int) -> tuple[str, object]:
    if step == 1:
        return welcome_text(), keyboards.welcome_keyboard(1)
    return texts.WELCOME_RULES, keyboards.welcome_keyboard(2)


async def send_welcome_step(message: Message, *, step: int) -> None:
    text, keyboard = welcome_step(step)
    await message.answer(text, disable_web_page_preview=True, reply_markup=keyboard)


async def edit_welcome_step(callback: CallbackQuery, *, step: int) -> None:
    text, keyboard = welcome_step(step)
    await nav.show(callback, text, keyboard)
