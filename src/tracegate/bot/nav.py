"""Rendering helpers: edit-in-place, chunking, HTML fallback and error mapping."""

from __future__ import annotations

import html
import logging
import re
from typing import Any

from aiogram import BaseMiddleware
from aiogram.exceptions import TelegramBadRequest
from aiogram.types import CallbackQuery, ErrorEvent, InlineKeyboardMarkup, Message

from tracegate.bot import texts
from tracegate.bot.access import is_admin
from tracegate.bot.client import ApiClientError
from tracegate.bot.profiles import ProfileDisabledError
from tracegate.services.connection_profiles import (
    RETIRED_CLIENT_PROTOCOL_MESSAGE,
    RETIRED_HYSTERIA_CHAIN_MESSAGE,
)

logger = logging.getLogger("tracegate.bot")

TELEGRAM_TEXT_CHUNK_LIMIT = 3900
HTML = "HTML"


# --------------------------------------------------------------- chunking ---


def split_text(text: str, *, limit: int = TELEGRAM_TEXT_CHUNK_LIMIT) -> tuple[str, ...]:
    """Split text into chunks of at most ``limit`` characters.

    Paragraphs stay together when they fit, then lines, then hard cuts.
    """

    normalized = str(text or "").strip()
    if len(normalized) <= limit:
        return (normalized,)

    chunks: list[str] = []
    current = ""
    for paragraph in normalized.split("\n\n"):
        candidate = f"{current}\n\n{paragraph}" if current else paragraph
        if len(candidate) <= limit:
            current = candidate
            continue
        if current:
            chunks.append(current)
            current = ""
        if len(paragraph) <= limit:
            current = paragraph
            continue
        for line in paragraph.splitlines() or [paragraph]:
            if len(line) > limit:
                if current:
                    chunks.append(current)
                    current = ""
                chunks.extend(line[index : index + limit] for index in range(0, len(line), limit))
                continue
            candidate = f"{current}\n{line}" if current else line
            if len(candidate) > limit:
                if current:
                    chunks.append(current)
                current = line
            else:
                current = candidate
    if current:
        chunks.append(current)
    return tuple(chunk for chunk in chunks if chunk) or (normalized[:limit],)


# -------------------------------------------------------------------- HTML ---

_TAG_RE = re.compile(r"<[^>]*>")


def strip_html(text: str) -> str:
    """Plain-text fallback for owner-authored HTML."""

    without_breaks = re.sub(r"<br\s*/?>", "\n", str(text or ""), flags=re.IGNORECASE)
    return html.unescape(_TAG_RE.sub("", without_breaks))


def _is_parse_error(exc: TelegramBadRequest) -> bool:
    message = str(exc).lower()
    return "parse" in message and "entit" in message


# ------------------------------------------------------------ edit / send ---


def _is_not_modified(exc: TelegramBadRequest) -> bool:
    return "message is not modified" in str(exc).lower()


def _is_gone(exc: TelegramBadRequest) -> bool:
    message = str(exc).lower()
    return (
        "message to edit not found" in message
        or "message can't be edited" in message
        or "there is no text in the message to edit" in message
    )


async def safe_edit(message_obj: Any, text: str, **kwargs: Any) -> bool:
    """Edit a message in place; send a new one when the original is gone.

    Returns False only when Telegram reports the content as unchanged.
    """

    if message_obj is None:
        return False
    try:
        await message_obj.edit_text(text, **kwargs)
        return True
    except TelegramBadRequest as exc:
        if _is_not_modified(exc):
            return False
        if _is_gone(exc):
            await message_obj.answer(text, **kwargs)
            return True
        raise


async def _deliver(
    message_obj: Any,
    text: str,
    *,
    edit: bool,
    reply_markup: InlineKeyboardMarkup | None,
    parse_mode: str | None,
) -> None:
    kwargs: dict[str, Any] = {"disable_web_page_preview": True}
    if reply_markup is not None:
        kwargs["reply_markup"] = reply_markup
    if parse_mode:
        kwargs["parse_mode"] = parse_mode
    try:
        if edit:
            await safe_edit(message_obj, text, **kwargs)
        else:
            await message_obj.answer(text, **kwargs)
    except TelegramBadRequest as exc:
        if not parse_mode or not _is_parse_error(exc):
            raise
        logger.warning("bot_html_fallback reason=%s", exc)
        kwargs.pop("parse_mode", None)
        plain = strip_html(text)
        if edit:
            await safe_edit(message_obj, plain, **kwargs)
        else:
            await message_obj.answer(plain, **kwargs)


def _is_callback(target: Any) -> bool:
    return not isinstance(target, Message) and hasattr(target, "message") and hasattr(target, "data")


def _target_message(target: CallbackQuery | Message) -> Any:
    return getattr(target, "message", None) if _is_callback(target) else target


async def show(
    target: CallbackQuery | Message,
    text: str,
    reply_markup: InlineKeyboardMarkup | None = None,
    *,
    parse_mode: str | None = None,
) -> None:
    """Render a screen: edit in place for callbacks, a new message otherwise."""

    await show_chunks(target, split_text(text), reply_markup, parse_mode=parse_mode)


async def show_chunks(
    target: CallbackQuery | Message,
    chunks: tuple[str, ...] | list[str],
    reply_markup: InlineKeyboardMarkup | None = None,
    *,
    parse_mode: str | None = None,
) -> None:
    """First chunk edits the screen (callbacks), the rest are new messages.

    The keyboard goes on the last chunk.
    """

    message_obj = _target_message(target)
    if message_obj is None:
        return
    items = [chunk for chunk in chunks if str(chunk or "").strip()] or [""]
    edit_first = _is_callback(target)
    last = len(items) - 1
    for index, chunk in enumerate(items):
        await _deliver(
            message_obj,
            chunk,
            edit=edit_first and index == 0,
            reply_markup=reply_markup if index == last else None,
            parse_mode=parse_mode,
        )


async def send(
    target: CallbackQuery | Message,
    text: str,
    reply_markup: InlineKeyboardMarkup | None = None,
) -> None:
    """Always send a new message (results of text input, notifications)."""

    message_obj = _target_message(target)
    if message_obj is None:
        return
    for chunk, is_last in _with_last(split_text(text)):
        kwargs: dict[str, Any] = {"disable_web_page_preview": True}
        if is_last and reply_markup is not None:
            kwargs["reply_markup"] = reply_markup
        await message_obj.answer(chunk, **kwargs)


def _with_last(items: tuple[str, ...]) -> list[tuple[str, bool]]:
    return [(item, index == len(items) - 1) for index, item in enumerate(items)]


# ---------------------------------------------------------- error mapping ---


def _api_detail(exc: ApiClientError) -> str:
    return str(getattr(exc, "detail", "") or "").lower()


def user_error_text(exc: BaseException, *, fallback: str = texts.ERR_GENERIC, admin: bool = False) -> str:
    """Map an exception to a short Russian message; never includes raw details."""

    text = fallback
    status_code: int | None = None
    if isinstance(exc, ProfileDisabledError):
        text = texts.ERR_PROFILE_DISABLED
    elif isinstance(exc, ValueError) and str(exc) in {
        RETIRED_CLIENT_PROTOCOL_MESSAGE,
        RETIRED_HYSTERIA_CHAIN_MESSAGE,
    }:
        text = texts.ERR_RETIRED
    elif isinstance(exc, ApiClientError):
        status_code = int(exc.status_code)
        detail = _api_detail(exc)
        if "retired in tracegate" in detail:
            text = texts.ERR_RETIRED
        elif "device limit" in detail:
            text = texts.ERR_DEVICE_LIMIT
        elif "connection limit" in detail or "connections limit" in detail:
            text = texts.ERR_CONNECTION_LIMIT
        elif status_code == 403 and ("grace" in detail or "blocked" in detail):
            text = texts.ERR_ISSUE_FORBIDDEN
    if admin:
        reference = texts.admin_error_reference(status_code, type(exc).__name__)
        text = f"{text}\n\n{reference}"
    return text


def log_error(where: str, exc: BaseException) -> None:
    logger.error("bot_handler_error where=%s error=%s", where, type(exc).__name__, exc_info=exc)


def is_admin_user(user: dict | None) -> bool:
    return bool(user) and is_admin(user or {})


# ------------------------------------------------------------- middleware ---


async def ack(callback: CallbackQuery) -> None:
    try:
        await callback.answer()
    except Exception as exc:  # noqa: BLE001 - a stale query must not break the flow
        logger.debug("bot_callback_answer_failed error=%s", type(exc).__name__)


class CallbackAnswerFirstMiddleware(BaseMiddleware):
    """Answers every callback query exactly once, before the handler runs."""

    async def __call__(self, handler, event, data):  # noqa: ANN001, ANN204
        if isinstance(event, CallbackQuery):
            await ack(event)
        return await handler(event, data)


async def on_error(event: ErrorEvent) -> bool:
    """Last-resort handler: log and show a generic Russian message."""

    logger.error(
        "bot_unhandled_error error=%s",
        type(event.exception).__name__,
        exc_info=event.exception,
    )
    update = event.update
    message_obj = None
    callback = getattr(update, "callback_query", None)
    if callback is not None:
        message_obj = callback.message
    elif getattr(update, "message", None) is not None:
        message_obj = update.message
    if message_obj is not None:
        try:
            await message_obj.answer(texts.ERR_GENERIC)
        except Exception:  # noqa: BLE001
            logger.debug("bot_error_notice_failed")
    return True
