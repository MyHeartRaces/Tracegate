"""Client config delivery (link, QR, file) and chat cleanup of old configs."""

from __future__ import annotations

import io
from typing import Any

import qrcode
from aiogram.types import CallbackQuery
from aiogram.types.input_file import BufferedInputFile

from tracegate.bot import context as ctx
from tracegate.bot import guide, keyboards, nav, texts
from tracegate.bot.profiles import connection_label
from tracegate.client_export.config import ClientConfigExportError, export_client_config

HIDDEN_EXPORT_EXTRA_TITLES = frozenset({"local socks5 credentials"})
QR_FILENAME = "tracegate-config-qr.png"
DEFAULT_ATTACHMENT_FILENAME = "tracegate-config.json"


def build_qr_png(payload: str) -> bytes:
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=2,
    )
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def visible_extra_messages(extra_messages: object) -> tuple[tuple[str, str], ...]:
    visible: list[tuple[str, str]] = []
    for item in extra_messages or ():
        try:
            title, content = item
        except (TypeError, ValueError):
            continue
        normalized_title = str(title or "").strip()
        if normalized_title.lower() in HIDDEN_EXPORT_EXTRA_TITLES:
            continue
        visible.append((normalized_title, str(content or "")))
    return tuple(visible)


def _has_attachment(exported: Any) -> bool:
    return bool(getattr(exported, "attachment_content", None) and getattr(exported, "attachment_filename", None))


def export_formats(exported: Any) -> list[str]:
    """Russian names of what a delivery for this export contains."""

    formats: list[str] = []
    if exported.kind == "uri":
        formats.extend([texts.FORMAT_LINK, texts.FORMAT_QR])
        if exported.alternate_content:
            formats.append(texts.FORMAT_ALTERNATE)
    if _has_attachment(exported):
        formats.append(texts.FORMAT_FILE)
    return formats


def formats_for_revision(revision: dict | None) -> list[str]:
    if not revision:
        return []
    try:
        return export_formats(export_client_config(revision.get("effective_config_json") or {}))
    except Exception:  # noqa: BLE001 - the page still renders without formats
        return []


# ----------------------------------------------------- message registration ---


async def register_bot_message(
    callback: CallbackQuery,
    *,
    message_id: int,
    connection_id: str | None,
    device_id: str | None,
    revision_id: str | None,
) -> None:
    message = callback.message
    if message is None:
        return
    try:
        await ctx.api.register_bot_message(
            telegram_id=callback.from_user.id,
            chat_id=message.chat.id,
            message_id=message_id,
            connection_id=connection_id,
            device_id=device_id,
            revision_id=revision_id,
        )
    except Exception as exc:  # noqa: BLE001 - cleanup bookkeeping is best-effort
        nav.logger.warning("bot_message_register_failed error=%s", type(exc).__name__)


async def cleanup_related_messages(
    callback: CallbackQuery,
    *,
    connection_id: str | None = None,
    device_id: str | None = None,
    revision_id: str | None = None,
) -> None:
    if not any([connection_id, device_id, revision_id]):
        return
    try:
        refs = await ctx.api.cleanup_bot_messages(
            connection_id=connection_id,
            device_id=device_id,
            revision_id=revision_id,
        )
    except Exception as exc:  # noqa: BLE001
        nav.logger.warning("bot_message_cleanup_failed error=%s", type(exc).__name__)
        return
    for ref in refs or []:
        try:
            await callback.bot.delete_message(chat_id=int(ref["chat_id"]), message_id=int(ref["message_id"]))
        except Exception:  # noqa: BLE001 - already deleted or too old
            continue


async def cleanup_connection_messages(callback: CallbackQuery, connection_ids: object) -> None:
    if not isinstance(connection_ids, list):
        return
    seen: set[str] = set()
    for raw_connection_id in connection_ids:
        connection_id = str(raw_connection_id or "").strip()
        if not connection_id or connection_id in seen:
            continue
        seen.add(connection_id)
        await cleanup_related_messages(callback, connection_id=connection_id)


class _ConfigSender:
    """Sends delivery messages and registers each one for later cleanup."""

    def __init__(self, callback: CallbackQuery, *, connection_id: str, device_id: str, revision_id: str) -> None:
        self.callback = callback
        self.message = callback.message
        self.refs = {
            "connection_id": connection_id or None,
            "device_id": device_id or None,
            "revision_id": revision_id or None,
        }

    async def _register(self, sent: Any) -> None:
        message_id = getattr(sent, "message_id", None)
        if message_id is None:
            return
        await register_bot_message(self.callback, message_id=int(message_id), **self.refs)

    async def text(self, text: str, reply_markup: Any = None) -> None:
        kwargs: dict[str, Any] = {"disable_web_page_preview": True}
        if reply_markup is not None:
            kwargs["reply_markup"] = reply_markup
        await self._register(await self.message.answer(text, **kwargs))

    async def photo(self, data: bytes, *, filename: str, caption: str) -> None:
        await self._register(await self.message.answer_photo(BufferedInputFile(data, filename=filename), caption=caption))

    async def document(self, data: bytes, *, filename: str, caption: str) -> None:
        await self._register(
            await self.message.answer_document(BufferedInputFile(data, filename=filename), caption=caption)
        )


async def send_client_config(
    callback: CallbackQuery,
    revision: dict,
    *,
    context: str = "created",
    connection: dict | None = None,
) -> bool:
    """Deliver a revision as link/QR/file messages. Returns False on failure."""

    message = callback.message
    if message is None:
        return False
    revision_id = str(revision.get("id") or "")
    connection_id = str(revision.get("connection_id") or "")
    if connection is None and connection_id:
        try:
            connection = await ctx.api.get_connection(connection_id)
        except Exception as exc:  # noqa: BLE001 - the label falls back to a generic one
            nav.log_error("config_delivery_connection", exc)
            connection = None
    connection = connection or {}
    device_id = str(connection.get("device_id") or "")
    label = connection_label(connection) if connection else texts.LABEL_OTHER

    try:
        exported = export_client_config(revision.get("effective_config_json") or {})
    except ClientConfigExportError as exc:
        nav.log_error("config_export", exc)
        await message.answer(texts.ERR_SHOW_CONFIG)
        return False

    has_attachment = _has_attachment(exported)
    if exported.kind not in {"uri", "attachment"} or (exported.kind == "attachment" and not has_attachment):
        nav.logger.error("bot_config_export_unusable kind=%s", exported.kind)
        await message.answer(texts.ERR_SHOW_CONFIG)
        return False

    extras = visible_extra_messages(exported.extra_messages)
    is_uri = exported.kind == "uri"
    prefer_attachment = bool(
        is_uri and has_attachment and str(exported.attachment_filename or "").endswith(".xray.json")
    )
    header = texts.config_delivery_message(
        label=label,
        context=context,
        has_primary_uri=is_uri,
        has_attachment=has_attachment,
        prefer_attachment=prefer_attachment,
        has_alternate_uri=bool(is_uri and exported.alternate_content),
        has_extra_messages=bool(extras),
    )
    keyboard = (
        keyboards.config_delivery_keyboard(connection_id=connection_id, howto_callback=guide.howto_callback())
        if connection_id
        else None
    )
    sender = _ConfigSender(callback, connection_id=connection_id, device_id=device_id, revision_id=revision_id)

    await sender.text(header, keyboard)
    if is_uri:
        await sender.text(exported.content)
        if exported.alternate_content:
            await sender.text(f"{texts.ALTERNATE_LINK_TITLE}\n\n{exported.alternate_content}")
    for extra_title, extra_content in extras:
        await sender.text(texts.extra_message(extra_title, extra_content))
    if is_uri:
        await sender.photo(build_qr_png(exported.content), filename=QR_FILENAME, caption=texts.qr_caption(label))
    if has_attachment:
        await sender.document(
            exported.attachment_content,
            filename=exported.attachment_filename or DEFAULT_ATTACHMENT_FILENAME,
            caption=texts.file_caption(label),
        )
    return True
