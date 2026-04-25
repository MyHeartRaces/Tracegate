from __future__ import annotations

import asyncio
import io
import ssl
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version as pkg_version
from pathlib import Path

from aiogram import BaseMiddleware, Bot, Dispatcher, F, Router
from aiogram.exceptions import TelegramBadRequest, TelegramForbiddenError, TelegramRetryAfter
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message
from aiogram.types import FSInputFile
from aiogram.types.input_file import BufferedInputFile
from aiogram.webhook.aiohttp_server import SimpleRequestHandler, setup_application
from aiohttp import web

import qrcode
from tracegate.bot.access import (
    blocked_message,
    bot_block_until,
    can_manage_block,
    can_manage_user_access,
    is_admin,
    is_bot_blocked,
    is_superadmin,
    user_label,
)
from tracegate.bot.admin_tools import (
    build_admin_mtproto_report,
    build_admin_users_report,
    build_feedback_admin_text,
    format_block_until_label,
    parse_user_block_request,
)
from tracegate.bot.client import ApiClientError, TracegateApiClient
from tracegate.bot.metrics import BotMetricsMiddleware, maybe_start_bot_metrics_server
from tracegate.bot.startup import delete_webhook_with_retry
from tracegate.bot.keyboards import (
    PROVIDER_CHOICES,
    SNI_PAGE_SIZE,
    admin_menu_keyboard,
    admin_mtproto_keyboard,
    cancel_only_keyboard,
    confirm_action_keyboard,
    config_delivery_keyboard,
    admin_user_revoke_notify_keyboard,
    device_actions_keyboard,
    devices_keyboard,
    feedback_admin_keyboard,
    guide_keyboard,
    main_menu_keyboard,
    mtproto_delivery_keyboard,
    provider_keyboard_with_cancel,
    revisions_keyboard,
    sni_catalog_action_keyboard,
    sni_catalog_connection_pick_keyboard,
    sni_catalog_device_pick_keyboard,
    sni_catalog_pick_keyboard,
    sni_page_keyboard_issue,
    sni_page_keyboard_new,
    vless_transport_keyboard,
)
from tracegate.client_export.v2rayn import V2RayNExportError, export_client_config
from tracegate.enums import ConnectionMode, ConnectionProtocol, ConnectionVariant
from tracegate.observability import configure_logging
from tracegate.services.bot_blocks import (
    MAX_TIMED_BOT_BLOCK_HOURS,
    PERMANENT_BOT_BLOCK_HOURS,
    is_permanent_bot_block_hours,
)
from tracegate.settings import get_settings

settings = get_settings()
api = TracegateApiClient(settings.bot_api_base_url, settings.bot_api_token)
router = Router()

def _app_version() -> str:
    try:
        return pkg_version("tracegate")
    except PackageNotFoundError:
        return "dev"
    except Exception:
        return "unknown"


def _emoji_text(emoji: str, text: str) -> str:
    raw = str(text or "").strip()
    if not raw:
        return emoji
    lines = raw.splitlines()
    return "\n".join([f"{emoji} {lines[0]}"] + lines[1:])


def _msg_info(text: str) -> str:
    return _emoji_text("ℹ️", text)


def _msg_ok(text: str) -> str:
    return _emoji_text("✅", text)


def _msg_warn(text: str) -> str:
    return _emoji_text("⚠️", text)


def _msg_prompt(text: str) -> str:
    return _emoji_text("✍️", text)


def _msg_error(error: object) -> str:
    text = str(error or "").strip() or "Неизвестная ошибка"
    lower = text.lower()
    if lower.startswith("ошибка:"):
        text = text.split(":", 1)[1].strip() or "Неизвестная ошибка"
    return _emoji_text("🔴", f"Ошибка: {text}")


def _is_grafana_disabled_error(error: object) -> bool:
    if not isinstance(error, ApiClientError):
        return False
    if int(error.status_code) != 404:
        return False
    detail = str(error.detail or "").strip().lower()
    return "grafana is disabled" in detail


def _grafana_unavailable_message() -> str:
    return _msg_warn(
        "Grafana пока не включена на этом узле.\n"
        "Когда панель будет развернута, эта кнопка начнет выдавать ссылку для входа."
    )


BLOCK_HOURS_HINT = (
    f"Срок блокировки: от 1 до {MAX_TIMED_BOT_BLOCK_HOURS} часов, "
    f"{PERMANENT_BOT_BLOCK_HOURS} = перманентно"
)


def _format_block_until_label(until: datetime | None) -> str:
    return format_block_until_label(until)


def _format_block_duration_label(hours: int) -> str:
    if is_permanent_bot_block_hours(hours):
        return "перманентно"
    return f"{int(hours)} ч."


def _build_block_notification_text(
    *,
    blocked_at: datetime,
    hours: int,
    until: datetime | None,
    reason: str | None,
) -> str:
    reason_text = (reason or "").strip() or "не указана"
    return (
        "Ваш доступ к боту заблокирован администратором.\n"
        f"Когда: {blocked_at.isoformat()}\n"
        f"На сколько: {_format_block_duration_label(hours)}\n"
        f"До: {_format_block_until_label(until)}\n"
        f"Причина: {reason_text}"
    )


def _build_unblock_notification_text(*, unblocked_at: datetime) -> str:
    return (
        "Блокировка вашего доступа к боту снята администратором.\n"
        f"Когда: {unblocked_at.isoformat()}\n"
        "Доступ восстановлен."
    )


def _build_access_revoked_notification_text(*, revoked_at: datetime) -> str:
    return (
        "Ваши активные устройства, подключения и Telegram Proxy-доступ были отозваны администратором.\n"
        f"Когда: {revoked_at.isoformat()}\n"
        "Это не блокировка бота. При необходимости запросите доступ заново."
    )


def _format_devices_text(devices: list[dict]) -> str:
    header = "📱 Устройства"
    if not devices:
        return f"{header}\n\nПока нет устройств."
    rows = [f"• {d['name']}\n  ID: {d['id']}" for d in devices]
    return f"{header}\n\n" + "\n".join(rows)


def _observability_scope_label(scope: str) -> str:
    return {
        "user": "пользовательский",
        "admin": "административный",
    }.get(str(scope or "").strip().lower(), str(scope or "").strip() or "неизвестный")


def _format_grafana_otp_message(*, scope: str, otp: dict) -> str:
    return _msg_ok(
        "Grafana\n"
        f"Контур: {_observability_scope_label(scope)}\n"
        f"Действует до: {otp.get('expires_at')}\n"
        f"Ссылка: {otp.get('login_url')}"
    )


def _mtproto_access_label(user: dict) -> str | None:
    username = str(user.get("telegram_username") or "").strip()
    if username:
        return f"@{username.lstrip('@')}"
    first = str(user.get("telegram_first_name") or "").strip()
    last = str(user.get("telegram_last_name") or "").strip()
    full = " ".join(part for part in [first, last] if part).strip()
    return full or None


def _format_mtproto_delivery_message(*, result: dict, rotate: bool) -> str:
    grant = result.get("grant") if isinstance(result.get("grant"), dict) else {}
    profile = result.get("profile") if isinstance(result.get("profile"), dict) else {}
    node = str(result.get("node") or "").strip() or "transit"
    reused = bool(profile.get("reused"))

    if rotate:
        status_line = "Секрет ротирован и готов к повторному запуску Telegram."
    elif reused:
        status_line = "Текущий постоянный Telegram Proxy-профиль отправлен повторно."
    else:
        status_line = "Постоянный Telegram Proxy-профиль выпущен и готов к использованию."

    label = str(grant.get("label") or "").strip()
    updated_at = str(grant.get("updated_at") or grant.get("last_sync_at") or "").strip()
    domain = str(profile.get("domain") or profile.get("server") or "").strip()

    lines = [
        "🔐 Telegram Proxy",
        "",
        status_line,
        f"Transit: {node}",
    ]
    if label:
        lines.append(f"Метка: {label}")
    if domain:
        lines.append(f"Домен: {domain}")
    if updated_at:
        lines.append(f"Синхронизация: {updated_at}")
    lines.extend(
        [
            "",
            "Что дальше:",
            "1. Откройте ссылку из следующего сообщения на устройстве с Telegram.",
            "2. Для замены доступа используйте «Ротировать секрет».",
            "3. Для полного отзыва используйте «Отозвать доступ».",
        ]
    )
    return "\n".join(lines)


def _main_menu_text() -> str:
    return (
        "🏠 Tracegate 2\n\n"
        "Управляйте устройствами, профилями, ревизиями и Telegram Proxy.\n"
        "Все основные действия доступны из этого меню."
    )


def _build_admin_mtproto_rows(*, grants: list[dict], users: list[dict]) -> list[dict]:
    users_by_id = {int(row.get("telegram_id") or 0): row for row in users}
    rows: list[dict] = []
    for grant in grants:
        telegram_id = int(grant.get("telegram_id") or 0)
        user = users_by_id.get(telegram_id)
        display = user_label(user) if user else (str(grant.get("label") or "").strip() or str(telegram_id))
        rows.append(
            {
                "telegram_id": telegram_id,
                "display": display,
                "role": user.get("role") if user else None,
                "label": grant.get("label"),
                "issued_by": grant.get("issued_by"),
                "updated_at": grant.get("updated_at"),
                "last_sync_at": grant.get("last_sync_at"),
            }
        )
    return rows


def _load_guide_text() -> str:
    guide_path = str(settings.bot_guide_path or "").strip()
    if guide_path:
        try:
            return Path(guide_path).read_text(encoding="utf-8").strip() or _msg_warn("Гайд пока пуст.")
        except FileNotFoundError:
            return _msg_warn("Гайд пока не настроен.")
        except Exception:
            return _msg_error("Не смог прочитать гайд.")
    return str(settings.bot_guide_message or "").strip() or "[TRACEGATE_BOT_GUIDE_PLACEHOLDER]"


def _bot_welcome_version() -> str:
    return str(settings.bot_welcome_version or "").strip() or "tracegate-2.1-client-safety-v1"


def _bot_welcome_text() -> str:
    message_file = str(settings.bot_welcome_message_file or "").strip()
    if message_file:
        try:
            text = Path(message_file).read_text(encoding="utf-8").strip()
            if text:
                return text
        except Exception:
            pass
    return str(settings.bot_welcome_message or "").strip() or "[TRACEGATE_BOT_WELCOME_MESSAGE_PLACEHOLDER]"


def _bot_welcome_accepted(user: dict) -> bool:
    if not settings.bot_welcome_required:
        return True
    accepted_at = str(user.get("bot_welcome_accepted_at") or "").strip()
    accepted_version = str(user.get("bot_welcome_version") or "").strip()
    return bool(accepted_at and accepted_version == _bot_welcome_version())


def _welcome_keyboard(callback_data: str, *, text: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text=text, callback_data=callback_data)]]
    )


async def _send_welcome_step(message: Message, *, step: int) -> None:
    if step == 1:
        text = _bot_welcome_text()
        callback_data = "welcome_continue_1"
        button_text = "Ознакомился с текстом и готов продолжить?"
    else:
        text = "Вы уверены?"
        callback_data = "welcome_continue_2"
        button_text = "Точно готов?"
    await message.answer(
        text,
        disable_web_page_preview=True,
        reply_markup=_welcome_keyboard(callback_data, text=button_text),
    )


async def _edit_welcome_step(callback: CallbackQuery, *, step: int) -> None:
    if step == 1:
        text = _bot_welcome_text()
        callback_data = "welcome_continue_1"
        button_text = "Ознакомился с текстом и готов продолжить?"
    else:
        text = "Вы уверены?"
        callback_data = "welcome_continue_2"
        button_text = "Точно готов?"
    await callback.message.edit_text(
        text,
        disable_web_page_preview=True,
        reply_markup=_welcome_keyboard(callback_data, text=button_text),
    )


async def _cleanup_chat_history(bot: Bot, chat_id: int, from_message_id: int, *, limit: int) -> None:
    # Telegram does not provide "clear chat" API; we delete recent messages one-by-one (best-effort).
    lower = max(1, int(from_message_id) - int(limit) + 1)
    for mid in range(int(from_message_id), lower - 1, -1):
        try:
            await bot.delete_message(chat_id=chat_id, message_id=mid)
        except TelegramRetryAfter as exc:
            await asyncio.sleep(float(exc.retry_after))
        except (TelegramBadRequest, TelegramForbiddenError):
            continue
        except Exception:
            continue
        await asyncio.sleep(0.02)


async def _send_main_menu(message: Message) -> None:
    user = await ensure_user(message.from_user.id)
    await message.answer(
        _main_menu_text(),
        reply_markup=main_menu_keyboard(is_admin=is_admin(user)),
    )


async def _send_mtproto_access(callback: CallbackQuery, *, rotate: bool) -> None:
    user = await ensure_user(callback.from_user.id)
    result = await api.issue_mtproto_access(
        telegram_id=int(user["telegram_id"]),
        label=_mtproto_access_label(user),
        rotate=rotate,
        issued_by="bot",
    )
    profile = result.get("profile") or {}
    https_url = str(profile.get("httpsUrl") or "").strip()
    tg_uri = str(profile.get("tgUri") or "").strip()
    if not https_url:
        raise ValueError("API did not return a valid MTProto httpsUrl")

    await callback.message.answer(
        _format_mtproto_delivery_message(result=result, rotate=rotate),
        reply_markup=mtproto_delivery_keyboard(),
    )
    link_lines = ["🔗 Ссылка для Telegram", "", https_url]
    if tg_uri:
        link_lines.extend(["", "tg:// deep link:", tg_uri])
    await callback.message.answer("\n".join(link_lines), disable_web_page_preview=True)
    qr_bytes = _build_qr_png(https_url)
    await callback.message.answer_photo(
        BufferedInputFile(qr_bytes, filename="tracegate-mtproto-qr.png"),
        caption="📷 QR для Telegram Proxy",
    )


def _grafana_scope_for_user(user: dict) -> str:
    return "admin" if is_admin(user) else "user"


class DeviceFlow(StatesGroup):
    waiting_for_name = State()


class FeedbackFlow(StatesGroup):
    waiting_for_message = State()


class SniCatalogFlow(StatesGroup):
    waiting_for_input = State()

class AdminFlow(StatesGroup):
    waiting_for_grant_id = State()
    waiting_for_revoke_id = State()
    waiting_for_mtproto_revoke_id = State()
    waiting_for_user_access_revoke_id = State()
    waiting_for_user_access_revoke_notify = State()
    waiting_for_user_block = State()
    waiting_for_user_unblock = State()
    waiting_for_announce_text = State()


class BotAccessMiddleware(BaseMiddleware):
    async def __call__(self, handler, event, data):  # noqa: ANN001, ANN204
        from_user = data.get("event_from_user")
        if from_user is None:
            return await handler(event, data)

        try:
            user = await api.get_or_create_user(
                from_user.id,
                telegram_username=getattr(from_user, "username", None),
                telegram_first_name=getattr(from_user, "first_name", None),
                telegram_last_name=getattr(from_user, "last_name", None),
            )
        except ApiClientError:
            return await handler(event, data)
        data["tracegate_user"] = user

        if is_bot_blocked(user):
            text = blocked_message(user)
            if isinstance(event, CallbackQuery):
                try:
                    await event.answer(_msg_warn("Доступ ограничен"), show_alert=True)
                except Exception:
                    pass
                if event.message is not None:
                    await event.message.answer(_msg_warn(text))
                return None
            if isinstance(event, Message):
                await event.answer(_msg_warn(text))
                return None
        if settings.bot_welcome_required and not _bot_welcome_accepted(user):
            if isinstance(event, CallbackQuery):
                data_value = str(event.data or "")
                if data_value.startswith("welcome_continue_"):
                    return await handler(event, data)
                try:
                    await event.answer(_msg_warn("Сначала подтвердите приветствие"), show_alert=True)
                except Exception:
                    pass
                if event.message is not None:
                    await _send_welcome_step(event.message, step=1)
                return None
            if isinstance(event, Message):
                text = str(event.text or "").strip()
                if text.startswith("/start"):
                    return await handler(event, data)
                await _send_welcome_step(event, step=1)
                return None
        return await handler(event, data)


async def ensure_user(telegram_id: int) -> dict:
    return await api.get_or_create_user(telegram_id)


async def _load_admin_chat_ids() -> list[int]:
    ids: set[int] = {int(value) for value in (settings.superadmin_telegram_ids or []) if int(value) > 0}
    for role in ("admin", "superadmin"):
        rows = await api.list_users(role=role, limit=500, include_empty=True, prune_empty=False)
        for row in rows:
            telegram_id = int(row.get("telegram_id") or 0)
            if telegram_id > 0:
                ids.add(telegram_id)
    return sorted(ids)


def _feedback_text_from_message(message: Message) -> str:
    return (message.text or message.caption or "").strip()


def _connection_family_name(protocol: str, mode: str) -> str:
    p = (protocol or "").strip().lower()
    m = (mode or "").strip().lower()
    if p == ConnectionProtocol.VLESS_REALITY.value:
        return "VLESS Reality Chain" if m == ConnectionMode.CHAIN.value else "VLESS Reality Direct"
    if p == ConnectionProtocol.VLESS_GRPC_TLS.value:
        return "VLESS gRPC-TLS Direct"
    if p == ConnectionProtocol.VLESS_WS_TLS.value:
        return "VLESS WS-TLS Direct"
    if p == ConnectionProtocol.HYSTERIA2.value:
        return "Hysteria2 QUIC Chain" if m == ConnectionMode.CHAIN.value else "Hysteria2 QUIC Direct"
    if p == ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS.value:
        return "Shadowsocks2022 ShadowTLS Chain" if m == ConnectionMode.CHAIN.value else "Shadowsocks2022 ShadowTLS Direct"
    if p == ConnectionProtocol.WIREGUARD_WSTUNNEL.value:
        return "WireGuard WSTunnel Direct"
    return f"{protocol}/{mode}"


def _provider_label(provider: str) -> str:
    normalized = str(provider or "").strip()
    mapping = {code: label for (label, code) in PROVIDER_CHOICES}
    return mapping.get(normalized, normalized or "Все")


def _revision_status_label(status: str) -> str:
    normalized = str(status or "").strip().lower()
    return {
        "active": "активна",
        "revoked": "отозвана",
    }.get(normalized, normalized or "неизвестно")


def _connection_profile_label(connection: dict) -> str:
    protocol = str(connection.get("protocol") or "").strip().lower()
    mode = str(connection.get("mode") or "").strip().lower()
    variant = str(connection.get("variant") or "").strip() or "V?"

    if protocol == ConnectionProtocol.VLESS_REALITY.value:
        suffix = "Chain" if mode == ConnectionMode.CHAIN.value else "Direct"
        return f"{variant}-VLESS-Reality-{suffix}"
    if protocol == ConnectionProtocol.VLESS_GRPC_TLS.value:
        return f"{variant}-VLESS-gRPC-TLS-Direct"
    if protocol == ConnectionProtocol.VLESS_WS_TLS.value:
        return f"{variant}-VLESS-WS-TLS-Direct"
    if protocol == ConnectionProtocol.HYSTERIA2.value:
        suffix = "Chain" if mode == ConnectionMode.CHAIN.value else "Direct"
        return f"{variant}-Hysteria2-QUIC-{suffix}"
    if protocol == ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS.value:
        suffix = "Chain" if mode == ConnectionMode.CHAIN.value else "Direct"
        return f"{variant}-Shadowsocks2022-ShadowTLS-{suffix}"
    if protocol == ConnectionProtocol.WIREGUARD_WSTUNNEL.value:
        return f"{variant}-WireGuard-WSTunnel-Direct"
    return f"{variant} | {_connection_family_name(protocol, mode)}"


def _format_connection_card(connection: dict) -> str:
    lines = [f"• {_connection_profile_label(connection)}", f"  ID: {connection.get('id')}"]
    alias = str(connection.get("alias") or "").strip()
    if alias:
        lines.append(f"  Метка: {alias}")
    return "\n".join(lines)


async def render_device_page(device_id: str) -> tuple[str, object]:
    device = await api.get_device(device_id)
    connections = await api.list_connections(device_id)
    text = (
        "🔌 Устройство\n\n"
        f"Имя: {device.get('name')}\n"
        f"ID: {device_id}\n"
        f"Подключений: {len(connections)}\n\n"
    )
    if connections:
        text += "\n\n".join(_format_connection_card(connection) for connection in connections)
    else:
        text += "Пока нет подключений."
    return text, device_actions_keyboard(device_id, connections)


async def render_revisions_page(connection_id: str) -> tuple[str, object]:
    connection = await api.get_connection(connection_id)
    device = await api.get_device(connection["device_id"])
    revisions = await api.list_revisions(connection_id)
    alias = (connection.get("alias") or "").strip()
    current = _current_revision_from_list(revisions)
    text = (
        "🧩 Ревизии\n\n"
        f"Профиль: {_connection_profile_label(connection)}\n"
        f"Устройство: {device.get('name')}\n"
        f"Подключение: {connection_id}\n"
    )
    if alias:
        text += f"Метка: {alias}\n"
    if current is not None:
        text += f"Текущая ревизия: слот {current['slot']} · {current['id']}\n"
    else:
        text += "Текущая ревизия: нет\n"
    text += "\n"
    if revisions:
        rows = [f"• Слот {r['slot']} · {_revision_status_label(r['status'])}\n  ID: {r['id']}" for r in revisions]
        text += "\n\n".join(rows)
    else:
        text += "Пока нет ревизий."

    is_vless = connection["protocol"] in {
        ConnectionProtocol.VLESS_REALITY.value,
        ConnectionProtocol.VLESS_GRPC_TLS.value,
        ConnectionProtocol.VLESS_WS_TLS.value,
    }
    return text, revisions_keyboard(connection_id, revisions, is_vless, connection["device_id"])


def _current_revision_from_list(revisions: list[dict]) -> dict | None:
    active = [row for row in revisions if str(row.get("status") or "").upper() == "ACTIVE"]
    for row in active:
        try:
            if int(row.get("slot")) == 0:
                return row
        except Exception:
            continue
    if active:
        return sorted(
            active,
            key=lambda row: (
                int(row.get("slot", 999)) if str(row.get("slot", "")).strip().isdigit() else 999,
                str(row.get("created_at") or ""),
            ),
        )[0]
    return None


@router.callback_query(F.data == "noop")
async def noop(callback: CallbackQuery) -> None:
    # Used for non-clickable pagination labels.
    await callback.answer()

async def _safe_edit_text(message_obj, text: str, reply_markup: object | None = None) -> bool:
    try:
        await message_obj.edit_text(text, reply_markup=reply_markup)
        return True
    except TelegramBadRequest as exc:
        msg = str(exc).lower()
        if "message is not modified" in msg:
            return False
        raise


def _config_delivery_context_label(context: str) -> str:
    normalized = str(context or "").strip().lower()
    return {
        "created": "Подключение создано и готово к импорту.",
        "issued": "Новая ревизия выпущена и готова к импорту.",
        "current": "Текущая активная ревизия готова к повторному импорту.",
    }.get(normalized, "Конфигурация подготовлена.")


def _format_config_delivery_message(
    *,
    marker: str,
    title: str,
    revision: dict,
    context: str = "default",
    has_attachment: bool = False,
    has_alternate_uri: bool = False,
    has_extra_messages: bool = False,
) -> str:
    next_steps = [
        "1. Скопируйте ссылку из следующего сообщения и импортируйте её в клиент.",
        "2. Или используйте QR из сообщения ниже.",
    ]
    if has_attachment:
        next_steps.insert(1, "2. Если клиент плохо импортирует URI, используйте приложенный `.json` файл.")
        next_steps[2] = "3. Или используйте QR из сообщения ниже."
        next_steps.append("4. После импорта вернитесь к устройству или ревизиям по кнопкам.")
    else:
        next_steps.append("3. После импорта вернитесь к устройству или ревизиям по кнопкам.")
    if has_alternate_uri:
        next_steps.append("5. Ниже будет отдельный raw-token fallback URI.")
    if has_extra_messages:
        next_steps.append("6. Ниже будут дополнительные параметры для ручного ввода, например локальный SOCKS5 или WSTunnel.")
    return (
        f"🔗 Конфигурация готова\n\n"
        f"{_config_delivery_context_label(context)}\n"
        f"{marker}\n"
        f"{title}\n"
        f"Ревизия: {revision.get('id')}\n"
        f"Слот: {revision.get('slot')}\n\n"
        "Что дальше:\n"
        + "\n".join(next_steps)
    )


def _format_device_delete_confirmation(*, device_name: str, device_id: str) -> str:
    return _msg_warn(
        "Удалить устройство?\n"
        f"Имя: {device_name}\n"
        f"ID: {device_id}\n\n"
        "Будут отозваны все связанные подключения и ревизии."
    )


def _format_connection_delete_confirmation(connection: dict) -> str:
    family = _connection_family_name(connection.get("protocol", ""), connection.get("mode", ""))
    alias = (connection.get("alias") or "").strip()
    marker = _connection_marker(connection)
    title = alias or family
    return _msg_warn(
        "Удалить подключение?\n"
        f"{marker}\n"
        f"Профиль: {title}\n\n"
        "Текущая и архивные ревизии будут отозваны."
    )


def _format_revision_delete_confirmation(connection: dict, revision: dict) -> str:
    marker = _connection_marker(connection)
    slot = revision.get("slot")
    status_label = _revision_status_label(str(revision.get("status") or ""))
    return _msg_warn(
        "Удалить ревизию?\n"
        f"{marker}\n"
        f"Слот: {slot}\n"
        f"Статус: {status_label}\n\n"
        "Связанные сообщения с конфигом будут очищены."
    )


def _connection_marker(connection: dict) -> str:
    variant = str(connection.get("variant") or "").strip() or "V?"
    tg_id = str(connection.get("user_id") or "").strip() or "?"
    device_id = str(connection.get("device_id") or "").strip() or "?"
    device_name = str(connection.get("device_name") or "").strip()
    device_part = f"{device_id}({device_name})" if device_name else device_id
    connection_id = str(connection.get("id") or "").strip() or "?"
    return f"{variant} - {tg_id} - {device_part} - {connection_id}"


def _build_qr_png(payload: str) -> bytes:
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


async def _register_bot_message_ref(
    callback: CallbackQuery,
    *,
    message_id: int,
    connection_id: str | None,
    device_id: str | None,
    revision_id: str | None,
) -> None:
    msg = callback.message
    if msg is None:
        return
    try:
        await api.register_bot_message(
            telegram_id=callback.from_user.id,
            chat_id=msg.chat.id,
            message_id=message_id,
            connection_id=connection_id,
            device_id=device_id,
            revision_id=revision_id,
        )
    except Exception:
        # Message cleanup is best-effort and must not break the main flow.
        pass


async def _cleanup_related_messages(
    callback: CallbackQuery,
    *,
    connection_id: str | None = None,
    device_id: str | None = None,
    revision_id: str | None = None,
) -> None:
    if not any([connection_id, device_id, revision_id]):
        return
    try:
        refs = await api.cleanup_bot_messages(
            connection_id=connection_id,
            device_id=device_id,
            revision_id=revision_id,
        )
    except Exception:
        return
    for ref in refs:
        try:
            await callback.bot.delete_message(chat_id=int(ref["chat_id"]), message_id=int(ref["message_id"]))
        except Exception:
            continue


async def _send_client_config(callback: CallbackQuery, revision: dict, *, context: str = "default") -> None:
    effective = revision.get("effective_config_json") or {}
    revision_id = str(revision.get("id") or "")
    connection_id = str(revision.get("connection_id") or "")
    device_id: str | None = None
    marker: str | None = None
    try:
        if connection_id:
            conn = await api.get_connection(connection_id)
            device_id = str(conn.get("device_id") or "")
            marker = _connection_marker(conn)
    except Exception:
        device_id = None
        marker = None

    if not marker:
        marker = f"V? - {callback.from_user.id} - {device_id or '?'} - {connection_id or '?'}"

    try:
        exported = export_client_config(effective)
    except V2RayNExportError as exc:
        await callback.message.answer(_msg_error(f"Не смог собрать конфиг для клиента: {exc}"))
        return

    if exported.kind == "uri":
        summary_msg = await callback.message.answer(
            _format_config_delivery_message(
                marker=marker,
                title=exported.title,
                revision=revision,
                context=context,
                has_attachment=bool(exported.attachment_content and exported.attachment_filename),
                has_alternate_uri=bool(exported.alternate_content),
                has_extra_messages=bool(exported.extra_messages),
            ),
            reply_markup=(
                config_delivery_keyboard(connection_id=connection_id, device_id=device_id)
                if connection_id and device_id
                else None
            ),
        )
        await _register_bot_message_ref(
            callback,
            message_id=summary_msg.message_id,
            connection_id=connection_id or None,
            device_id=device_id or None,
            revision_id=revision_id or None,
        )
        uri_msg = await callback.message.answer(exported.content, disable_web_page_preview=True)
        await _register_bot_message_ref(
            callback,
            message_id=uri_msg.message_id,
            connection_id=connection_id or None,
            device_id=device_id or None,
            revision_id=revision_id or None,
        )
        if exported.alternate_content and exported.alternate_title:
            alt_msg = await callback.message.answer(
                f"{exported.alternate_title}\n\n{exported.alternate_content}",
                disable_web_page_preview=True,
            )
            await _register_bot_message_ref(
                callback,
                message_id=alt_msg.message_id,
                connection_id=connection_id or None,
                device_id=device_id or None,
                revision_id=revision_id or None,
            )
        for extra_title, extra_content in exported.extra_messages:
            extra_msg = await callback.message.answer(
                f"{extra_title}\n\n{extra_content}",
                disable_web_page_preview=True,
            )
            await _register_bot_message_ref(
                callback,
                message_id=extra_msg.message_id,
                connection_id=connection_id or None,
                device_id=device_id or None,
                revision_id=revision_id or None,
            )
        qr_bytes = _build_qr_png(exported.content)
        qr_msg = await callback.message.answer_photo(
            BufferedInputFile(qr_bytes, filename="tracegate-config-qr.png"),
            caption=f"📷 QR для импорта\n\n{marker}\n{exported.title}",
        )
        await _register_bot_message_ref(
            callback,
            message_id=qr_msg.message_id,
            connection_id=connection_id or None,
            device_id=device_id or None,
            revision_id=revision_id or None,
        )
        if exported.attachment_content and exported.attachment_filename:
            document_msg = await callback.message.answer_document(
                BufferedInputFile(exported.attachment_content, filename=exported.attachment_filename),
                caption=f"📎 Файл для импорта\n\n{marker}\n{exported.title}",
            )
            await _register_bot_message_ref(
                callback,
                message_id=document_msg.message_id,
                connection_id=connection_id or None,
                device_id=device_id or None,
                revision_id=revision_id or None,
            )
        return

    await callback.message.answer(_msg_error(f"Неизвестный тип экспорта: {exported.kind}"))


@router.message(CommandStart())
async def start(message: Message) -> None:
    user = await ensure_user(message.from_user.id)
    if not _bot_welcome_accepted(user):
        await _send_welcome_step(message, step=1)
        return
    await _send_main_menu(message)


@router.callback_query(F.data == "welcome_continue_1")
async def welcome_continue_1(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    user = await ensure_user(callback.from_user.id)
    if _bot_welcome_accepted(user):
        await callback.message.edit_text(
            _main_menu_text(),
            reply_markup=main_menu_keyboard(is_admin=is_admin(user)),
        )
        await callback.answer()
        return
    await _edit_welcome_step(callback, step=2)
    await callback.answer()


@router.callback_query(F.data == "welcome_continue_2")
async def welcome_continue_2(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    user = await ensure_user(callback.from_user.id)
    if not _bot_welcome_accepted(user):
        user = await api.accept_bot_welcome(int(user["telegram_id"]), version=_bot_welcome_version())
    await callback.message.edit_text(
        _main_menu_text(),
        reply_markup=main_menu_keyboard(is_admin=is_admin(user)),
    )
    await callback.answer()


@router.message(Command("guide"))
async def guide(message: Message) -> None:
    await message.answer(
        _emoji_text("📘", _load_guide_text()),
        disable_web_page_preview=True,
        reply_markup=guide_keyboard(),
    )


@router.callback_query(F.data == "guide_open")
async def guide_open(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await callback.message.edit_text(
        _emoji_text("📘", _load_guide_text()),
        disable_web_page_preview=True,
        reply_markup=guide_keyboard(),
    )
    await callback.answer()


@router.message(Command("clear"))
async def clear(message: Message, state: FSMContext) -> None:
    await state.clear()
    if message.chat.type != "private":
        await message.answer(_msg_warn("Команда /clear доступна только в личном чате с ботом."))
        return

    from_mid = int(message.message_id)
    asyncio.create_task(
        _cleanup_chat_history(
            message.bot,
            int(message.chat.id),
            from_mid,
            limit=int(settings.bot_clean_max_messages),
        )
    )
    await _send_main_menu(message)


@router.message(Command("cancel"))
async def cancel(message: Message, state: FSMContext) -> None:
    await state.clear()
    if message.chat.type != "private":
        await message.answer(_msg_warn("Команда /cancel доступна только в личном чате с ботом."))
        return
    await message.answer(_msg_warn("Отменено."))
    await _send_main_menu(message)


@router.callback_query(F.data == "feedback_start")
async def feedback_start(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await state.set_state(FeedbackFlow.waiting_for_message)
    await callback.message.answer(
        _msg_prompt(
            "Напишите сообщение для команды Tracegate.\n"
            "Его увидят администраторы проекта, а ваш Telegram ID будет приложен.\n"
            "/cancel для отмены."
        ),
        reply_markup=cancel_only_keyboard(cancel_callback_data="menu"),
    )
    await callback.answer()


@router.message(FeedbackFlow.waiting_for_message)
async def feedback_message(message: Message, state: FSMContext) -> None:
    try:
        text = _feedback_text_from_message(message)
        if not text:
            await message.answer(_msg_warn("Сообщение не может быть пустым.\n/cancel для отмены."))
            return

        author = await ensure_user(message.from_user.id)
        admin_chat_ids = await _load_admin_chat_ids()
        if not admin_chat_ids:
            await message.answer(_msg_error("Список администраторов пуст, сообщение не отправлено."))
            return

        sent_at = datetime.now(timezone.utc)
        admin_text = build_feedback_admin_text(author=author, feedback_text=text, sent_at=sent_at)
        sent = 0
        failed = 0
        for chat_id in admin_chat_ids:
            try:
                await message.bot.send_message(
                    chat_id=chat_id,
                    text=admin_text,
                    reply_markup=feedback_admin_keyboard(telegram_id=int(author["telegram_id"])),
                )
                sent += 1
            except TelegramRetryAfter as exc:
                await asyncio.sleep(float(exc.retry_after))
                try:
                    await message.bot.send_message(
                        chat_id=chat_id,
                        text=admin_text,
                        reply_markup=feedback_admin_keyboard(telegram_id=int(author["telegram_id"])),
                    )
                    sent += 1
                except Exception:
                    failed += 1
            except (TelegramForbiddenError, TelegramBadRequest):
                failed += 1
            except Exception:
                failed += 1
            await asyncio.sleep(0.04)

        if sent == 0:
            await message.answer(_msg_error("Не удалось доставить сообщение администраторам."))
            return

        if failed:
            await message.answer(
                _msg_ok(
                    "Сообщение передано команде Tracegate.\n"
                    f"Доставлено: {sent}\n"
                    f"Ошибки: {failed}"
                )
            )
        else:
            await message.answer(_msg_ok("Сообщение передано команде Tracegate."))
        await _send_main_menu(message)
    except ApiClientError as exc:
        await message.answer(_msg_error(exc))
    finally:
        await state.clear()


@router.message(Command("announce"))
async def announce(message: Message, state: FSMContext) -> None:
    await state.clear()
    if message.chat.type != "private":
        await message.answer(_msg_warn("Команда /announce доступна только в личном чате с ботом."))
        return
    actor = await ensure_user(message.from_user.id)
    if not is_admin(actor):
        await message.answer(_msg_warn("Недостаточно прав"))
        return
    await state.set_state(AdminFlow.waiting_for_announce_text)
    await message.answer(
        _msg_prompt("Введите текст для рассылки всем пользователям.\n/cancel для отмены."),
        reply_markup=cancel_only_keyboard(cancel_callback_data="admin_menu"),
    )


@router.message(AdminFlow.waiting_for_announce_text)
async def announce_text(message: Message, state: FSMContext) -> None:
    try:
        text = (message.text or "").strip()
        if not text:
            await message.answer(_msg_warn("Сообщение не может быть пустым.\n/cancel для отмены."))
            return

        actor = await ensure_user(message.from_user.id)
        if not is_admin(actor):
            await message.answer(_msg_warn("Недостаточно прав"))
            return

        users = await api.list_users(limit=1000, include_empty=True, prune_empty=False)
        sent = 0
        failed = 0
        for user in users:
            telegram_id = int(user.get("telegram_id") or 0)
            if not telegram_id:
                continue
            try:
                await message.bot.send_message(chat_id=telegram_id, text=text)
                sent += 1
            except TelegramRetryAfter as exc:
                await asyncio.sleep(float(exc.retry_after))
                try:
                    await message.bot.send_message(chat_id=telegram_id, text=text)
                    sent += 1
                except Exception:
                    failed += 1
            except (TelegramForbiddenError, TelegramBadRequest):
                failed += 1
            except Exception:
                failed += 1
            await asyncio.sleep(0.04)

        await message.answer(
            _msg_ok(
                "Рассылка завершена.\n"
                f"Доставлено: {sent}\n"
                f"Ошибки: {failed}"
            )
        )
    except ApiClientError as exc:
        await message.answer(_msg_error(exc))
    finally:
        await state.clear()


@router.callback_query(F.data == "menu")
async def menu(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    user = await ensure_user(callback.from_user.id)
    await callback.message.edit_text(
        _main_menu_text(),
        reply_markup=main_menu_keyboard(is_admin=is_admin(user)),
    )
    await callback.answer()


@router.callback_query(F.data == "admin_menu")
async def admin_menu(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    user = await ensure_user(callback.from_user.id)
    if not is_admin(user):
        await callback.answer(_msg_warn("Недостаточно прав"))
        return
    await callback.message.edit_text(
        "🛠️ Управление Tracegate\n\nОперации доступа, блокировок, рассылок, Grafana и Telegram Proxy.",
        reply_markup=admin_menu_keyboard(is_superadmin=is_superadmin(user)),
    )
    await callback.answer()


@router.callback_query(F.data == "admin_reset_connections")
async def admin_reset_connections(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    actor = await ensure_user(callback.from_user.id)
    if not is_admin(actor):
        await callback.answer(_msg_warn("Недостаточно прав"))
        return

    kb = InlineKeyboardMarkup(
        inline_keyboard=confirm_action_keyboard(
            confirm_callback_data="admin_reset_connections_confirm",
            cancel_callback_data="admin_menu",
            confirm_text="Подтвердить отзыв",
        ).inline_keyboard
    )
    await callback.message.answer(
        _msg_warn(
            "Будут отозваны все активные подключения и постоянные Telegram Proxy-доступы у всех пользователей.\n"
            "Данные пользователей и устройств не удаляются.\n\n"
            "Подтвердите действие."
        ),
        reply_markup=kb,
    )
    await callback.answer()


@router.callback_query(F.data == "admin_reset_connections_confirm")
async def admin_reset_connections_confirm(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    actor = await ensure_user(callback.from_user.id)
    if not is_admin(actor):
        await callback.answer(_msg_warn("Недостаточно прав"))
        return
    try:
        result = await api.reset_all_connections(actor_telegram_id=callback.from_user.id)
        revoked = int(result.get("revoked_connections") or 0)
        revoked_mtproto = int(result.get("revoked_mtproto_accesses") or 0)
        await callback.message.answer(
            _msg_ok(
                "Глобальный отзыв завершен.\n"
                f"Подключения: {revoked}\n"
                f"Telegram Proxy: {revoked_mtproto}"
            )
        )
    except ApiClientError as exc:
        await callback.message.answer(_msg_error(exc))
    await callback.answer()


@router.callback_query(F.data == "grafana_otp")
async def grafana_otp(callback: CallbackQuery) -> None:
    try:
        if not settings.grafana_enabled:
            await callback.message.answer(_grafana_unavailable_message())
            await callback.answer()
            return
        user = await ensure_user(callback.from_user.id)
        scope = _grafana_scope_for_user(user)
        otp = await api.create_grafana_otp(user["telegram_id"], scope=scope)
        await callback.message.answer(
            _format_grafana_otp_message(scope=scope, otp=otp),
            disable_web_page_preview=True,
        )
    except ApiClientError as exc:
        if _is_grafana_disabled_error(exc):
            await callback.message.answer(_grafana_unavailable_message())
        else:
            await callback.message.answer(_msg_error(exc))
    await callback.answer()


@router.callback_query(F.data == "grafana_otp_admin")
async def grafana_otp_admin(callback: CallbackQuery) -> None:
    try:
        if not settings.grafana_enabled:
            await callback.message.answer(_grafana_unavailable_message())
            await callback.answer()
            return
        user = await ensure_user(callback.from_user.id)
        if not is_admin(user):
            await callback.answer(_msg_warn("Недостаточно прав"))
            return
        scope = _grafana_scope_for_user(user)
        otp = await api.create_grafana_otp(user["telegram_id"], scope=scope)
        await callback.message.answer(
            _format_grafana_otp_message(scope=scope, otp=otp),
            disable_web_page_preview=True,
        )
    except ApiClientError as exc:
        if _is_grafana_disabled_error(exc):
            await callback.message.answer(_grafana_unavailable_message())
        else:
            await callback.message.answer(_msg_error(exc))
    await callback.answer()


@router.callback_query(F.data == "mtproto_open")
async def mtproto_open(callback: CallbackQuery) -> None:
    try:
        await _send_mtproto_access(callback, rotate=False)
        await callback.answer(_msg_ok("Telegram Proxy отправлен"))
    except ApiClientError as exc:
        await callback.message.answer(_msg_error(exc))
        await callback.answer()
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(_msg_error(exc))
        await callback.answer()


@router.callback_query(F.data == "mtproto_rotate")
async def mtproto_rotate(callback: CallbackQuery) -> None:
    try:
        await _send_mtproto_access(callback, rotate=True)
        await callback.answer(_msg_ok("Telegram Proxy обновлен"))
    except ApiClientError as exc:
        await callback.message.answer(_msg_error(exc))
        await callback.answer()
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(_msg_error(exc))
        await callback.answer()


@router.callback_query(F.data == "mtproto_revoke")
async def mtproto_revoke(callback: CallbackQuery) -> None:
    await callback.message.answer(
        _msg_warn(
            "Отозвать постоянный Telegram Proxy-доступ?\n\n"
            "Текущий секрет перестанет работать после применения revoke на Transit."
        ),
        reply_markup=confirm_action_keyboard(
            confirm_callback_data="mtproto_revoke_confirm",
            cancel_callback_data="menu",
            confirm_text="Отозвать Telegram Proxy",
        ),
    )
    await callback.answer()


@router.callback_query(F.data == "mtproto_revoke_confirm")
async def mtproto_revoke_confirm(callback: CallbackQuery) -> None:
    try:
        await api.revoke_mtproto_access(callback.from_user.id)
        await callback.message.answer(_msg_ok("Постоянный Telegram Proxy-доступ отозван."))
        await callback.answer(_msg_ok("Telegram Proxy отозван"))
    except ApiClientError as exc:
        await callback.message.answer(_msg_error(exc))
        await callback.answer()
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(_msg_error(exc))
        await callback.answer()


@router.callback_query(F.data == "admin_grant")
async def admin_grant(callback: CallbackQuery, state: FSMContext) -> None:
    user = await ensure_user(callback.from_user.id)
    if not is_superadmin(user):
        await callback.answer(_msg_warn("Доступно только суперадмину."))
        return
    await state.set_state(AdminFlow.waiting_for_grant_id)
    await callback.message.answer(
        _msg_prompt("Введите Telegram ID пользователя для назначения роли администратора."),
        reply_markup=cancel_only_keyboard(cancel_callback_data="admin_menu"),
    )
    await callback.answer()


@router.callback_query(F.data == "admin_revoke")
async def admin_revoke(callback: CallbackQuery, state: FSMContext) -> None:
    user = await ensure_user(callback.from_user.id)
    if not is_superadmin(user):
        await callback.answer(_msg_warn("Доступно только суперадмину."))
        return
    await state.set_state(AdminFlow.waiting_for_revoke_id)
    await callback.message.answer(
        _msg_prompt("Введите Telegram ID пользователя для снятия роли администратора."),
        reply_markup=cancel_only_keyboard(cancel_callback_data="admin_menu"),
    )
    await callback.answer()


@router.callback_query(F.data == "admin_list")
async def admin_list(callback: CallbackQuery) -> None:
    user = await ensure_user(callback.from_user.id)
    if not is_superadmin(user):
        await callback.answer(_msg_warn("Доступно только суперадмину."))
        return
    try:
        admins = await api.list_users(role="admin", limit=500)
        supers = await api.list_users(role="superadmin", limit=500)
        lines = ["👑 Суперадмины"] + [f"• {user_label(u)}" for u in supers]
        lines += ["", "🛡️ Администраторы"] + [f"• {user_label(u)}" for u in admins]
        await callback.message.answer("\n".join(lines) if (admins or supers) else _msg_info("Список администраторов пуст."))
    except ApiClientError as exc:
        await callback.message.answer(_msg_error(exc))
    await callback.answer()

@router.callback_query(F.data == "admin_users")
async def admin_users(callback: CallbackQuery) -> None:
    actor = await ensure_user(callback.from_user.id)
    if not is_admin(actor):
        await callback.answer(_msg_warn("Недостаточно прав"))
        return
    try:
        now = datetime.now(timezone.utc)
        all_users = await api.list_users(limit=500, include_empty=True, prune_empty=False)
        active_users = await api.list_users(limit=500, include_empty=False, prune_empty=False)
        blocked_users = await api.list_users(
            limit=500,
            blocked_only=True,
            include_empty=True,
            prune_empty=False,
        )
        mtproto_grants = await api.list_mtproto_access()
        mtproto_rows = _build_admin_mtproto_rows(grants=mtproto_grants, users=all_users)

        active_blocked_users: list[dict] = []
        for row in blocked_users:
            until = bot_block_until(row)
            if until is not None and until > now:
                active_blocked_users.append(row)
        await callback.message.answer(
            build_admin_users_report(
                all_users=all_users,
                active_users=active_users,
                blocked_users=active_blocked_users,
                active_mtproto_grants=mtproto_rows,
            )
        )
    except ApiClientError as exc:
        await callback.message.answer(_msg_error(exc))
    await callback.answer()


@router.callback_query(F.data == "admin_mtproto")
async def admin_mtproto(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    actor = await ensure_user(callback.from_user.id)
    if not is_admin(actor):
        await callback.answer(_msg_warn("Недостаточно прав"))
        return
    try:
        all_users = await api.list_users(limit=1000, include_empty=True, prune_empty=False)
        grants = await api.list_mtproto_access()
        rows = _build_admin_mtproto_rows(grants=grants, users=all_users)
        await callback.message.answer(
            build_admin_mtproto_report(grants=rows),
            reply_markup=admin_mtproto_keyboard(),
        )
    except ApiClientError as exc:
        await callback.message.answer(_msg_error(exc))
    await callback.answer()


@router.callback_query(F.data == "admin_mtproto_revoke")
async def admin_mtproto_revoke(callback: CallbackQuery, state: FSMContext) -> None:
    actor = await ensure_user(callback.from_user.id)
    if not is_admin(actor):
        await callback.answer(_msg_warn("Недостаточно прав"))
        return
    await state.clear()
    await state.set_state(AdminFlow.waiting_for_mtproto_revoke_id)
    await callback.message.answer(
        _msg_prompt("Введите Telegram ID пользователя, для которого нужно отозвать только Telegram Proxy-доступ."),
        reply_markup=cancel_only_keyboard(cancel_callback_data="admin_mtproto"),
    )
    await callback.answer()


@router.callback_query(F.data == "admin_user_revoke_access")
async def admin_user_revoke_access(callback: CallbackQuery, state: FSMContext) -> None:
    actor = await ensure_user(callback.from_user.id)
    if not is_admin(actor):
        await callback.answer(_msg_warn("Недостаточно прав"))
        return
    await state.clear()
    await state.set_state(AdminFlow.waiting_for_user_access_revoke_id)
    await state.update_data(revoke_access_target_id=None, revoke_access_target_label=None)
    await callback.message.answer(
        _msg_prompt(
            "Введите Telegram ID пользователя, для которого нужно отозвать все активные устройства и подключения."
        ),
        reply_markup=cancel_only_keyboard(cancel_callback_data="admin_menu"),
    )
    await callback.answer()


@router.callback_query(F.data == "admin_user_block")
async def admin_user_block(callback: CallbackQuery, state: FSMContext) -> None:
    actor = await ensure_user(callback.from_user.id)
    if not is_admin(actor):
        await callback.answer(_msg_warn("Недостаточно прав"))
        return
    await state.clear()
    await state.set_state(AdminFlow.waiting_for_user_block)
    await state.update_data(block_target_id=None, block_target_label=None)
    await callback.message.answer(
        _msg_prompt(
            "Введите: <telegram_id> <hours> [reason]\n"
            f"{BLOCK_HOURS_HINT}\n"
            "Пример: 123456789 72 abuse"
        ),
        reply_markup=cancel_only_keyboard(cancel_callback_data="admin_menu"),
    )
    await callback.answer()


@router.callback_query(F.data == "admin_user_unblock")
async def admin_user_unblock(callback: CallbackQuery, state: FSMContext) -> None:
    actor = await ensure_user(callback.from_user.id)
    if not is_admin(actor):
        await callback.answer(_msg_warn("Недостаточно прав"))
        return
    await state.set_state(AdminFlow.waiting_for_user_unblock)
    await callback.message.answer(
        _msg_prompt("Введите Telegram ID пользователя для снятия блокировки."),
        reply_markup=cancel_only_keyboard(cancel_callback_data="admin_menu"),
    )
    await callback.answer()


@router.message(AdminFlow.waiting_for_user_access_revoke_id)
async def receive_user_access_revoke_id(message: Message, state: FSMContext) -> None:
    try:
        actor = await ensure_user(message.from_user.id)
        if not is_admin(actor):
            await message.answer(_msg_warn("Недостаточно прав."))
            return

        target_id = int((message.text or "").strip())
        target = await api.get_user(target_id)
        if not can_manage_user_access(actor, target):
            await message.answer(_msg_warn("Недостаточно прав для отзыва доступа этой роли."))
            return

        await state.set_state(AdminFlow.waiting_for_user_access_revoke_notify)
        await state.update_data(
            revoke_access_target_id=target_id,
            revoke_access_target_label=user_label(target),
        )
        await message.answer(
            _msg_prompt(
                f"Отозвать все активные устройства и подключения для {user_label(target)}?\n\n"
                "Отправить пользователю уведомление?"
            ),
            reply_markup=admin_user_revoke_notify_keyboard(),
        )
    except Exception as exc:  # noqa: BLE001
        await message.answer(_msg_error(exc))
        await state.clear()


@router.message(AdminFlow.waiting_for_mtproto_revoke_id)
async def receive_mtproto_revoke_id(message: Message, state: FSMContext) -> None:
    try:
        actor = await ensure_user(message.from_user.id)
        if not is_admin(actor):
            await message.answer(_msg_warn("Недостаточно прав."))
            return

        target_id = int((message.text or "").strip())
        target = await api.get_user(target_id)
        if not can_manage_user_access(actor, target):
            await message.answer(_msg_warn("Недостаточно прав для Telegram Proxy-доступа этой роли."))
            return

        await api.revoke_mtproto_access(target_id)
        await message.answer(
            _msg_ok(f"Постоянный Telegram Proxy-доступ отозван для {user_label(target)}."),
            reply_markup=admin_mtproto_keyboard(),
        )
        await state.clear()
    except ApiClientError as exc:
        if exc.status_code == 404:
            await message.answer(_msg_warn("Активный постоянный Telegram Proxy-доступ не найден."))
        else:
            await message.answer(_msg_error(exc))
        await state.clear()
    except Exception as exc:  # noqa: BLE001
        await message.answer(_msg_error(exc))
        await state.clear()


@router.callback_query(F.data.startswith("admin_user_revoke_notify:"))
async def admin_user_revoke_notify(callback: CallbackQuery, state: FSMContext) -> None:
    actor = await ensure_user(callback.from_user.id)
    if not is_admin(actor):
        await callback.answer(_msg_warn("Недостаточно прав"))
        return

    state_data = await state.get_data()
    target_id_raw = state_data.get("revoke_access_target_id")
    target_label = (state_data.get("revoke_access_target_label") or "").strip()
    if target_id_raw is None:
        await state.clear()
        await callback.answer(_msg_warn("Сессия отзыва истекла. Повторите действие."), show_alert=True)
        return

    notify = callback.data.endswith(":yes")
    target_id = int(target_id_raw)
    try:
        target = await api.get_user(target_id)
        if not can_manage_user_access(actor, target):
            await callback.message.answer(_msg_warn("Недостаточно прав для отзыва доступа этой роли."))
            await callback.answer()
            return

        result = await api.revoke_user_access(
            actor_telegram_id=callback.from_user.id,
            target_telegram_id=target_id,
        )
        revoked_connections = int(result.get("revoked_connections") or 0)
        revoked_devices = int(result.get("revoked_devices") or 0)
        revoked_mtproto = bool(result.get("revoked_mtproto_access"))
        await callback.message.answer(
            _msg_ok(
                f"Доступ отозван для {target_label or user_label(target)}.\n"
                f"Подключения: {revoked_connections}\n"
                f"Устройства: {revoked_devices}\n"
                f"Telegram Proxy: {'да' if revoked_mtproto else 'нет'}"
            )
        )
        if notify:
            try:
                await callback.message.bot.send_message(
                    chat_id=target_id,
                    text=_msg_warn(
                        _build_access_revoked_notification_text(revoked_at=datetime.now(timezone.utc))
                    ),
                )
            except (TelegramBadRequest, TelegramForbiddenError):
                await callback.message.answer(
                    _msg_warn("Доступ отозван, но уведомление отправить не удалось.")
                )
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(_msg_error(exc))
    finally:
        await state.clear()
        await callback.answer()


@router.message(AdminFlow.waiting_for_grant_id)
async def receive_admin_grant_id(message: Message, state: FSMContext) -> None:
    try:
        text = (message.text or "").strip()
        telegram_id = int(text)
        await api.get_or_create_user(telegram_id)
        await api.set_user_role(telegram_id, "admin")
        await message.answer(_msg_ok(f"Роль обновлена.\n{telegram_id} теперь администратор."))
    except Exception as exc:  # noqa: BLE001
        await message.answer(_msg_error(exc))
    finally:
        await state.clear()


@router.message(AdminFlow.waiting_for_revoke_id)
async def receive_admin_revoke_id(message: Message, state: FSMContext) -> None:
    try:
        text = (message.text or "").strip()
        telegram_id = int(text)
        if telegram_id in (settings.superadmin_telegram_ids or []):
            await message.answer(_msg_warn("Нельзя снять роль суперадмина."))
            return
        await api.set_user_role(telegram_id, "user")
        await message.answer(_msg_ok(f"Роль обновлена.\n{telegram_id} теперь пользователь."))
    except Exception as exc:  # noqa: BLE001
        await message.answer(_msg_error(exc))
    finally:
        await state.clear()


@router.message(AdminFlow.waiting_for_user_block)
async def receive_user_block(message: Message, state: FSMContext) -> None:
    try:
        actor = await ensure_user(message.from_user.id)
        if not is_admin(actor):
            await message.answer(_msg_warn("Недостаточно прав."))
            return

        state_data = await state.get_data()
        default_target_id_raw = state_data.get("block_target_id")
        default_target_label = (state_data.get("block_target_label") or "").strip()
        default_target_id = int(default_target_id_raw) if default_target_id_raw is not None else None

        try:
            target_id, hours, reason = parse_user_block_request(
                message.text or "",
                default_target_id=default_target_id,
            )
        except ValueError as exc:
            if default_target_id is None:
                await message.answer(
                    _msg_warn(
                        f"{exc}\n"
                        f"{BLOCK_HOURS_HINT}"
                    )
                )
            else:
                await message.answer(
                    _msg_warn(
                        f"{exc}\n"
                        f"Для {default_target_label or default_target_id}: <hours> [reason]\n"
                        f"{BLOCK_HOURS_HINT}"
                    )
                )
            return

        target = await api.get_or_create_user(target_id)
        if not can_manage_block(actor, target):
            await message.answer(_msg_warn("Недостаточно прав для блокировки этой роли."))
            return

        blocked = await api.block_user_bot(target_id, hours=hours, reason=reason, revoke_access=True)
        until = bot_block_until(blocked)
        reason_from_api = (blocked.get("bot_block_reason") or "").strip() or reason
        await message.answer(
            _msg_ok(f"Блокировка применена.\n{user_label(target)}\nДо: {_format_block_until_label(until)}")
        )
        try:
            await message.bot.send_message(
                chat_id=target_id,
                text=_msg_warn(
                    _build_block_notification_text(
                        blocked_at=datetime.now(timezone.utc),
                        hours=hours,
                        until=until,
                        reason=reason_from_api,
                    )
                ),
            )
        except (TelegramBadRequest, TelegramForbiddenError):
            await message.answer(_msg_warn("Пользователь заблокирован, но уведомление отправить не удалось."))
    except Exception as exc:  # noqa: BLE001
        await message.answer(_msg_error(exc))
    finally:
        await state.clear()


@router.message(AdminFlow.waiting_for_user_unblock)
async def receive_user_unblock(message: Message, state: FSMContext) -> None:
    try:
        actor = await ensure_user(message.from_user.id)
        if not is_admin(actor):
            await message.answer(_msg_warn("Недостаточно прав."))
            return

        target_id = int((message.text or "").strip())
        target = await api.get_user(target_id)
        if not can_manage_block(actor, target):
            await message.answer(_msg_warn("Недостаточно прав для снятия блокировки этой роли."))
            return

        await api.unblock_user_bot(target_id)
        await message.answer(_msg_ok(f"Блокировка снята.\n{user_label(target)}"))
        try:
            await message.bot.send_message(
                chat_id=target_id,
                text=_msg_ok(_build_unblock_notification_text(unblocked_at=datetime.now(timezone.utc))),
            )
        except (TelegramBadRequest, TelegramForbiddenError):
            await message.answer(_msg_warn("Блокировка снята, но уведомление отправить не удалось."))
    except Exception as exc:  # noqa: BLE001
        await message.answer(_msg_error(exc))
    finally:
        await state.clear()


@router.callback_query(F.data == "devices")
async def list_devices(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    user = await ensure_user(callback.from_user.id)
    devices = await api.list_devices(user["telegram_id"])
    text = _format_devices_text(devices)
    await callback.message.edit_text(text, reply_markup=devices_keyboard(devices))
    await callback.answer()


@router.callback_query(F.data == "add_device")
async def add_device(callback: CallbackQuery, state: FSMContext) -> None:
    await state.set_state(DeviceFlow.waiting_for_name)
    await callback.message.answer(
        _msg_prompt("Введите имя нового устройства"),
        reply_markup=cancel_only_keyboard(cancel_callback_data="menu"),
    )
    await callback.answer()


@router.message(DeviceFlow.waiting_for_name)
async def receive_device_name(message: Message, state: FSMContext) -> None:
    try:
        name = (message.text or "").strip()
        if name.lower() == "/cancel":
            await message.answer(_msg_warn("Отменено."))
            await _send_main_menu(message)
            return
        if not name:
            await message.answer(_msg_warn("Имя устройства не может быть пустым."))
            return
        user = await ensure_user(message.from_user.id)
        await api.create_device(user["telegram_id"], name)
        devices = await api.list_devices(user["telegram_id"])
        await message.answer(_msg_ok("Устройство добавлено."), reply_markup=devices_keyboard(devices))
    except ApiClientError as exc:
        await message.answer(_msg_error(exc))
    finally:
        await state.clear()


@router.callback_query(F.data.startswith("device:"))
async def device_actions(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    _, device_id = callback.data.split(":", 1)
    text, keyboard = await render_device_page(device_id)
    await callback.message.edit_text(text, reply_markup=keyboard)
    await callback.answer()


@router.callback_query(F.data.startswith("deldevask:"))
async def confirm_delete_device(callback: CallbackQuery) -> None:
    _, device_id = callback.data.split(":", 1)
    try:
        user = await ensure_user(callback.from_user.id)
        devices = await api.list_devices(user["telegram_id"])
        device = next((row for row in devices if str(row.get("id")) == device_id), None)
        if device is None:
            await callback.answer(_msg_warn("Устройство не найдено"), show_alert=True)
            return
        await callback.message.edit_text(
            _format_device_delete_confirmation(device_name=str(device.get("name") or "Без имени"), device_id=device_id),
            reply_markup=confirm_action_keyboard(
                confirm_callback_data=f"deldev:{device_id}",
                cancel_callback_data="devices",
                confirm_text="Удалить устройство",
            ),
        )
    except ApiClientError as exc:
        await callback.message.answer(_msg_error(exc))
    await callback.answer()


@router.callback_query(F.data.startswith("deldev:"))
async def delete_device(callback: CallbackQuery) -> None:
    _, device_id = callback.data.split(":", 1)
    try:
        await api.delete_device(device_id)
        await _cleanup_related_messages(callback, device_id=device_id)
        user = await ensure_user(callback.from_user.id)
        devices = await api.list_devices(user["telegram_id"])
        text = _format_devices_text(devices)
        await callback.message.edit_text(text, reply_markup=devices_keyboard(devices))
        await callback.message.answer(_msg_ok("Устройство удалено. Все связанные подключения отозваны."))
    except ApiClientError as exc:
        await callback.message.answer(_msg_error(exc))
    await callback.answer()


def _profile(spec: str) -> tuple[ConnectionProtocol, ConnectionMode, ConnectionVariant]:
    if spec == "v1":
        return ConnectionProtocol.VLESS_REALITY, ConnectionMode.DIRECT, ConnectionVariant.V1
    if spec == "v1grpc":
        return ConnectionProtocol.VLESS_GRPC_TLS, ConnectionMode.DIRECT, ConnectionVariant.V1
    if spec == "v1ws":
        return ConnectionProtocol.VLESS_WS_TLS, ConnectionMode.DIRECT, ConnectionVariant.V1
    if spec == "v2":
        return ConnectionProtocol.VLESS_REALITY, ConnectionMode.CHAIN, ConnectionVariant.V2
    if spec == "v3":
        return ConnectionProtocol.HYSTERIA2, ConnectionMode.DIRECT, ConnectionVariant.V3
    if spec == "v4":
        return ConnectionProtocol.HYSTERIA2, ConnectionMode.CHAIN, ConnectionVariant.V4
    if spec == "v5":
        return ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS, ConnectionMode.DIRECT, ConnectionVariant.V5
    if spec == "v6":
        return ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS, ConnectionMode.CHAIN, ConnectionVariant.V6
    if spec == "v7":
        return ConnectionProtocol.WIREGUARD_WSTUNNEL, ConnectionMode.DIRECT, ConnectionVariant.V7
    raise ValueError("unknown profile")


@router.callback_query(F.data.startswith("new:"))
async def new_connection(callback: CallbackQuery) -> None:
    _, spec, device_id = callback.data.split(":", 2)

    try:
        protocol, _, _ = _profile(spec)
        if protocol == ConnectionProtocol.VLESS_REALITY:
            await callback.message.edit_text(
                "🌐 Выберите провайдера для фильтра SNI:",
                reply_markup=provider_keyboard_with_cancel(
                    "new",
                    f"{spec}:{device_id}",
                    cancel_callback_data=f"device:{device_id}",
                ),
            )
            await callback.answer()
            return

        user = await ensure_user(callback.from_user.id)
        protocol, mode, variant = _profile(spec)
        connection, revision = await api.create_connection_and_revision(
            user["telegram_id"],
            device_id,
            protocol,
            mode,
            variant,
            None,
            custom_overrides_json=None,
        )
        text, keyboard = await render_device_page(device_id)
        await callback.message.edit_text(text, reply_markup=keyboard)
        await _send_client_config(callback, revision, context="created")
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(_msg_error(exc))

    await callback.answer()


@router.callback_query(F.data.startswith("vlessnew:"))
async def vless_new(callback: CallbackQuery) -> None:
    # vlessnew:<spec>:<device_id> where spec is "v1" (direct) or "v2" (chain)
    _, spec, device_id = callback.data.split(":", 2)
    if spec not in {"v1", "v2"}:
        await callback.message.answer(_msg_error("Неизвестный профиль VLESS."))
        await callback.answer()
        return

    if spec == "v2":
        # Chain profile supports only Reality transport in current architecture.
        await callback.message.edit_text(
            "🛡️ V2-VLESS-Reality-Chain\n\nReality включен автоматически.\n\nВыберите провайдера для фильтра SNI:",
            reply_markup=provider_keyboard_with_cancel(
                "new",
                f"{spec}:{device_id}",
                cancel_callback_data=f"device:{device_id}",
            ),
        )
        await callback.answer()
        return

    await callback.message.edit_text(
        "🔌 V1-VLESS Direct\n\nВыберите транспорт подключения:",
        reply_markup=vless_transport_keyboard(spec=spec, device_id=device_id),
    )
    await callback.answer()


@router.callback_query(F.data.startswith("feedback_block:"))
async def feedback_block(callback: CallbackQuery, state: FSMContext) -> None:
    actor = await ensure_user(callback.from_user.id)
    if not is_admin(actor):
        await callback.answer(_msg_warn("Недостаточно прав"))
        return
    try:
        _, raw_target_id = callback.data.split(":", 1)
        target_id = int(raw_target_id)
        target = await api.get_or_create_user(target_id)
        if not can_manage_block(actor, target):
            await callback.answer(_msg_warn("Недостаточно прав для блокировки этой роли."), show_alert=True)
            return
        await state.clear()
        await state.set_state(AdminFlow.waiting_for_user_block)
        await state.update_data(
            block_target_id=target_id,
            block_target_label=user_label(target),
        )
        await callback.message.answer(
            _msg_prompt(
                f"Блокировка автора обращения: {user_label(target)}\n"
                f"Введите: <hours> [reason]\n"
                f"{BLOCK_HOURS_HINT}\n"
                "Пример: 72 abuse"
            ),
            reply_markup=cancel_only_keyboard(cancel_callback_data="admin_menu"),
        )
        await callback.answer()
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(_msg_error(exc))
        await callback.answer()


@router.callback_query(F.data.startswith("vlesstrans:"))
async def vless_transport(callback: CallbackQuery) -> None:
    # vlesstrans:<spec>:<device_id>:<transport>
    _, spec, device_id, transport = callback.data.split(":", 3)
    transport = (transport or "").strip().lower()
    if spec not in {"v1", "v2"}:
        await callback.message.answer(_msg_error("Неизвестный профиль VLESS."))
        await callback.answer()
        return

    try:
        # Chain profile supports only Reality transport.
        if spec == "v2":
            transport = "reality"

        if transport == "reality":
            await callback.message.edit_text(
                "🌐 Выберите провайдера для фильтра SNI:",
                reply_markup=provider_keyboard_with_cancel(
                    "new",
                    f"{spec}:{device_id}",
                    cancel_callback_data=f"device:{device_id}",
                ),
            )
            await callback.answer()
            return

        if transport not in {"grpc", "tls"}:
            raise ValueError("unknown transport")

        if spec != "v1":
            raise ValueError("TLS compatibility transports are available only for V1 Direct")

        user = await ensure_user(callback.from_user.id)
        profile_spec = "v1grpc" if transport == "grpc" else "v1ws"
        protocol, mode, variant = _profile(profile_spec)
        connection, revision = await api.create_connection_and_revision(
            user["telegram_id"],
            device_id,
            protocol,
            mode,
            variant,
            None,
            custom_overrides_json=None,
        )
        text, keyboard = await render_device_page(device_id)
        await callback.message.edit_text(text, reply_markup=keyboard)
        await _send_client_config(callback, revision, context="created")
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(_msg_error(exc))
    finally:
        await callback.answer()


@router.callback_query(F.data.startswith("sni:"))
async def new_vless_with_sni(callback: CallbackQuery) -> None:
    _, spec, device_id, sni_id_raw = callback.data.split(":", 3)

    try:
        user = await ensure_user(callback.from_user.id)
        protocol, mode, variant = _profile(spec)
        connection, revision = await api.create_connection_and_revision(
            user["telegram_id"],
            device_id,
            protocol,
            mode,
            variant,
            int(sni_id_raw),
        )
        text, keyboard = await render_device_page(device_id)
        await callback.message.edit_text(text, reply_markup=keyboard)
        await _send_client_config(callback, revision, context="created")
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(_msg_error(exc))

    await callback.answer()


def _clip_note(note: str | None, *, max_len: int = 80) -> str:
    if not note:
        return ""
    s = " ".join(note.split()).strip()
    if len(s) <= max_len:
        return s
    return s[: max_len - 3].rstrip() + "..."


async def _render_sni_picker_new(*, spec: str, device_id: str, provider: str, page: int) -> tuple[str, object]:
    sni_rows = [
        row
        for row in await api.list_sni_filtered(
            provider=None if provider == "all" else provider,
            purpose="vless_reality",
        )
        if row["enabled"]
    ]
    if not sni_rows:
        return (
            _msg_warn("Нет доступных SNI в этой категории.\nВыберите другой провайдер:"),
            provider_keyboard_with_cancel("new", f"{spec}:{device_id}", cancel_callback_data=f"device:{device_id}"),
        )

    total = len(sni_rows)
    page_count = max(1, (total + SNI_PAGE_SIZE - 1) // SNI_PAGE_SIZE)
    page = max(0, min(page, page_count - 1))
    start = page * SNI_PAGE_SIZE
    end = start + SNI_PAGE_SIZE
    page_rows = sni_rows[start:end]

    text = (
        "🌐 Выбор SNI для VLESS/Reality\n\n"
        f"Провайдер: {_provider_label(provider)} | Страница: {page+1}/{page_count} | Всего: {total}\n\n"
        "Выберите домен из списка:"
    )
    keyboard = sni_page_keyboard_new(
        spec=spec,
        device_id=device_id,
        provider=provider,
        page=page,
        page_count=page_count,
        sni_rows_page=page_rows,
    )
    return text, keyboard


async def _render_sni_picker_issue(*, connection_id: str, provider: str, page: int) -> tuple[str, object]:
    sni_rows = [
        row
        for row in await api.list_sni_filtered(
            provider=None if provider == "all" else provider,
            purpose="vless_reality",
        )
        if row["enabled"]
    ]
    if not sni_rows:
        return (
            _msg_warn("Нет доступных SNI в этой категории.\nВыберите другой провайдер:"),
            provider_keyboard_with_cancel("issue", connection_id, cancel_callback_data=f"revs:{connection_id}"),
        )

    total = len(sni_rows)
    page_count = max(1, (total + SNI_PAGE_SIZE - 1) // SNI_PAGE_SIZE)
    page = max(0, min(page, page_count - 1))
    start = page * SNI_PAGE_SIZE
    end = start + SNI_PAGE_SIZE
    page_rows = sni_rows[start:end]

    text = (
        "🧩 Выбор SNI для новой ревизии\n\n"
        f"Провайдер: {_provider_label(provider)} | Страница: {page+1}/{page_count} | Всего: {total}\n\n"
        "Выберите домен из списка:"
    )
    keyboard = sni_page_keyboard_issue(
        connection_id=connection_id,
        provider=provider,
        page=page,
        page_count=page_count,
        sni_rows_page=page_rows,
    )
    return text, keyboard


async def _render_sni_catalog(
    *,
    provider: str,
    page: int,
    query: str,
) -> tuple[str, object, list[dict], int, int]:
    rows = [
        row
        for row in await api.list_sni_filtered(
            provider=None if provider == "all" else provider,
            purpose=None,
        )
        if row["enabled"]
    ]
    q = query.strip().lower()
    if q:
        rows = [
            r
            for r in rows
            if q in (r.get("fqdn") or "").lower() or q in (r.get("note") or "").lower()
        ]

    total = len(rows)
    page_size = 20
    page_count = max(1, (total + page_size - 1) // page_size)
    page = max(0, min(page, page_count - 1))
    start = page * page_size
    end = start + page_size
    page_rows = rows[start:end]

    header = f"📚 Каталог SNI (провайдер: {_provider_label(provider)}, страница: {page+1}/{page_count}, всего: {total})"
    if q:
        header += f"\nПоиск: {query.strip()}"
    lines: list[str] = [header]

    if total == 0:
        lines.append("Ничего не найдено.")
    else:
        for idx, row in enumerate(page_rows, start=1):
            note = _clip_note(row.get("note"))
            fqdn = row.get("fqdn") or ""
            if note:
                lines.append(f"{idx}. {fqdn} | {note}")
            else:
                lines.append(f"{idx}. {fqdn}")

    lines.append("")
    lines.append("✍️ Введите номер из списка, чтобы выбрать SNI.")
    lines.append("🔎 Или введите часть домена для поиска (например: splitter, vk.com).")

    text = "\n".join(lines)
    keyboard = sni_catalog_pick_keyboard(
        provider=provider,
        page=page,
        page_count=page_count,
        has_query=bool(q),
    )
    return text, keyboard, page_rows, page, page_count


@router.callback_query(F.data.startswith("prov:"))
async def pick_provider(callback: CallbackQuery, state: FSMContext) -> None:
    # Format: prov:<context>:<target_id...>:<provider>
    # target_id may itself contain ":" (e.g. "v1:<device_id>") so we can't use a fixed maxsplit.
    parts = callback.data.split(":")
    if len(parts) < 4:
        await callback.message.answer(_msg_error("Некорректные данные кнопки."))
        await callback.answer()
        return

    context = parts[1]
    provider = parts[-1]
    target_id = ":".join(parts[2:-1])

    try:
        if context == "new":
            if ":" not in target_id:
                raise ValueError("invalid target id")
            spec, device_id = target_id.split(":", 1)
            text, keyboard = await _render_sni_picker_new(spec=spec, device_id=device_id, provider=provider, page=0)
            await callback.message.edit_text(text, reply_markup=keyboard)
        elif context == "issue":
            connection_id = target_id
            text, keyboard = await _render_sni_picker_issue(connection_id=connection_id, provider=provider, page=0)
            await callback.message.edit_text(text, reply_markup=keyboard)
        elif context == "catalog":
            await state.set_state(SniCatalogFlow.waiting_for_input)
            query = ""
            text, keyboard, page_rows, normalized_page, _ = await _render_sni_catalog(
                provider=provider,
                page=0,
                query=query,
            )
            await state.update_data(
                provider=provider,
                page=normalized_page,
                query=query,
                page_rows=[{"id": r["id"], "fqdn": r.get("fqdn"), "note": r.get("note")} for r in page_rows],
                catalog_msg_id=callback.message.message_id,
            )
            await callback.message.edit_text(text, reply_markup=keyboard)
        else:
            await callback.message.answer(_msg_error("Неизвестный контекст выбора провайдера."))
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(_msg_error(exc))

    await callback.answer()


@router.callback_query(F.data.startswith("snipage:"))
async def sni_page(callback: CallbackQuery) -> None:
    parts = callback.data.split(":")
    if len(parts) < 2:
        await callback.answer()
        return

    context = parts[1]
    try:
        if context == "new":
            # snipage:new:<spec>:<device_id>:<provider>:<page>
            if len(parts) != 6:
                raise ValueError("invalid snipage payload")
            spec = parts[2]
            device_id = parts[3]
            provider = parts[4]
            page = int(parts[5])
            text, keyboard = await _render_sni_picker_new(spec=spec, device_id=device_id, provider=provider, page=page)
            await callback.message.edit_text(text, reply_markup=keyboard)
        elif context == "issue":
            # snipage:issue:<connection_id>:<provider>:<page>
            if len(parts) != 5:
                raise ValueError("invalid snipage payload")
            connection_id = parts[2]
            provider = parts[3]
            page = int(parts[4])
            text, keyboard = await _render_sni_picker_issue(connection_id=connection_id, provider=provider, page=page)
            await callback.message.edit_text(text, reply_markup=keyboard)
        else:
            raise ValueError("unknown snipage context")
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(_msg_error(exc))
    finally:
        await callback.answer()


@router.callback_query(F.data == "sni_catalog")
async def sni_catalog(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    user = await ensure_user(callback.from_user.id)
    devices = await api.list_devices(user["telegram_id"])
    await callback.message.edit_text(
        _format_devices_text(devices),
        reply_markup=devices_keyboard(devices),
    )
    await callback.answer(
        _msg_info("Каталог SNI доступен только при создании Reality-подключения."),
        show_alert=True,
    )


@router.callback_query(F.data == "catreset")
async def sni_catalog_reset(callback: CallbackQuery, state: FSMContext) -> None:
    data = await state.get_data()
    provider = (data.get("provider") or "all").strip()
    try:
        await state.set_state(SniCatalogFlow.waiting_for_input)
        text, keyboard, page_rows, normalized_page, _ = await _render_sni_catalog(provider=provider, page=0, query="")
        await state.update_data(
            provider=provider,
            page=normalized_page,
            query="",
            page_rows=[{"id": r["id"], "fqdn": r.get("fqdn"), "note": r.get("note")} for r in page_rows],
            catalog_msg_id=callback.message.message_id,
        )
        await callback.message.edit_text(text, reply_markup=keyboard)
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(_msg_error(exc))
    await callback.answer()


@router.callback_query(F.data.startswith("cat:"))
async def sni_catalog_page(callback: CallbackQuery, state: FSMContext) -> None:
    _, provider, page_raw = callback.data.split(":", 2)
    try:
        page = int(page_raw)
        await state.set_state(SniCatalogFlow.waiting_for_input)
        data = await state.get_data()
        query = (data.get("query") or "").strip()
        text, keyboard, page_rows, normalized_page, _ = await _render_sni_catalog(
            provider=provider,
            page=page,
            query=query,
        )
        await state.update_data(
            provider=provider,
            page=normalized_page,
            query=query,
            page_rows=[{"id": r["id"], "fqdn": r.get("fqdn"), "note": r.get("note")} for r in page_rows],
            catalog_msg_id=callback.message.message_id,
        )
        await callback.message.edit_text(text, reply_markup=keyboard)
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(_msg_error(exc))
    await callback.answer()


@router.message(SniCatalogFlow.waiting_for_input)
async def sni_catalog_input(message: Message, state: FSMContext) -> None:
    text_in = (message.text or "").strip()
    if not text_in:
        return

    data = await state.get_data()
    provider = (data.get("provider") or "all").strip()
    page = int(data.get("page") or 0)
    query = (data.get("query") or "").strip()
    page_rows: list[dict] = data.get("page_rows") or []

    async def _edit_or_send(text: str, keyboard: object) -> None:
        msg_id = data.get("catalog_msg_id")
        if msg_id:
            try:
                await message.bot.edit_message_text(
                    chat_id=message.chat.id,
                    message_id=int(msg_id),
                    text=text,
                    reply_markup=keyboard,
                )
                return
            except Exception:
                pass
        sent = await message.answer(text, reply_markup=keyboard)
        await state.update_data(catalog_msg_id=sent.message_id)

    if text_in.isdigit():
        n = int(text_in)
        if n < 1 or n > len(page_rows):
            await message.answer(_msg_warn(f"Неверный номер. Введите число от 1 до {len(page_rows)}."))
            return

        chosen = page_rows[n - 1]
        sni_id = int(chosen["id"])
        fqdn = (chosen.get("fqdn") or "").strip()
        note = _clip_note(chosen.get("note"))
        out = f"✅ Выбран SNI\n\n{fqdn or f'id={sni_id}'}"
        if note:
            out += f"\n\n{note}"

        await _edit_or_send(out, sni_catalog_action_keyboard(sni_id=sni_id, provider=provider, page=page))
        return

    # Treat as search query (fqdn substring).
    query = text_in
    page = 0
    try:
        rendered, keyboard, new_page_rows, normalized_page, _ = await _render_sni_catalog(
            provider=provider,
            page=page,
            query=query,
        )
        await state.update_data(
            provider=provider,
            page=normalized_page,
            query=query,
            page_rows=[{"id": r["id"], "fqdn": r.get("fqdn"), "note": r.get("note")} for r in new_page_rows],
        )
        await _edit_or_send(rendered, keyboard)
    except Exception as exc:  # noqa: BLE001
        await message.answer(_msg_error(exc))


async def _render_sni_catalog_actions(
    *,
    state: FSMContext,
    sni_id: int,
    provider: str,
    page: int,
) -> tuple[str, object]:
    # Try state cache first (current page rows).
    data = await state.get_data()
    cached: list[dict] = data.get("page_rows") or []
    chosen = next((r for r in cached if int(r.get("id") or 0) == sni_id), None)

    if chosen is None:
        # Fallback: fetch from API and find by id.
        rows = await api.list_sni_filtered(provider=None if provider == "all" else provider, purpose=None)
        chosen = next((r for r in rows if int(r.get("id") or 0) == sni_id), None)

    fqdn = (chosen.get("fqdn") if chosen else None) or f"id={sni_id}"
    note = _clip_note((chosen or {}).get("note"))
    out = f"✅ Выбран SNI\n\n{fqdn}"
    if note:
        out += f"\n\n{note}"
    return out, sni_catalog_action_keyboard(sni_id=sni_id, provider=provider, page=page)


@router.callback_query(F.data.startswith("catsel:"))
async def sni_catalog_select(callback: CallbackQuery, state: FSMContext) -> None:
    # catsel:<sni_id>:<provider>:<page>
    _, sni_id_raw, provider, page_raw = callback.data.split(":", 3)
    try:
        sni_id = int(sni_id_raw)
        page = int(page_raw)
        await state.set_state(SniCatalogFlow.waiting_for_input)
        await state.update_data(provider=provider, page=page, catalog_msg_id=callback.message.message_id)
        text, keyboard = await _render_sni_catalog_actions(state=state, sni_id=sni_id, provider=provider, page=page)
        await callback.message.edit_text(text, reply_markup=keyboard)
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(_msg_error(exc))
    await callback.answer()


@router.callback_query(F.data.startswith("catnewpick:"))
async def sni_catalog_new_pick_device(callback: CallbackQuery) -> None:
    # catnewpick:<v1|v2>:<sni_id>:<provider>:<page>
    parts = callback.data.split(":")
    if len(parts) != 5:
        await callback.message.answer(_msg_error("Некорректные данные кнопки."))
        await callback.answer()
        return
    _, spec, sni_id_raw, provider, page_raw = parts
    try:
        sni_id = int(sni_id_raw)
        page = int(page_raw)
        user = await ensure_user(callback.from_user.id)
        devices = await api.list_devices(user["telegram_id"])
        if not devices:
            await callback.message.edit_text(
                _msg_info("Нет устройств. Сначала добавьте устройство."),
                reply_markup=main_menu_keyboard(),
            )
            await callback.answer()
            return
        await callback.message.edit_text(
            "📱 Выберите устройство для нового VLESS-подключения:",
            reply_markup=sni_catalog_device_pick_keyboard(
                spec=spec,
                sni_id=sni_id,
                devices=devices,
                provider=provider,
                page=page,
            ),
        )
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(_msg_error(exc))
    await callback.answer()


@router.callback_query(F.data.startswith("catnew:"))
async def sni_catalog_new_connection(callback: CallbackQuery, state: FSMContext) -> None:
    # catnew:<v1|v2>:<device_id>:<sni_id>
    _, spec, device_id, sni_id_raw = callback.data.split(":", 3)
    try:
        user = await ensure_user(callback.from_user.id)
        protocol, mode, variant = _profile(spec)
        connection, revision = await api.create_connection_and_revision(
            user["telegram_id"],
            device_id,
            protocol,
            mode,
            variant,
            int(sni_id_raw),
        )
        await state.clear()
        text, keyboard = await render_device_page(device_id)
        await callback.message.edit_text(text, reply_markup=keyboard)
        await _send_client_config(callback, revision, context="created")
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(_msg_error(exc))
    await callback.answer()


@router.callback_query(F.data.startswith("catissuepick:"))
async def sni_catalog_issue_pick_connection(callback: CallbackQuery) -> None:
    # catissuepick:<sni_id>:<provider>:<page>
    _, sni_id_raw, provider, page_raw = callback.data.split(":", 3)
    try:
        sni_id = int(sni_id_raw)
        page = int(page_raw)
        user = await ensure_user(callback.from_user.id)
        devices = await api.list_devices(user["telegram_id"])

        vless_connections: list[dict] = []
        for dev in devices:
            for conn in await api.list_connections(dev["id"]):
                if conn.get("protocol") != ConnectionProtocol.VLESS_REALITY.value:
                    continue
                label = (
                    str(conn.get("alias") or "").strip()
                    or f"{dev['name']} | {_connection_family_name(conn.get('protocol', ''), conn.get('mode', ''))}"
                )
                vless_connections.append({"id": conn["id"], "label": label})

        if not vless_connections:
            await callback.message.edit_text(
                _msg_info("Нет VLESS-подключений, для которых можно выпустить ревизию."),
                reply_markup=sni_catalog_action_keyboard(sni_id=sni_id, provider=provider, page=page),
            )
            await callback.answer()
            return

        await callback.message.edit_text(
            "🧩 Выберите VLESS-подключение для новой ревизии\n\nSNI будет применен к новой ревизии.",
            reply_markup=sni_catalog_connection_pick_keyboard(
                sni_id=sni_id,
                vless_connections=vless_connections,
                provider=provider,
                page=page,
            ),
        )
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(_msg_error(exc))
    await callback.answer()


@router.callback_query(F.data.startswith("catissue:"))
async def sni_catalog_issue_revision(callback: CallbackQuery, state: FSMContext) -> None:
    # catissue:<connection_id>:<sni_id>
    _, connection_id, sni_id_raw = callback.data.split(":", 2)
    try:
        revision = await api.issue_revision(connection_id, sni_id=int(sni_id_raw))
        await state.clear()
        text, keyboard = await render_revisions_page(revision["connection_id"])
        await callback.message.edit_text(text, reply_markup=keyboard)
        await _cleanup_related_messages(callback, connection_id=revision["connection_id"])
        await _send_client_config(callback, revision, context="issued")
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(_msg_error(exc))
    await callback.answer()


@router.callback_query(F.data.startswith("revs:"))
async def list_revisions(callback: CallbackQuery) -> None:
    _, connection_id = callback.data.split(":", 1)
    try:
        text, keyboard = await render_revisions_page(connection_id)
        edited = await _safe_edit_text(callback.message, text, reply_markup=keyboard)
        await callback.answer(_msg_ok("Список обновлен") if edited else _msg_info("Изменений нет"))
    except ApiClientError as exc:
        await callback.message.answer(_msg_error(exc))
        await callback.answer()
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(_msg_error(exc))
        await callback.answer()


@router.callback_query(F.data.startswith("showcur:"))
async def show_current_revision_config(callback: CallbackQuery) -> None:
    _, connection_id = callback.data.split(":", 1)
    try:
        revisions = await api.list_revisions(connection_id)
        current = _current_revision_from_list(revisions)
        if current is None:
            await callback.answer(_msg_warn("Нет активной ревизии"), show_alert=True)
            return
        await _cleanup_related_messages(callback, connection_id=connection_id)
        await _send_client_config(callback, current, context="current")
        await callback.answer(_msg_ok("Конфиг отправлен в чат"))
    except ApiClientError as exc:
        await callback.message.answer(_msg_error(exc))
        await callback.answer()
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(_msg_error(exc))
        await callback.answer()


@router.callback_query(F.data.startswith("issuepick:"))
async def issue_pick_sni(callback: CallbackQuery) -> None:
    _, connection_id = callback.data.split(":", 1)
    await callback.message.edit_text(
        "🌐 Выберите провайдера (для фильтра SNI):",
        reply_markup=provider_keyboard_with_cancel("issue", connection_id, cancel_callback_data=f"revs:{connection_id}"),
    )
    await callback.answer()


@router.callback_query(F.data.startswith("issueplain:"))
async def issue_revision(callback: CallbackQuery) -> None:
    _, connection_id = callback.data.split(":", 1)
    try:
        revision = await api.issue_revision(connection_id)
        text, keyboard = await render_revisions_page(revision["connection_id"])
        await _safe_edit_text(callback.message, text, reply_markup=keyboard)
        await _cleanup_related_messages(callback, connection_id=revision["connection_id"])
        await _send_client_config(callback, revision, context="issued")
    except ApiClientError as exc:
        await callback.message.answer(_msg_error(exc))
    await callback.answer()


@router.callback_query(F.data.startswith("activate:"))
async def activate_revision(callback: CallbackQuery) -> None:
    _, revision_id = callback.data.split(":", 1)
    try:
        revision = await api.activate_revision(revision_id)
        text, keyboard = await render_revisions_page(revision["connection_id"])
        await _safe_edit_text(callback.message, text, reply_markup=keyboard)
        await callback.answer(_msg_ok("Ревизия активирована"))
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(_msg_error(exc))
        await callback.answer()


@router.callback_query(F.data.startswith("revokeask:"))
async def confirm_revoke_revision(callback: CallbackQuery) -> None:
    _, revision_id = callback.data.split(":", 1)
    try:
        revision = await api.get_revision(revision_id)
        connection = await api.get_connection(revision["connection_id"])
        await callback.message.edit_text(
            _format_revision_delete_confirmation(connection, revision),
            reply_markup=confirm_action_keyboard(
                confirm_callback_data=f"revoke:{revision_id}",
                cancel_callback_data=f"revs:{revision['connection_id']}",
                confirm_text="Удалить ревизию",
            ),
        )
    except ApiClientError as exc:
        await callback.message.answer(_msg_error(exc))
    await callback.answer()


@router.callback_query(F.data.startswith("revoke:"))
async def revoke_revision(callback: CallbackQuery) -> None:
    _, revision_id = callback.data.split(":", 1)
    try:
        revision = await api.revoke_revision(revision_id)
        await _cleanup_related_messages(callback, revision_id=revision_id)
        text, keyboard = await render_revisions_page(revision["connection_id"])
        await _safe_edit_text(callback.message, text, reply_markup=keyboard)
        await callback.answer(_msg_ok("Ревизия удалена"))
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(_msg_error(exc))
        await callback.answer()


@router.callback_query(F.data.startswith("issuesni:"))
async def issue_revision_with_sni(callback: CallbackQuery) -> None:
    _, connection_id, sni_id_raw = callback.data.split(":", 2)
    try:
        revision = await api.issue_revision(connection_id, sni_id=int(sni_id_raw))
        text, keyboard = await render_revisions_page(revision["connection_id"])
        await _safe_edit_text(callback.message, text, reply_markup=keyboard)
        await _cleanup_related_messages(callback, connection_id=revision["connection_id"])
        await _send_client_config(callback, revision, context="issued")
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(_msg_error(exc))

    await callback.answer()


@router.callback_query(F.data.startswith("delconnask:"))
async def confirm_delete_connection(callback: CallbackQuery) -> None:
    _, connection_id = callback.data.split(":", 1)
    try:
        conn = await api.get_connection(connection_id)
        await callback.message.edit_text(
            _format_connection_delete_confirmation(conn),
            reply_markup=confirm_action_keyboard(
                confirm_callback_data=f"delconn:{connection_id}",
                cancel_callback_data=f"device:{conn['device_id']}",
                confirm_text="Удалить подключение",
            ),
        )
    except ApiClientError as exc:
        await callback.message.answer(_msg_error(exc))
    await callback.answer()


@router.callback_query(F.data.startswith("delconn:"))
async def delete_connection(callback: CallbackQuery) -> None:
    _, connection_id = callback.data.split(":", 1)
    try:
        # Fetch device_id for UI refresh before deleting.
        conn = await api.get_connection(connection_id)
        device_id = conn["device_id"]
        await api.delete_connection(connection_id)
        await _cleanup_related_messages(callback, connection_id=connection_id)
        text, keyboard = await render_device_page(device_id)
        await callback.message.edit_text(text, reply_markup=keyboard)
        await callback.message.answer(_msg_ok("Подключение удалено (доступ отозван)."))
    except ApiClientError as exc:
        await callback.message.answer(_msg_error(exc))
    await callback.answer()


def run() -> None:
    configure_logging(settings.log_level)
    if not settings.bot_token:
        raise RuntimeError("BOT_TOKEN is required")
    if not settings.bot_api_token:
        raise RuntimeError("BOT_API_TOKEN is required")
    if not settings.bot_api_base_url:
        raise RuntimeError("BOT_API_BASE_URL is required")
    maybe_start_bot_metrics_server(
        enabled=bool(settings.bot_metrics_enabled),
        host=str(settings.bot_metrics_host),
        port=int(settings.bot_metrics_port),
    )

    mode = (settings.bot_mode or "polling").strip().lower()
    if mode == "webhook":
        _run_webhook()
    elif mode == "polling":
        asyncio.run(_run_polling())
    else:
        raise RuntimeError(f"Unsupported BOT_MODE={settings.bot_mode!r} (expected 'polling' or 'webhook')")


async def _run_polling() -> None:
    bot = Bot(token=settings.bot_token)
    dp = Dispatcher()
    metrics_mw = BotMetricsMiddleware()
    access_mw = BotAccessMiddleware()
    dp.message.middleware(metrics_mw)
    dp.callback_query.middleware(metrics_mw)
    dp.message.middleware(access_mw)
    dp.callback_query.middleware(access_mw)
    dp.include_router(router)

    # Ensure webhook is disabled; otherwise Telegram rejects getUpdates.
    await delete_webhook_with_retry(bot, drop_pending_updates=True)
    try:
        await dp.start_polling(bot)
    finally:
        await api.close()
        await bot.session.close()


def _run_webhook() -> None:
    bot = Bot(token=settings.bot_token)
    dp = Dispatcher()
    metrics_mw = BotMetricsMiddleware()
    access_mw = BotAccessMiddleware()
    dp.message.middleware(metrics_mw)
    dp.callback_query.middleware(metrics_mw)
    dp.message.middleware(access_mw)
    dp.callback_query.middleware(access_mw)
    dp.include_router(router)

    path = settings.bot_webhook_path or "/"
    if not path.startswith("/"):
        path = "/" + path
    secret_token = settings.bot_webhook_secret_token or None

    public_url = settings.bot_webhook_public_url.strip()
    if not public_url:
        base = settings.bot_webhook_public_base_url.strip()
        if not base:
            raise RuntimeError("BOT_WEBHOOK_PUBLIC_URL or BOT_WEBHOOK_PUBLIC_BASE_URL is required for webhook mode")
        public_url = base.rstrip("/") + path

    tls_cert = Path(settings.bot_webhook_tls_cert)
    tls_key = Path(settings.bot_webhook_tls_key)
    if not tls_cert.exists() or not tls_key.exists():
        raise RuntimeError(
            "Webhook TLS files are missing. "
            f"Expected cert={tls_cert} key={tls_key} (configure BOT_WEBHOOK_TLS_CERT/BOT_WEBHOOK_TLS_KEY)"
        )

    app = web.Application()
    SimpleRequestHandler(dispatcher=dp, bot=bot, secret_token=secret_token).register(app, path=path)
    setup_application(app, dp, bot=bot)

    async def on_startup(_: web.Application) -> None:
        cert_file = FSInputFile(str(tls_cert)) if settings.bot_webhook_upload_cert else None
        await bot.set_webhook(
            url=public_url,
            secret_token=secret_token,
            certificate=cert_file,
            drop_pending_updates=True,
        )

    async def on_shutdown(_: web.Application) -> None:
        await bot.delete_webhook(drop_pending_updates=False)
        await api.close()
        await bot.session.close()

    app.on_startup.append(on_startup)
    app.on_shutdown.append(on_shutdown)

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile=str(tls_cert), keyfile=str(tls_key))

    web.run_app(
        app,
        host=settings.bot_webhook_listen_host,
        port=settings.bot_webhook_listen_port,
        ssl_context=ssl_context,
        access_log=None,
    )


if __name__ == "__main__":
    run()
