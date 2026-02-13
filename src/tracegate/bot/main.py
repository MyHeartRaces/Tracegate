from __future__ import annotations

import asyncio
import io
import ssl
from datetime import datetime, timezone
from pathlib import Path

from aiogram import BaseMiddleware, Bot, Dispatcher, F, Router
from aiogram.exceptions import TelegramBadRequest, TelegramForbiddenError, TelegramRetryAfter
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import CallbackQuery, Message
from aiogram.types import FSInputFile
from aiogram.types.input_file import BufferedInputFile
from aiogram.webhook.aiohttp_server import SimpleRequestHandler, setup_application
from aiohttp import web

import qrcode
from tracegate.bot.access import (
    blocked_message,
    bot_block_until,
    can_manage_block,
    is_admin,
    is_bot_blocked,
    is_superadmin,
    user_label,
)
from tracegate.bot.client import ApiClientError, TracegateApiClient
from tracegate.bot.keyboards import (
    SNI_PAGE_SIZE,
    admin_menu_keyboard,
    device_actions_keyboard,
    devices_keyboard,
    main_menu_keyboard,
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
from tracegate.settings import get_settings

settings = get_settings()
api = TracegateApiClient(settings.bot_api_base_url, settings.bot_api_token)
router = Router()

def _main_menu_text() -> str:
    return "Tracegate v0.3\nВыберите действие:\n\nГайдлайн доступен по команде /guide"


def _load_guide_text() -> str:
    guide_path = settings.bot_guide_path.strip()
    if not guide_path:
        guide_path = str(Path(settings.bundle_root) / "bot" / "guide.md")
    try:
        return Path(guide_path).read_text(encoding="utf-8").strip() or "Гайд пока пуст."
    except FileNotFoundError:
        return "Гайд пока не настроен."
    except Exception:
        return "Не смог прочитать гайд."


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


class DeviceFlow(StatesGroup):
    waiting_for_name = State()


class SniCatalogFlow(StatesGroup):
    waiting_for_input = State()

class AdminFlow(StatesGroup):
    waiting_for_grant_id = State()
    waiting_for_revoke_id = State()
    waiting_for_user_block = State()
    waiting_for_user_unblock = State()


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
                    await event.answer("Доступ ограничен", show_alert=True)
                except Exception:
                    pass
                if event.message is not None:
                    await event.message.answer(text)
                return None
            if isinstance(event, Message):
                await event.answer(text)
                return None
        return await handler(event, data)


async def ensure_user(telegram_id: int) -> dict:
    return await api.get_or_create_user(telegram_id)


def _connection_family_name(protocol: str, mode: str) -> str:
    p = (protocol or "").strip().lower()
    m = (mode or "").strip().lower()
    if p == ConnectionProtocol.VLESS_REALITY.value:
        return "VLESS Reality Chain" if m == ConnectionMode.CHAIN.value else "VLESS Reality Direct"
    if p == ConnectionProtocol.VLESS_WS_TLS.value:
        return "VLESS TLS Chain" if m == ConnectionMode.CHAIN.value else "VLESS TLS Direct"
    if p == ConnectionProtocol.HYSTERIA2.value:
        return "Hysteria2"
    if p == ConnectionProtocol.WIREGUARD.value:
        return "WireGuard"
    return f"{protocol}/{mode}"


async def render_device_page(device_id: str) -> tuple[str, object]:
    connections = await api.list_connections(device_id)
    text = "Подключения:\n"
    if connections:
        lines = []
        for connection in connections:
            alias = (connection.get("alias") or "").strip()
            if alias:
                lines.append(f"- {alias}")
            else:
                lines.append(
                    f"- {_connection_family_name(connection['protocol'], connection['mode'])} id={connection['id']}"
                )
        text += "\n".join(lines)
    else:
        text += "пока нет"
    return text, device_actions_keyboard(device_id, connections)


async def render_revisions_page(connection_id: str) -> tuple[str, object]:
    connection = await api.get_connection(connection_id)
    revisions = await api.list_revisions(connection_id)
    family = _connection_family_name(connection["protocol"], connection["mode"])
    alias = (connection.get("alias") or "").strip()
    text = f"Ревизии: {alias or family}\nconnection={connection_id}\n"
    if revisions:
        rows = [f"- id={r['id']} slot={r['slot']} status={r['status']}" for r in revisions]
        text += "\n".join(rows)
    else:
        text += "пока нет"

    is_vless = connection["protocol"] in {ConnectionProtocol.VLESS_REALITY.value, ConnectionProtocol.VLESS_WS_TLS.value}
    return text, revisions_keyboard(connection_id, revisions, is_vless, connection["device_id"])


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


def _format_uri_instructions(uri: str) -> str:
    return (
        "Ссылка для импорта в клиент:\n\n"
        f"{uri}"
    )


def _connection_marker(connection: dict) -> str:
    variant = str(connection.get("variant") or "").strip() or "B?"
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


async def _send_client_config(callback: CallbackQuery, revision: dict) -> None:
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
        marker = f"B? - {callback.from_user.id} - {device_id or '?'} - {connection_id or '?'}"

    try:
        exported = export_client_config(effective)
    except V2RayNExportError as exc:
        await callback.message.answer(f"Не смог собрать конфиг для клиента: {exc}")
        return

    if exported.kind == "uri":
        sent = await callback.message.answer(
            f"{marker}\n\n{_format_uri_instructions(exported.content)}",
            disable_web_page_preview=True,
        )
        await _register_bot_message_ref(
            callback,
            message_id=sent.message_id,
            connection_id=connection_id or None,
            device_id=device_id or None,
            revision_id=revision_id or None,
        )
        qr_bytes = _build_qr_png(exported.content)
        qr_msg = await callback.message.answer_photo(
            BufferedInputFile(qr_bytes, filename="tracegate-config-qr.png"),
            caption=f"{marker}\n{exported.title} (QR)",
        )
        await _register_bot_message_ref(
            callback,
            message_id=qr_msg.message_id,
            connection_id=connection_id or None,
            device_id=device_id or None,
            revision_id=revision_id or None,
        )
        return

    if exported.kind == "wg_conf":
        data = exported.content.encode("utf-8")
        filename = exported.filename or "wg0.conf"
        sent = await callback.message.answer_document(
            BufferedInputFile(data, filename=filename),
            caption=f"{marker}\n{exported.title}",
        )
        await _register_bot_message_ref(
            callback,
            message_id=sent.message_id,
            connection_id=connection_id or None,
            device_id=device_id or None,
            revision_id=revision_id or None,
        )
        return

    await callback.message.answer(f"Неизвестный тип экспорта: {exported.kind}")


@router.message(CommandStart())
async def start(message: Message) -> None:
    await _send_main_menu(message)


@router.message(Command("guide"))
async def guide(message: Message) -> None:
    await message.answer(_load_guide_text(), disable_web_page_preview=True)


@router.message(Command("clean"))
async def clean(message: Message, state: FSMContext) -> None:
    await state.clear()
    if message.chat.type != "private":
        await message.answer("Команда /clean доступна только в личном чате с ботом.")
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
        await callback.answer("Недостаточно прав")
        return
    await callback.message.edit_text(
        "Админ меню:",
        reply_markup=admin_menu_keyboard(is_superadmin=is_superadmin(user)),
    )
    await callback.answer()


@router.callback_query(F.data == "grafana_otp")
async def grafana_otp(callback: CallbackQuery) -> None:
    try:
        user = await ensure_user(callback.from_user.id)
        otp = await api.create_grafana_otp(user["telegram_id"], scope="user")
        await callback.message.answer(
            "Grafana OTP (user scope):\n"
            f"- expires_at: {otp.get('expires_at')}\n"
            f"- link: {otp.get('login_url')}",
            disable_web_page_preview=True,
        )
    except ApiClientError as exc:
        await callback.message.answer(f"Ошибка: {exc}")
    await callback.answer()


@router.callback_query(F.data == "grafana_otp_admin")
async def grafana_otp_admin(callback: CallbackQuery) -> None:
    try:
        user = await ensure_user(callback.from_user.id)
        if not is_admin(user):
            await callback.answer("Недостаточно прав")
            return
        otp = await api.create_grafana_otp(user["telegram_id"], scope="admin")
        await callback.message.answer(
            "Grafana OTP (admin scope):\n"
            f"- expires_at: {otp.get('expires_at')}\n"
            f"- link: {otp.get('login_url')}",
            disable_web_page_preview=True,
        )
    except ApiClientError as exc:
        await callback.message.answer(f"Ошибка: {exc}")
    await callback.answer()


@router.callback_query(F.data == "admin_grant")
async def admin_grant(callback: CallbackQuery, state: FSMContext) -> None:
    user = await ensure_user(callback.from_user.id)
    if not is_superadmin(user):
        await callback.answer("Только superadmin")
        return
    await state.set_state(AdminFlow.waiting_for_grant_id)
    await callback.message.answer("Введи Telegram ID пользователя, которому выдать роль admin:")
    await callback.answer()


@router.callback_query(F.data == "admin_revoke")
async def admin_revoke(callback: CallbackQuery, state: FSMContext) -> None:
    user = await ensure_user(callback.from_user.id)
    if not is_superadmin(user):
        await callback.answer("Только superadmin")
        return
    await state.set_state(AdminFlow.waiting_for_revoke_id)
    await callback.message.answer("Введи Telegram ID пользователя, у которого снять роль admin:")
    await callback.answer()


@router.callback_query(F.data == "admin_list")
async def admin_list(callback: CallbackQuery) -> None:
    user = await ensure_user(callback.from_user.id)
    if not is_superadmin(user):
        await callback.answer("Только superadmin")
        return
    try:
        admins = await api.list_users(role="admin", limit=500)
        supers = await api.list_users(role="superadmin", limit=500)
        lines = ["Superadmins:"] + [f"- {u['telegram_id']}" for u in supers]
        lines += ["", "Admins:"] + [f"- {u['telegram_id']}" for u in admins]
        await callback.message.answer("\n".join(lines) if (admins or supers) else "Нет админов.")
    except ApiClientError as exc:
        await callback.message.answer(f"Ошибка: {exc}")
    await callback.answer()

@router.callback_query(F.data == "admin_users")
async def admin_users(callback: CallbackQuery) -> None:
    actor = await ensure_user(callback.from_user.id)
    if not is_admin(actor):
        await callback.answer("Недостаточно прав")
        return
    try:
        users = await api.list_users(limit=300)
        users.sort(key=lambda row: (str(row.get("role") or ""), int(row.get("telegram_id") or 0)))
        lines = ["Пользователи (до 300):"]
        max_rows = 80
        for idx, user in enumerate(users[:max_rows], start=1):
            role = (user.get("role") or "").strip()
            until = bot_block_until(user)
            block_suffix = f" [BLOCK до {until.isoformat()}]" if until and until > datetime.now(timezone.utc) else ""
            lines.append(f"{idx}. {user_label(user)} | role={role}{block_suffix}")
        if len(users) > max_rows:
            lines.append("")
            lines.append(f"Показано {max_rows} из {len(users)}.")
        await callback.message.answer("\n".join(lines))
    except ApiClientError as exc:
        await callback.message.answer(f"Ошибка: {exc}")
    await callback.answer()


@router.callback_query(F.data == "admin_user_block")
async def admin_user_block(callback: CallbackQuery, state: FSMContext) -> None:
    actor = await ensure_user(callback.from_user.id)
    if not is_admin(actor):
        await callback.answer("Недостаточно прав")
        return
    await state.set_state(AdminFlow.waiting_for_user_block)
    await callback.message.answer(
        "Введи: <telegram_id> <hours> [reason]\n"
        "Пример: 123456789 72 abuse"
    )
    await callback.answer()


@router.callback_query(F.data == "admin_user_unblock")
async def admin_user_unblock(callback: CallbackQuery, state: FSMContext) -> None:
    actor = await ensure_user(callback.from_user.id)
    if not is_admin(actor):
        await callback.answer("Недостаточно прав")
        return
    await state.set_state(AdminFlow.waiting_for_user_unblock)
    await callback.message.answer("Введи Telegram ID пользователя для снятия блокировки:")
    await callback.answer()


@router.message(AdminFlow.waiting_for_grant_id)
async def receive_admin_grant_id(message: Message, state: FSMContext) -> None:
    try:
        text = (message.text or "").strip()
        telegram_id = int(text)
        await api.get_or_create_user(telegram_id)
        await api.set_user_role(telegram_id, "admin")
        await message.answer(f"Готово: {telegram_id} теперь admin.")
    except Exception as exc:  # noqa: BLE001
        await message.answer(f"Ошибка: {exc}")
    finally:
        await state.clear()


@router.message(AdminFlow.waiting_for_revoke_id)
async def receive_admin_revoke_id(message: Message, state: FSMContext) -> None:
    try:
        text = (message.text or "").strip()
        telegram_id = int(text)
        if telegram_id in (settings.superadmin_telegram_ids or []):
            await message.answer("Нельзя снять superadmin.")
            return
        await api.set_user_role(telegram_id, "user")
        await message.answer(f"Готово: {telegram_id} теперь user.")
    except Exception as exc:  # noqa: BLE001
        await message.answer(f"Ошибка: {exc}")
    finally:
        await state.clear()


@router.message(AdminFlow.waiting_for_user_block)
async def receive_user_block(message: Message, state: FSMContext) -> None:
    try:
        actor = await ensure_user(message.from_user.id)
        if not is_admin(actor):
            await message.answer("Недостаточно прав.")
            return

        parts = (message.text or "").strip().split(maxsplit=2)
        if len(parts) < 2:
            await message.answer("Формат: <telegram_id> <hours> [reason]")
            return
        target_id = int(parts[0])
        hours = int(parts[1])
        reason = parts[2].strip() if len(parts) >= 3 else None

        target = await api.get_or_create_user(target_id)
        if not can_manage_block(actor, target):
            await message.answer("Недостаточно прав для блокировки этой роли.")
            return

        blocked = await api.block_user_bot(target_id, hours=hours, reason=reason, revoke_access=True)
        await message.answer(
            f"Готово: {user_label(target)} заблокирован до {blocked.get('bot_blocked_until')}."
        )
    except Exception as exc:  # noqa: BLE001
        await message.answer(f"Ошибка: {exc}")
    finally:
        await state.clear()


@router.message(AdminFlow.waiting_for_user_unblock)
async def receive_user_unblock(message: Message, state: FSMContext) -> None:
    try:
        actor = await ensure_user(message.from_user.id)
        if not is_admin(actor):
            await message.answer("Недостаточно прав.")
            return

        target_id = int((message.text or "").strip())
        target = await api.get_user(target_id)
        if not can_manage_block(actor, target):
            await message.answer("Недостаточно прав для снятия блокировки этой роли.")
            return

        await api.unblock_user_bot(target_id)
        await message.answer(f"Готово: блокировка снята для {user_label(target)}.")
    except Exception as exc:  # noqa: BLE001
        await message.answer(f"Ошибка: {exc}")
    finally:
        await state.clear()


@router.callback_query(F.data == "devices")
async def list_devices(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    user = await ensure_user(callback.from_user.id)
    devices = await api.list_devices(user["telegram_id"])
    text = "Устройства:\n" + ("\n".join([f"- {d['name']} id={d['id']}" for d in devices]) if devices else "пока нет")
    await callback.message.edit_text(text, reply_markup=devices_keyboard(devices))
    await callback.answer()


@router.callback_query(F.data == "add_device")
async def add_device(callback: CallbackQuery, state: FSMContext) -> None:
    await state.set_state(DeviceFlow.waiting_for_name)
    await callback.message.answer("Введите имя нового устройства")
    await callback.answer()


@router.message(DeviceFlow.waiting_for_name)
async def receive_device_name(message: Message, state: FSMContext) -> None:
    try:
        name = (message.text or "").strip()
        if not name:
            await message.answer("Имя устройства не может быть пустым.")
            return
        user = await ensure_user(message.from_user.id)
        await api.create_device(user["telegram_id"], name)
        devices = await api.list_devices(user["telegram_id"])
        await message.answer("Устройство добавлено", reply_markup=devices_keyboard(devices))
    except ApiClientError as exc:
        await message.answer(f"Ошибка: {exc}")
    finally:
        await state.clear()


@router.callback_query(F.data.startswith("device:"))
async def device_actions(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    _, device_id = callback.data.split(":", 1)
    text, keyboard = await render_device_page(device_id)
    await callback.message.edit_text(text, reply_markup=keyboard)
    await callback.answer()


@router.callback_query(F.data.startswith("deldev:"))
async def delete_device(callback: CallbackQuery) -> None:
    _, device_id = callback.data.split(":", 1)
    try:
        await api.delete_device(device_id)
        await _cleanup_related_messages(callback, device_id=device_id)
        user = await ensure_user(callback.from_user.id)
        devices = await api.list_devices(user["telegram_id"])
        text = "Устройства:\n" + ("\n".join([f"- {d['name']} id={d['id']}" for d in devices]) if devices else "пока нет")
        await callback.message.edit_text(text, reply_markup=devices_keyboard(devices))
        await callback.message.answer("Устройство удалено (все подключения отозваны).")
    except ApiClientError as exc:
        await callback.message.answer(f"Ошибка: {exc}")
    await callback.answer()


def _profile(spec: str) -> tuple[ConnectionProtocol, ConnectionMode, ConnectionVariant]:
    if spec == "b1":
        return ConnectionProtocol.VLESS_REALITY, ConnectionMode.DIRECT, ConnectionVariant.B1
    if spec == "b1ws":
        return ConnectionProtocol.VLESS_WS_TLS, ConnectionMode.DIRECT, ConnectionVariant.B1
    if spec == "b2":
        return ConnectionProtocol.VLESS_REALITY, ConnectionMode.CHAIN, ConnectionVariant.B2
    if spec == "b2ws":
        return ConnectionProtocol.VLESS_WS_TLS, ConnectionMode.CHAIN, ConnectionVariant.B2
    if spec == "b3":
        return ConnectionProtocol.HYSTERIA2, ConnectionMode.DIRECT, ConnectionVariant.B3
    if spec == "b5":
        return ConnectionProtocol.WIREGUARD, ConnectionMode.DIRECT, ConnectionVariant.B5
    raise ValueError("unknown profile")


@router.callback_query(F.data.startswith("new:"))
async def new_connection(callback: CallbackQuery) -> None:
    _, spec, device_id = callback.data.split(":", 2)

    try:
        protocol, _, _ = _profile(spec)
        if protocol == ConnectionProtocol.VLESS_REALITY:
            await callback.message.edit_text(
                "Выбери провайдера (для фильтра SNI):",
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
        await callback.message.answer(
            f"Создано: {_connection_marker(connection)}\nrevision={revision['id']} slot={revision['slot']}"
        )
        await _send_client_config(callback, revision)
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(f"Ошибка: {exc}")

    await callback.answer()


@router.callback_query(F.data.startswith("vlessnew:"))
async def vless_new(callback: CallbackQuery) -> None:
    # vlessnew:<spec>:<device_id> where spec is "b1" (direct) or "b2" (chain)
    _, spec, device_id = callback.data.split(":", 2)
    if spec not in {"b1", "b2"}:
        await callback.message.answer("Ошибка: неизвестный профиль VLESS")
        await callback.answer()
        return

    await callback.message.edit_text(
        f"{'B1' if spec == 'b1' else 'B2'} - VLESS: выбери транспорт подключения:",
        reply_markup=vless_transport_keyboard(spec=spec, device_id=device_id),
    )
    await callback.answer()


@router.callback_query(F.data.startswith("vlesstrans:"))
async def vless_transport(callback: CallbackQuery) -> None:
    # vlesstrans:<spec>:<device_id>:<transport>
    _, spec, device_id, transport = callback.data.split(":", 3)
    transport = (transport or "").strip().lower()
    if spec not in {"b1", "b2"}:
        await callback.message.answer("Ошибка: неизвестный профиль VLESS")
        await callback.answer()
        return

    try:
        if transport == "reality":
            await callback.message.edit_text(
                "Выбери провайдера (для фильтра SNI):",
                reply_markup=provider_keyboard_with_cancel(
                    "new",
                    f"{spec}:{device_id}",
                    cancel_callback_data=f"device:{device_id}",
                ),
            )
            await callback.answer()
            return

        if transport != "tls":
            raise ValueError("unknown transport")

        user = await ensure_user(callback.from_user.id)
        protocol, mode, variant = _profile(f"{spec}ws")
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
        await callback.message.answer(
            f"Создано: {_connection_marker(connection)}\nrevision={revision['id']} slot={revision['slot']}"
        )
        await _send_client_config(callback, revision)
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(f"Ошибка: {exc}")
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
        await callback.message.answer(
            f"Создано: {_connection_marker(connection)}\nrevision={revision['id']} slot={revision['slot']}"
        )
        await _send_client_config(callback, revision)
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(f"Ошибка: {exc}")

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
            "Нет доступных SNI в этой категории. Выберите другой провайдер:",
            provider_keyboard_with_cancel("new", f"{spec}:{device_id}", cancel_callback_data=f"device:{device_id}"),
        )

    total = len(sni_rows)
    page_count = max(1, (total + SNI_PAGE_SIZE - 1) // SNI_PAGE_SIZE)
    page = max(0, min(page, page_count - 1))
    start = page * SNI_PAGE_SIZE
    end = start + SNI_PAGE_SIZE
    page_rows = sni_rows[start:end]

    text = f"Выберите SNI для VLESS/REALITY (provider={provider}, {page+1}/{page_count}, total={total}):"
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
            "Нет доступных SNI в этой категории. Выберите другой провайдер:",
            provider_keyboard_with_cancel("issue", connection_id, cancel_callback_data=f"revs:{connection_id}"),
        )

    total = len(sni_rows)
    page_count = max(1, (total + SNI_PAGE_SIZE - 1) // SNI_PAGE_SIZE)
    page = max(0, min(page, page_count - 1))
    start = page * SNI_PAGE_SIZE
    end = start + SNI_PAGE_SIZE
    page_rows = sni_rows[start:end]

    text = f"Выберите SNI для новой ревизии (provider={provider}, {page+1}/{page_count}, total={total}):"
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

    header = f"Каталог SNI (provider={provider}, {page+1}/{page_count}, total={total})"
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
    lines.append("Напиши номер из списка, чтобы выбрать SNI.")
    lines.append("Или напиши часть домена для поиска (например: splitter, vk.com).")

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
    # target_id may itself contain ":" (e.g. "b1:<device_id>") so we can't use a fixed maxsplit.
    parts = callback.data.split(":")
    if len(parts) < 4:
        await callback.message.answer("Ошибка: некорректные данные кнопки")
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
            await callback.message.answer("Неизвестный контекст выбора провайдера")
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(f"Ошибка: {exc}")

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
        await callback.message.answer(f"Ошибка: {exc}")
    finally:
        await callback.answer()


@router.callback_query(F.data == "sni_catalog")
async def sni_catalog(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await callback.message.edit_text(
        "Каталог SNI: выбери провайдера (для фильтра):",
        reply_markup=provider_keyboard_with_cancel("catalog", "catalog", cancel_callback_data="menu"),
    )
    await callback.answer()


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
        await callback.message.answer(f"Ошибка: {exc}")
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
        await callback.message.answer(f"Ошибка: {exc}")
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
            await message.answer(f"Неверный номер. Введи число от 1 до {len(page_rows)}.")
            return

        chosen = page_rows[n - 1]
        sni_id = int(chosen["id"])
        fqdn = (chosen.get("fqdn") or "").strip()
        note = _clip_note(chosen.get("note"))
        out = f"Выбран SNI:\n{fqdn or f'id={sni_id}'}"
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
        await message.answer(f"Ошибка: {exc}")


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
    out = f"Выбран SNI:\n{fqdn}"
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
        await callback.message.answer(f"Ошибка: {exc}")
    await callback.answer()


@router.callback_query(F.data.startswith("catnewpick:"))
async def sni_catalog_new_pick_device(callback: CallbackQuery) -> None:
    # catnewpick:<b1|b2>:<sni_id>:<provider>:<page>
    parts = callback.data.split(":")
    if len(parts) != 5:
        await callback.message.answer("Ошибка: некорректные данные кнопки")
        await callback.answer()
        return
    _, spec, sni_id_raw, provider, page_raw = parts
    try:
        sni_id = int(sni_id_raw)
        page = int(page_raw)
        user = await ensure_user(callback.from_user.id)
        devices = await api.list_devices(user["telegram_id"])
        if not devices:
            await callback.message.edit_text("Нет устройств. Сначала добавь устройство.", reply_markup=main_menu_keyboard())
            await callback.answer()
            return
        await callback.message.edit_text(
            "Выбери устройство для нового VLESS подключения:",
            reply_markup=sni_catalog_device_pick_keyboard(
                spec=spec,
                sni_id=sni_id,
                devices=devices,
                provider=provider,
                page=page,
            ),
        )
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(f"Ошибка: {exc}")
    await callback.answer()


@router.callback_query(F.data.startswith("catnew:"))
async def sni_catalog_new_connection(callback: CallbackQuery, state: FSMContext) -> None:
    # catnew:<b1|b2>:<device_id>:<sni_id>
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
        await callback.message.answer(
            f"Создано: connection={connection['id']} revision={revision['id']} slot={revision['slot']}"
        )
        await _send_client_config(callback, revision)
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(f"Ошибка: {exc}")
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
                "У тебя нет VLESS подключений, куда можно выпустить ревизию.",
                reply_markup=sni_catalog_action_keyboard(sni_id=sni_id, provider=provider, page=page),
            )
            await callback.answer()
            return

        await callback.message.edit_text(
            "Выбери VLESS подключение для новой ревизии (SNI будет применён к новой ревизии):",
            reply_markup=sni_catalog_connection_pick_keyboard(
                sni_id=sni_id,
                vless_connections=vless_connections,
                provider=provider,
                page=page,
            ),
        )
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(f"Ошибка: {exc}")
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
        await _send_client_config(callback, revision)
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(f"Ошибка: {exc}")
    await callback.answer()


@router.callback_query(F.data.startswith("revs:"))
async def list_revisions(callback: CallbackQuery) -> None:
    _, connection_id = callback.data.split(":", 1)
    try:
        text, keyboard = await render_revisions_page(connection_id)
        edited = await _safe_edit_text(callback.message, text, reply_markup=keyboard)
        await callback.answer("Обновлено" if edited else "Без изменений")
    except ApiClientError as exc:
        await callback.message.answer(f"Ошибка: {exc}")
        await callback.answer()
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(f"Ошибка: {exc}")
        await callback.answer()


@router.callback_query(F.data.startswith("issuepick:"))
async def issue_pick_sni(callback: CallbackQuery) -> None:
    _, connection_id = callback.data.split(":", 1)
    await callback.message.edit_text(
        "Выбери провайдера (для фильтра SNI):",
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
        await _send_client_config(callback, revision)
    except ApiClientError as exc:
        await callback.message.answer(f"Ошибка: {exc}")
    await callback.answer()


@router.callback_query(F.data.startswith("activate:"))
async def activate_revision(callback: CallbackQuery) -> None:
    _, revision_id = callback.data.split(":", 1)
    try:
        revision = await api.activate_revision(revision_id)
        text, keyboard = await render_revisions_page(revision["connection_id"])
        await _safe_edit_text(callback.message, text, reply_markup=keyboard)
        await callback.answer("Активировано")
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(f"Ошибка: {exc}")
        await callback.answer()


@router.callback_query(F.data.startswith("revoke:"))
async def revoke_revision(callback: CallbackQuery) -> None:
    _, revision_id = callback.data.split(":", 1)
    try:
        revision = await api.revoke_revision(revision_id)
        await _cleanup_related_messages(callback, revision_id=revision_id)
        text, keyboard = await render_revisions_page(revision["connection_id"])
        await _safe_edit_text(callback.message, text, reply_markup=keyboard)
        await callback.answer("Удалено")
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(f"Ошибка: {exc}")
        await callback.answer()


@router.callback_query(F.data.startswith("issuesni:"))
async def issue_revision_with_sni(callback: CallbackQuery) -> None:
    _, connection_id, sni_id_raw = callback.data.split(":", 2)
    try:
        revision = await api.issue_revision(connection_id, sni_id=int(sni_id_raw))
        text, keyboard = await render_revisions_page(revision["connection_id"])
        await _safe_edit_text(callback.message, text, reply_markup=keyboard)
        await _send_client_config(callback, revision)
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(f"Ошибка: {exc}")

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
        await callback.message.answer("Подключение удалено (доступ отозван).")
    except ApiClientError as exc:
        await callback.message.answer(f"Ошибка: {exc}")
    await callback.answer()


def run() -> None:
    configure_logging(settings.log_level)
    if not settings.bot_token:
        raise RuntimeError("BOT_TOKEN is required")
    if not settings.bot_api_token:
        raise RuntimeError("BOT_API_TOKEN is required")
    if not settings.bot_api_base_url:
        raise RuntimeError("BOT_API_BASE_URL is required")

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
    access_mw = BotAccessMiddleware()
    dp.message.middleware(access_mw)
    dp.callback_query.middleware(access_mw)
    dp.include_router(router)

    # Ensure webhook is disabled; otherwise Telegram rejects getUpdates.
    await bot.delete_webhook(drop_pending_updates=True)
    try:
        await dp.start_polling(bot)
    finally:
        await api.close()
        await bot.session.close()


def _run_webhook() -> None:
    bot = Bot(token=settings.bot_token)
    dp = Dispatcher()
    access_mw = BotAccessMiddleware()
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
