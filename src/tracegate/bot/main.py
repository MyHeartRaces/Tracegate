from __future__ import annotations

import asyncio
import ssl
from pathlib import Path

from aiogram import Bot, Dispatcher, F, Router
from aiogram.filters import CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import CallbackQuery, Message
from aiogram.types import FSInputFile
from aiogram.types.input_file import BufferedInputFile
from aiogram.webhook.aiohttp_server import SimpleRequestHandler, setup_application
from aiohttp import web

from tracegate.bot.client import ApiClientError, TracegateApiClient
from tracegate.bot.keyboards import (
    device_actions_keyboard,
    devices_keyboard,
    issue_sni_keyboard,
    main_menu_keyboard,
    provider_keyboard,
    revisions_keyboard,
    sni_keyboard,
)
from tracegate.client_export.v2rayn import V2RayNExportError, export_v2rayn
from tracegate.enums import ConnectionMode, ConnectionProtocol, ConnectionVariant
from tracegate.settings import get_settings

settings = get_settings()
api = TracegateApiClient(settings.bot_api_base_url, settings.bot_api_token)
router = Router()


class DeviceFlow(StatesGroup):
    waiting_for_name = State()


async def ensure_user(telegram_id: int) -> dict:
    return await api.get_or_create_user(telegram_id)


async def render_device_page(device_id: str) -> tuple[str, object]:
    connections = await api.list_connections(device_id)
    text = "Подключения:\n"
    if connections:
        lines = [f"- {c['variant']} ({c['protocol']}) id={c['id']}" for c in connections]
        text += "\n".join(lines)
    else:
        text += "пока нет"
    return text, device_actions_keyboard(device_id, connections)


async def render_revisions_page(connection_id: str) -> tuple[str, object]:
    connection = await api.get_connection(connection_id)
    revisions = await api.list_revisions(connection_id)
    text = f"Ревизии connection={connection_id}\n"
    if revisions:
        rows = [f"- id={r['id']} slot={r['slot']} status={r['status']}" for r in revisions]
        text += "\n".join(rows)
    else:
        text += "пока нет"

    is_vless = connection["protocol"] == ConnectionProtocol.VLESS_REALITY.value
    return text, revisions_keyboard(connection_id, revisions, is_vless)

def _format_v2rayn_instructions(uri: str) -> str:
    # Keep it short: Telegram message length is limited and users mainly want the share link.
    return (
        "v2rayN import:\n"
        "1) Copy the link below\n"
        "2) In v2rayN: Ctrl+V (or Import from clipboard)\n\n"
        f"{uri}"
    )


async def _send_client_config(callback: CallbackQuery, revision: dict) -> None:
    effective = revision.get("effective_config_json") or {}
    try:
        exported = export_v2rayn(effective)
    except V2RayNExportError as exc:
        await callback.message.answer(f"Не смог собрать конфиг для v2rayN: {exc}")
        return

    if exported.kind == "uri":
        await callback.message.answer(_format_v2rayn_instructions(exported.content))
        return

    if exported.kind == "wg_conf":
        data = exported.content.encode("utf-8")
        filename = exported.filename or "wg0.conf"
        await callback.message.answer_document(BufferedInputFile(data, filename=filename), caption=exported.title)
        return

    await callback.message.answer(f"Неизвестный тип экспорта: {exported.kind}")


@router.message(CommandStart())
async def start(message: Message) -> None:
    await ensure_user(message.from_user.id)
    await message.answer("Tracegate v0.1\nВыберите действие:", reply_markup=main_menu_keyboard())


@router.callback_query(F.data == "menu")
async def menu(callback: CallbackQuery) -> None:
    await callback.message.edit_text("Tracegate v0.1\nВыберите действие:", reply_markup=main_menu_keyboard())
    await callback.answer()


@router.callback_query(F.data == "devices")
async def list_devices(callback: CallbackQuery) -> None:
    user = await ensure_user(callback.from_user.id)
    devices = await api.list_devices(user["id"])
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
        user = await ensure_user(message.from_user.id)
        await api.create_device(user["id"], message.text.strip())
        devices = await api.list_devices(user["id"])
        await message.answer("Устройство добавлено", reply_markup=devices_keyboard(devices))
    except ApiClientError as exc:
        await message.answer(f"Ошибка: {exc}")
    finally:
        await state.clear()


@router.callback_query(F.data.startswith("device:"))
async def device_actions(callback: CallbackQuery) -> None:
    _, device_id = callback.data.split(":", 1)
    text, keyboard = await render_device_page(device_id)
    await callback.message.edit_text(text, reply_markup=keyboard)
    await callback.answer()


@router.callback_query(F.data.startswith("deldev:"))
async def delete_device(callback: CallbackQuery) -> None:
    _, device_id = callback.data.split(":", 1)
    try:
        await api.delete_device(device_id)
        user = await ensure_user(callback.from_user.id)
        devices = await api.list_devices(user["id"])
        text = "Устройства:\n" + ("\n".join([f"- {d['name']} id={d['id']}" for d in devices]) if devices else "пока нет")
        await callback.message.edit_text(text, reply_markup=devices_keyboard(devices))
        await callback.message.answer("Устройство удалено (все подключения отозваны).")
    except ApiClientError as exc:
        await callback.message.answer(f"Ошибка: {exc}")
    await callback.answer()


def _profile(spec: str) -> tuple[ConnectionProtocol, ConnectionMode, ConnectionVariant]:
    if spec == "b1":
        return ConnectionProtocol.VLESS_REALITY, ConnectionMode.DIRECT, ConnectionVariant.B1
    if spec == "b2":
        return ConnectionProtocol.VLESS_REALITY, ConnectionMode.CHAIN, ConnectionVariant.B2
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
                reply_markup=provider_keyboard("new", f"{spec}:{device_id}"),
            )
            await callback.answer()
            return

        user = await ensure_user(callback.from_user.id)
        protocol, mode, variant = _profile(spec)
        connection, revision = await api.create_connection_and_revision(
            user["id"],
            device_id,
            protocol,
            mode,
            variant,
            None,
        )
        text, keyboard = await render_device_page(device_id)
        await callback.message.edit_text(text, reply_markup=keyboard)
        await callback.message.answer(
            f"Создано: connection={connection['id']} revision={revision['id']} slot={revision['slot']}"
        )
        await _send_client_config(callback, revision)
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(f"Ошибка: {exc}")

    await callback.answer()


@router.callback_query(F.data.startswith("sni:"))
async def new_vless_with_sni(callback: CallbackQuery) -> None:
    _, spec, device_id, sni_id_raw = callback.data.split(":", 3)

    try:
        user = await ensure_user(callback.from_user.id)
        protocol, mode, variant = _profile(spec)
        connection, revision = await api.create_connection_and_revision(
            user["id"],
            device_id,
            protocol,
            mode,
            variant,
            int(sni_id_raw),
        )
        text, keyboard = await render_device_page(device_id)
        await callback.message.edit_text(text, reply_markup=keyboard)
        await callback.message.answer(
            f"Создано: connection={connection['id']} revision={revision['id']} slot={revision['slot']}"
        )
        await _send_client_config(callback, revision)
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(f"Ошибка: {exc}")

    await callback.answer()


@router.callback_query(F.data.startswith("prov:"))
async def pick_provider(callback: CallbackQuery) -> None:
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
            sni_rows = [
                row
                for row in await api.list_sni_filtered(
                    provider=None if provider == "all" else provider,
                    purpose="vless_reality",
                )
                if row["enabled"]
            ]
            if not sni_rows:
                await callback.message.answer("Нет доступных SNI в этой категории")
            else:
                await callback.message.edit_text(
                    "Выберите SNI для VLESS/REALITY:",
                    reply_markup=sni_keyboard(spec, device_id, sni_rows),
                )
        elif context == "issue":
            connection_id = target_id
            sni_rows = [
                row
                for row in await api.list_sni_filtered(
                    provider=None if provider == "all" else provider,
                    purpose="vless_reality",
                )
                if row["enabled"]
            ]
            if not sni_rows:
                await callback.message.answer("Нет доступных SNI в этой категории")
            else:
                await callback.message.edit_text(
                    "Выберите SNI для новой ревизии:",
                    reply_markup=issue_sni_keyboard(connection_id, sni_rows),
                )
        else:
            await callback.message.answer("Неизвестный контекст выбора провайдера")
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(f"Ошибка: {exc}")

    await callback.answer()


@router.callback_query(F.data.startswith("revs:"))
async def list_revisions(callback: CallbackQuery) -> None:
    _, connection_id = callback.data.split(":", 1)
    text, keyboard = await render_revisions_page(connection_id)
    await callback.message.edit_text(text, reply_markup=keyboard)
    await callback.answer()


@router.callback_query(F.data.startswith("issuepick:"))
async def issue_pick_sni(callback: CallbackQuery) -> None:
    _, connection_id = callback.data.split(":", 1)
    await callback.message.edit_text(
        "Выбери провайдера (для фильтра SNI):",
        reply_markup=provider_keyboard("issue", connection_id),
    )
    await callback.answer()


@router.callback_query(F.data.startswith("issueplain:"))
async def issue_revision(callback: CallbackQuery) -> None:
    _, connection_id = callback.data.split(":", 1)
    try:
        revision = await api.issue_revision(connection_id)
        text, keyboard = await render_revisions_page(revision["connection_id"])
        await callback.message.edit_text(text, reply_markup=keyboard)
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
        await callback.message.edit_text(text, reply_markup=keyboard)
    except ApiClientError as exc:
        await callback.message.answer(f"Ошибка: {exc}")
    await callback.answer()


@router.callback_query(F.data.startswith("revoke:"))
async def revoke_revision(callback: CallbackQuery) -> None:
    _, revision_id = callback.data.split(":", 1)
    try:
        revision = await api.revoke_revision(revision_id)
        text, keyboard = await render_revisions_page(revision["connection_id"])
        await callback.message.edit_text(text, reply_markup=keyboard)
    except ApiClientError as exc:
        await callback.message.answer(f"Ошибка: {exc}")
    await callback.answer()


@router.callback_query(F.data.startswith("issuesni:"))
async def issue_revision_with_sni(callback: CallbackQuery) -> None:
    _, connection_id, sni_id_raw = callback.data.split(":", 2)
    try:
        revision = await api.issue_revision(connection_id, sni_id=int(sni_id_raw))
        text, keyboard = await render_revisions_page(revision["connection_id"])
        await callback.message.edit_text(text, reply_markup=keyboard)
        await _send_client_config(callback, revision)
    except Exception as exc:  # noqa: BLE001
        await callback.message.answer(f"Ошибка: {exc}")

    await callback.answer()


@router.callback_query(F.data.startswith("delconn:"))
async def delete_connection(callback: CallbackQuery) -> None:
    _, device_id, connection_id = callback.data.split(":", 2)
    try:
        await api.delete_connection(connection_id)
        text, keyboard = await render_device_page(device_id)
        await callback.message.edit_text(text, reply_markup=keyboard)
        await callback.message.answer("Подключение удалено (доступ отозван).")
    except ApiClientError as exc:
        await callback.message.answer(f"Ошибка: {exc}")
    await callback.answer()


def run() -> None:
    if not settings.bot_token:
        raise RuntimeError("BOT_TOKEN is required")

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
    dp.include_router(router)

    # Ensure webhook is disabled; otherwise Telegram rejects getUpdates.
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)


def _run_webhook() -> None:
    bot = Bot(token=settings.bot_token)
    dp = Dispatcher()
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
