from __future__ import annotations

import asyncio
import ssl
from pathlib import Path

from aiogram import Bot, Dispatcher, F, Router
from aiogram.exceptions import TelegramBadRequest
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
    SNI_PAGE_SIZE,
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
)
from tracegate.client_export.v2rayn import V2RayNExportError, export_v2rayn
from tracegate.enums import ConnectionMode, ConnectionProtocol, ConnectionVariant
from tracegate.settings import get_settings

settings = get_settings()
api = TracegateApiClient(settings.bot_api_base_url, settings.bot_api_token)
router = Router()


class DeviceFlow(StatesGroup):
    waiting_for_name = State()


class SniCatalogFlow(StatesGroup):
    waiting_for_input = State()


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
async def menu(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await callback.message.edit_text("Tracegate v0.1\nВыберите действие:", reply_markup=main_menu_keyboard())
    await callback.answer()


@router.callback_query(F.data == "devices")
async def list_devices(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
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
        devices = await api.list_devices(user["id"])
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
            user["id"],
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
        devices = await api.list_devices(user["id"])

        vless_connections: list[dict] = []
        for dev in devices:
            for conn in await api.list_connections(dev["id"]):
                if conn.get("protocol") != ConnectionProtocol.VLESS_REALITY.value:
                    continue
                label = f"{dev['name']} | {conn.get('variant')} | {conn.get('mode')}"
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
