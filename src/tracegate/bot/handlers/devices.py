"""Device list, device page, add / rename / delete device."""

from __future__ import annotations

from aiogram import F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from tracegate.bot import callbacks as cb
from tracegate.bot import context as ctx
from tracegate.bot import keyboards, nav, texts
from tracegate.bot.client import ApiClientError
from tracegate.bot.delivery import cleanup_related_messages
from tracegate.bot.handlers.start import Screen, show_error, show_outdated
from tracegate.bot.states import DeviceFlow
from tracegate.services.connection_profiles import MAX_CONNECTIONS_PER_DEVICE, MAX_DEVICES_PER_USER

router = Router(name="devices")


async def load_owned_device(telegram_id: int, device_id: str) -> dict | None:
    """The device when it exists, is active and belongs to ``telegram_id``."""

    if cb.normalize_uuid(device_id) is None:
        return None
    try:
        device = await ctx.api.get_device(device_id)
    except ApiClientError as exc:
        if exc.status_code in {404, 422}:
            return None
        raise
    if int(device.get("user_id") or 0) != int(telegram_id):
        return None
    if str(device.get("status") or "active").strip().lower() != "active":
        return None
    return device


async def render_devices(telegram_id: int, *, status: str | None = None) -> Screen:
    devices = await ctx.api.list_devices(int(telegram_id))
    counts: dict[str, int] = {}
    for device in devices:
        counts[str(device["id"])] = len(await ctx.api.list_connections(device["id"]))
    return texts.with_status(status, texts.devices_screen(devices)), keyboards.devices_keyboard(devices, counts)


async def render_device(device: dict, *, status: str | None = None) -> Screen:
    connections = await ctx.api.list_connections(device["id"])
    text = texts.with_status(status, texts.device_screen(device, connections))
    keyboard = keyboards.device_keyboard(
        str(device["id"]),
        connections,
        can_create=len(connections) < MAX_CONNECTIONS_PER_DEVICE,
    )
    return text, keyboard


async def show_devices(target: CallbackQuery | Message, telegram_id: int, user: dict | None, *, status=None) -> None:
    try:
        text, keyboard = await render_devices(telegram_id, status=status)
    except Exception as exc:  # noqa: BLE001
        await show_error(target, exc, where="devices", fallback=texts.ERR_LOAD, user=user)
        return
    await nav.show(target, text, keyboard)


async def show_device(
    target: CallbackQuery | Message,
    telegram_id: int,
    device_id: str,
    user: dict | None,
    *,
    status: str | None = None,
) -> None:
    try:
        device = await load_owned_device(telegram_id, device_id)
        if device is None:
            text, keyboard = await render_devices(telegram_id, status=texts.ERR_DEVICE_NOT_FOUND)
        else:
            text, keyboard = await render_device(device, status=status)
    except Exception as exc:  # noqa: BLE001
        await show_error(target, exc, where="device", fallback=texts.ERR_LOAD, user=user, back_callback=cb.DEVICES)
        return
    await nav.show(target, text, keyboard)


def _validate_device_name(raw: str | None) -> tuple[str | None, str | None]:
    name = " ".join(str(raw or "").split())
    if not name or name.startswith("/"):
        return None, texts.DEVICE_NAME_EMPTY
    if len(name) > texts.DEVICE_NAME_MAX_LENGTH:
        return None, texts.DEVICE_NAME_TOO_LONG
    return name, None


# ------------------------------------------------------------------- list ---


@router.callback_query(F.data == cb.DEVICES)
async def devices_list(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    await show_devices(callback, callback.from_user.id, tracegate_user)


@router.callback_query(F.data == cb.DEVICE_ADD)
async def add_device(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    try:
        devices = await ctx.api.list_devices(callback.from_user.id)
    except Exception as exc:  # noqa: BLE001
        await show_error(callback, exc, where="add_device", fallback=texts.ERR_LOAD, user=tracegate_user)
        return
    if len(devices) >= MAX_DEVICES_PER_USER:
        await show_devices(callback, callback.from_user.id, tracegate_user, status=texts.ERR_DEVICE_LIMIT)
        return
    await state.set_state(DeviceFlow.waiting_for_name)
    await nav.show(callback, texts.DEVICE_NAME_PROMPT, keyboards.cancel_keyboard(cb.DEVICES))


@router.message(DeviceFlow.waiting_for_name)
async def receive_device_name(message: Message, state: FSMContext, tracegate_user: dict | None = None) -> None:
    name, problem = _validate_device_name(message.text)
    if problem:
        await nav.send(message, problem, keyboards.cancel_keyboard(cb.DEVICES))
        return
    await state.clear()
    try:
        device = await ctx.api.create_device(message.from_user.id, name)
        text, keyboard = await render_device(device, status=texts.device_added(name))
    except Exception as exc:  # noqa: BLE001
        nav.log_error("create_device", exc)
        error = nav.user_error_text(exc, fallback=texts.ERR_ADD_DEVICE, admin=nav.is_admin_user(tracegate_user))
        await nav.send(message, error, keyboards.back_home_keyboard(cb.DEVICES))
        return
    await nav.send(message, text, keyboard)


# ----------------------------------------------------------------- device ---


@router.callback_query(F.data.startswith(cb.DEVICE_P))
async def device_page(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    device_id = cb.parse_id(callback.data, cb.DEVICE_P)
    if device_id is None:
        await show_outdated(callback, tracegate_user)
        return
    await show_device(callback, callback.from_user.id, device_id, tracegate_user)


@router.callback_query(F.data.startswith(cb.DEVICE_RENAME_P))
async def rename_device(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    device_id = cb.parse_id(callback.data, cb.DEVICE_RENAME_P)
    if device_id is None:
        await show_outdated(callback, tracegate_user)
        return
    try:
        device = await load_owned_device(callback.from_user.id, device_id)
    except Exception as exc:  # noqa: BLE001
        await show_error(callback, exc, where="rename_device", fallback=texts.ERR_LOAD, user=tracegate_user)
        return
    if device is None:
        await show_devices(callback, callback.from_user.id, tracegate_user, status=texts.ERR_DEVICE_NOT_FOUND)
        return
    await state.set_state(DeviceFlow.waiting_for_rename)
    await state.update_data(rename_device_id=device_id)
    await nav.show(callback, texts.device_rename_prompt(device.get("name")), keyboards.cancel_keyboard(cb.device(device_id)))


@router.message(DeviceFlow.waiting_for_rename)
async def receive_device_rename(message: Message, state: FSMContext, tracegate_user: dict | None = None) -> None:
    data = await state.get_data()
    device_id = cb.normalize_uuid(data.get("rename_device_id"))
    if device_id is None:
        await state.clear()
        await show_outdated(message, tracegate_user)
        return
    name, problem = _validate_device_name(message.text)
    if problem:
        await nav.send(message, problem, keyboards.cancel_keyboard(cb.device(device_id)))
        return
    await state.clear()
    try:
        device = await load_owned_device(message.from_user.id, device_id)
        if device is None:
            text, keyboard = await render_devices(message.from_user.id, status=texts.ERR_DEVICE_NOT_FOUND)
        else:
            renamed = await ctx.api.rename_device(device_id, name)
            text, keyboard = await render_device({**device, **(renamed or {})}, status=texts.device_renamed(name))
    except Exception as exc:  # noqa: BLE001
        nav.log_error("rename_device", exc)
        error = nav.user_error_text(exc, fallback=texts.ERR_RENAME_DEVICE, admin=nav.is_admin_user(tracegate_user))
        await nav.send(message, error, keyboards.back_home_keyboard(cb.device(device_id)))
        return
    await nav.send(message, text, keyboard)


@router.callback_query(F.data.startswith(cb.DEVICE_DELETE_ASK_P))
async def confirm_delete_device(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    device_id = cb.parse_id(callback.data, cb.DEVICE_DELETE_ASK_P)
    if device_id is None:
        await show_outdated(callback, tracegate_user)
        return
    try:
        device = await load_owned_device(callback.from_user.id, device_id)
    except Exception as exc:  # noqa: BLE001
        await show_error(callback, exc, where="delete_device_ask", fallback=texts.ERR_LOAD, user=tracegate_user)
        return
    if device is None:
        await show_devices(callback, callback.from_user.id, tracegate_user, status=texts.ERR_DEVICE_NOT_FOUND)
        return
    await nav.show(
        callback,
        texts.device_delete_confirm(device.get("name")),
        keyboards.confirm_keyboard(
            confirm_text=texts.BTN_CONFIRM_DELETE,
            confirm_callback=cb.with_id(cb.DEVICE_DELETE_P, device_id),
            back_callback=cb.device(device_id),
        ),
    )


@router.callback_query(F.data.startswith(cb.DEVICE_DELETE_P))
async def delete_device(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    device_id = cb.parse_id(callback.data, cb.DEVICE_DELETE_P)
    if device_id is None:
        await show_outdated(callback, tracegate_user)
        return
    try:
        device = await load_owned_device(callback.from_user.id, device_id)
        if device is None:
            await show_devices(callback, callback.from_user.id, tracegate_user, status=texts.ERR_DEVICE_NOT_FOUND)
            return
        await ctx.api.delete_device(device_id)
    except Exception as exc:  # noqa: BLE001
        await show_error(
            callback,
            exc,
            where="delete_device",
            fallback=texts.ERR_DELETE_DEVICE,
            user=tracegate_user,
            back_callback=cb.device(device_id),
        )
        return
    await cleanup_related_messages(callback, device_id=device_id)
    await show_devices(callback, callback.from_user.id, tracegate_user, status=texts.device_deleted(device.get("name")))
