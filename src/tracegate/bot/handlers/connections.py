"""Create connection, connection page, re-issue, slots ("Дополнительно"), delete."""

from __future__ import annotations

from aiogram import F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery

from tracegate.bot import callbacks as cb
from tracegate.bot import context as ctx
from tracegate.bot import keyboards, nav, texts
from tracegate.bot.client import ApiClientError
from tracegate.bot.delivery import cleanup_related_messages, formats_for_revision, send_client_config
from tracegate.bot.handlers.devices import load_owned_device, render_device, render_devices, show_device
from tracegate.bot.handlers.start import Screen, show_error, show_outdated
from tracegate.bot.profiles import (
    connection_kind,
    connection_label,
    enabled_profile_specs,
    ensure_profile_enabled,
    profile,
)
from tracegate.services.connection_profiles import MAX_CONNECTIONS_PER_DEVICE

router = Router(name="connections")

# Older revoked revisions shown under "Дополнительно" (active ones are always shown).
MAX_REVOKED_SLOTS_SHOWN = 3

_MAKE_TO_SPEC = {
    cb.MAKE_ENTRY: ("entry", None),
    cb.MAKE_REALITY: ("reality", None),
    cb.MAKE_HYSTERIA_SALAMANDER: ("hysteria", "salamander"),
    cb.MAKE_HYSTERIA_GECKO: ("hysteria", "gecko"),
}


def _is_active(revision: dict) -> bool:
    return str(revision.get("status") or "").strip().lower() == "active"


def _slot(revision: dict) -> int:
    try:
        return int(revision.get("slot"))
    except (TypeError, ValueError):
        return 999


def current_revision(revisions: list[dict]) -> dict | None:
    active = [row for row in revisions if _is_active(row)]
    if not active:
        return None
    return sorted(active, key=lambda row: (_slot(row), str(row.get("created_at") or "")))[0]


def visible_revisions(revisions: list[dict]) -> list[dict]:
    active = sorted((row for row in revisions if _is_active(row)), key=_slot)
    revoked = sorted(
        (row for row in revisions if not _is_active(row)),
        key=lambda row: str(row.get("created_at") or ""),
        reverse=True,
    )
    return active + revoked[:MAX_REVOKED_SLOTS_SHOWN]


def _slot_status_label(revision: dict) -> str:
    if not _is_active(revision):
        return texts.SLOT_REVOKED
    return texts.SLOT_MAIN if _slot(revision) == 0 else texts.SLOT_RESERVE


async def load_owned_connection(telegram_id: int, connection_id: str) -> dict | None:
    if cb.normalize_uuid(connection_id) is None:
        return None
    try:
        connection = await ctx.api.get_connection(connection_id)
    except ApiClientError as exc:
        if exc.status_code in {404, 422}:
            return None
        raise
    if int(connection.get("user_id") or 0) != int(telegram_id):
        return None
    if str(connection.get("status") or "active").strip().lower() != "active":
        return None
    return connection


async def _load_owned_revision(telegram_id: int, revision_id: str) -> tuple[dict | None, dict | None]:
    try:
        revision = await ctx.api.get_revision(revision_id)
    except ApiClientError as exc:
        if exc.status_code in {404, 422}:
            return None, None
        raise
    connection = await load_owned_connection(telegram_id, str(revision.get("connection_id") or ""))
    if connection is None:
        return None, None
    return revision, connection


async def render_connection(connection: dict, *, status: str | None = None) -> Screen:
    connection_id = str(connection["id"])
    device_id = str(connection.get("device_id") or "")
    device_name = connection.get("device_name") or ""
    kind = connection_kind(connection)
    if kind == "legacy":
        text = texts.legacy_connection_screen(device_name)
        return texts.with_status(status, text), keyboards.connection_keyboard(connection_id, device_id, legacy=True)
    revisions = await ctx.api.list_revisions(connection_id)
    current = current_revision(revisions)
    text = texts.connection_screen(
        title=texts.connection_title(kind, connection_label(connection)),
        device_name=device_name,
        active_since=current.get("created_at") if current else None,
        formats=formats_for_revision(current),
    )
    keyboard = keyboards.connection_keyboard(connection_id, device_id, has_config=current is not None)
    return texts.with_status(status, text), keyboard


async def render_slots(connection: dict, *, status: str | None = None) -> Screen:
    revisions = visible_revisions(await ctx.api.list_revisions(str(connection["id"])))
    rows = [(_slot_status_label(row), row.get("created_at")) for row in revisions]
    text = texts.slots_screen(connection_label(connection), rows)
    return texts.with_status(status, text), keyboards.slots_keyboard(str(connection["id"]), revisions)


async def show_connection_screen(
    callback: CallbackQuery,
    connection_id: str | None,
    user: dict | None,
    *,
    status: str | None = None,
) -> dict | None:
    """Render the connection page; return the connection (None when missing)."""

    if connection_id is None:
        await show_outdated(callback, user)
        return None
    try:
        connection = await load_owned_connection(callback.from_user.id, connection_id)
        if connection is None:
            text, keyboard = await render_devices(callback.from_user.id, status=texts.ERR_CONNECTION_NOT_FOUND)
        else:
            text, keyboard = await render_connection(connection, status=status)
    except Exception as exc:  # noqa: BLE001
        await show_error(callback, exc, where="connection", fallback=texts.ERR_LOAD, user=user, back_callback=cb.DEVICES)
        return None
    await nav.show(callback, text, keyboard)
    return connection


async def _owned_connection_for_action(
    callback: CallbackQuery, prefix: str, user: dict | None, *, allow_legacy: bool = False
) -> dict | None:
    """Load the connection for an action button, or render the right fallback screen."""

    connection_id = cb.parse_id(callback.data, prefix)
    if connection_id is None:
        await show_outdated(callback, user)
        return None
    try:
        connection = await load_owned_connection(callback.from_user.id, connection_id)
    except Exception as exc:  # noqa: BLE001
        await show_error(callback, exc, where="connection_action", fallback=texts.ERR_LOAD, user=user)
        return None
    if connection is None:
        await show_connection_screen(callback, connection_id, user)
        return None
    if not allow_legacy and connection_kind(connection) == "legacy":
        await show_connection_screen(callback, connection_id, user, status=texts.ERR_RETIRED)
        return None
    return connection


# ----------------------------------------------------------------- create ---


async def _device_for_create(callback: CallbackQuery, prefix: str, user: dict | None) -> dict | None:
    device_id = cb.parse_id(callback.data, prefix)
    if device_id is None:
        await show_outdated(callback, user)
        return None
    return await _check_create_allowed(callback, device_id, user)


async def _check_create_allowed(callback: CallbackQuery, device_id: str, user: dict | None) -> dict | None:
    try:
        device = await load_owned_device(callback.from_user.id, device_id)
        if device is None:
            await show_device(callback, callback.from_user.id, device_id, user)
            return None
        connections = await ctx.api.list_connections(device_id)
    except Exception as exc:  # noqa: BLE001
        await show_error(callback, exc, where="create_check", fallback=texts.ERR_LOAD, user=user)
        return None
    if len(connections) >= MAX_CONNECTIONS_PER_DEVICE:
        # The device page body already explains the limit.
        await show_device(callback, callback.from_user.id, device_id, user)
        return None
    return device


@router.callback_query(F.data.startswith(cb.CONN_NEW_P))
async def create_menu(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    device = await _device_for_create(callback, cb.CONN_NEW_P, tracegate_user)
    if device is None:
        return
    enabled = enabled_profile_specs()
    await nav.show(
        callback,
        texts.create_connection_screen(device.get("name"), enabled),
        keyboards.create_connection_keyboard(str(device["id"]), enabled),
    )


@router.callback_query(F.data.startswith(cb.CONN_HYSTERIA_P))
async def hysteria_menu(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    device = await _device_for_create(callback, cb.CONN_HYSTERIA_P, tracegate_user)
    if device is None:
        return
    if "hysteria" not in enabled_profile_specs():
        await show_device(
            callback, callback.from_user.id, str(device["id"]), tracegate_user, status=texts.ERR_PROFILE_DISABLED
        )
        return
    await nav.show(callback, texts.HYSTERIA_OBFS_SCREEN, keyboards.hysteria_obfs_keyboard(str(device["id"])))


@router.callback_query(F.data.startswith(cb.CONN_MAKE_P))
async def create_connection(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    parsed = cb.parse_make(callback.data)
    if parsed is None:
        await show_outdated(callback, tracegate_user)
        return
    choice, device_id = parsed
    spec, obfs = _MAKE_TO_SPEC[choice]
    device = await _check_create_allowed(callback, device_id, tracegate_user)
    if device is None:
        return
    try:
        ensure_profile_enabled(spec)
        protocol, mode, variant = profile(spec)
        args = [callback.from_user.id, device_id, protocol, mode, variant, None]
        if obfs:
            args.append({"hysteria_obfs": obfs})
        connection, revision = await ctx.api.create_connection_and_revision(*args)
    except Exception as exc:  # noqa: BLE001
        await show_error(
            callback,
            exc,
            where="create_connection",
            fallback=texts.ERR_CREATE_CONNECTION,
            user=tracegate_user,
            back_callback=cb.device(device_id),
        )
        return
    connection = {**connection, "device_name": connection.get("device_name") or device.get("name")}
    label = connection_label(connection)
    try:
        text, keyboard = await render_connection(connection, status=texts.connection_created(label))
    except Exception as exc:  # noqa: BLE001 - the connection exists; still deliver the config
        nav.log_error("render_after_create", exc)
        text, keyboard = await render_device(device, status=texts.connection_created(label))
    await nav.show(callback, text, keyboard)
    await send_client_config(callback, revision, context="created", connection=connection)


# ------------------------------------------------------------- connection ---


@router.callback_query(F.data.startswith(cb.CONN_P))
async def connection_page(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    await show_connection_screen(callback, cb.parse_id(callback.data, cb.CONN_P), tracegate_user)


@router.callback_query(F.data.startswith(cb.CONN_SHOW_P))
async def show_config(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    connection = await _owned_connection_for_action(callback, cb.CONN_SHOW_P, tracegate_user)
    if connection is None:
        return
    connection_id = str(connection["id"])
    try:
        current = current_revision(await ctx.api.list_revisions(connection_id))
    except Exception as exc:  # noqa: BLE001
        await show_error(
            callback, exc, where="show_config", fallback=texts.ERR_SHOW_CONFIG, user=tracegate_user,
            back_callback=cb.connection(connection_id),
        )
        return
    if current is None:
        await show_connection_screen(callback, connection_id, tracegate_user)
        return
    await cleanup_related_messages(callback, connection_id=connection_id)
    await show_connection_screen(callback, connection_id, tracegate_user, status=texts.CONFIG_SENT)
    await send_client_config(callback, current, context="current", connection=connection)


@router.callback_query(F.data.startswith(cb.CONN_REISSUE_ASK_P))
async def confirm_reissue(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    connection = await _owned_connection_for_action(callback, cb.CONN_REISSUE_ASK_P, tracegate_user)
    if connection is None:
        return
    connection_id = str(connection["id"])
    await nav.show(
        callback,
        texts.reissue_confirm(connection_label(connection)),
        keyboards.confirm_keyboard(
            confirm_text=texts.BTN_CONFIRM_REISSUE,
            confirm_callback=cb.with_id(cb.CONN_REISSUE_P, connection_id),
            back_callback=cb.connection(connection_id),
        ),
    )


@router.callback_query(F.data.startswith(cb.CONN_REISSUE_P))
async def reissue(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    connection = await _owned_connection_for_action(callback, cb.CONN_REISSUE_P, tracegate_user)
    if connection is None:
        return
    connection_id = str(connection["id"])
    try:
        revision = await ctx.api.issue_revision(connection_id)
    except Exception as exc:  # noqa: BLE001
        await show_error(
            callback, exc, where="reissue", fallback=texts.ERR_REISSUE, user=tracegate_user,
            back_callback=cb.connection(connection_id),
        )
        return
    await cleanup_related_messages(callback, connection_id=connection_id)
    await show_connection_screen(callback, connection_id, tracegate_user, status=texts.REISSUED)
    await send_client_config(callback, revision, context="issued", connection=connection)


@router.callback_query(F.data.startswith(cb.CONN_ADVANCED_P))
async def advanced(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    connection = await _owned_connection_for_action(callback, cb.CONN_ADVANCED_P, tracegate_user)
    if connection is None:
        return
    try:
        text, keyboard = await render_slots(connection)
    except Exception as exc:  # noqa: BLE001
        await show_error(
            callback, exc, where="slots", fallback=texts.ERR_LOAD, user=tracegate_user,
            back_callback=cb.connection(str(connection["id"])),
        )
        return
    await nav.show(callback, text, keyboard)


# ------------------------------------------------------------------ slots ---


async def _revision_for_action(callback: CallbackQuery, prefix: str, user: dict | None) -> tuple[dict, dict] | None:
    revision_id = cb.parse_id(callback.data, prefix)
    if revision_id is None:
        await show_outdated(callback, user)
        return None
    try:
        revision, connection = await _load_owned_revision(callback.from_user.id, revision_id)
    except Exception as exc:  # noqa: BLE001
        await show_error(callback, exc, where="slot_action", fallback=texts.ERR_LOAD, user=user)
        return None
    if revision is None or connection is None:
        await nav.show(callback, texts.ERR_CONNECTION_NOT_FOUND, keyboards.back_home_keyboard(cb.DEVICES))
        return None
    if connection_kind(connection) == "legacy":
        await show_connection_screen(callback, str(connection["id"]), user, status=texts.ERR_RETIRED)
        return None
    return revision, connection


@router.callback_query(F.data.startswith(cb.SLOT_ACTIVATE_P))
async def activate_slot(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    loaded = await _revision_for_action(callback, cb.SLOT_ACTIVATE_P, tracegate_user)
    if loaded is None:
        return
    revision, connection = loaded
    try:
        await ctx.api.activate_revision(str(revision["id"]))
        text, keyboard = await render_slots(connection, status=texts.SLOT_ACTIVATED)
    except Exception as exc:  # noqa: BLE001
        await show_error(
            callback, exc, where="activate_slot", fallback=texts.ERR_SLOT, user=tracegate_user,
            back_callback=cb.with_id(cb.CONN_ADVANCED_P, connection["id"]),
        )
        return
    await nav.show(callback, text, keyboard)


@router.callback_query(F.data.startswith(cb.SLOT_REVOKE_ASK_P))
async def confirm_revoke_slot(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    loaded = await _revision_for_action(callback, cb.SLOT_REVOKE_ASK_P, tracegate_user)
    if loaded is None:
        return
    revision, connection = loaded
    try:
        revisions = await ctx.api.list_revisions(str(connection["id"]))
    except Exception as exc:  # noqa: BLE001
        await show_error(callback, exc, where="revoke_slot_ask", fallback=texts.ERR_LOAD, user=tracegate_user)
        return
    active_ids = {str(row.get("id")) for row in revisions if _is_active(row)}
    last_active = active_ids == {str(revision["id"])}
    await nav.show(
        callback,
        texts.slot_revoke_confirm(revision.get("created_at"), last_active=last_active),
        keyboards.confirm_keyboard(
            confirm_text=texts.BTN_CONFIRM_SLOT_REVOKE,
            confirm_callback=cb.with_id(cb.SLOT_REVOKE_P, revision["id"]),
            back_callback=cb.with_id(cb.CONN_ADVANCED_P, connection["id"]),
        ),
    )


@router.callback_query(F.data.startswith(cb.SLOT_REVOKE_P))
async def revoke_slot(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    loaded = await _revision_for_action(callback, cb.SLOT_REVOKE_P, tracegate_user)
    if loaded is None:
        return
    revision, connection = loaded
    revision_id = str(revision["id"])
    connection_id = str(connection["id"])
    try:
        await ctx.api.revoke_revision(revision_id)
    except Exception as exc:  # noqa: BLE001
        await show_error(
            callback, exc, where="revoke_slot", fallback=texts.ERR_SLOT, user=tracegate_user,
            back_callback=cb.with_id(cb.CONN_ADVANCED_P, connection_id),
        )
        return
    await cleanup_related_messages(callback, revision_id=revision_id)
    try:
        still_active = await load_owned_connection(callback.from_user.id, connection_id)
        if still_active is None:
            device = await load_owned_device(callback.from_user.id, str(connection.get("device_id") or ""))
            if device is None:
                text, keyboard = await render_devices(
                    callback.from_user.id, status=texts.SLOT_REVOKED_CONNECTION_GONE
                )
            else:
                text, keyboard = await render_device(device, status=texts.SLOT_REVOKED_CONNECTION_GONE)
        else:
            text, keyboard = await render_slots(still_active, status=texts.SLOT_REVOKED_DONE)
    except Exception as exc:  # noqa: BLE001
        await show_error(callback, exc, where="revoke_slot_render", fallback=texts.ERR_LOAD, user=tracegate_user)
        return
    await nav.show(callback, text, keyboard)


# ----------------------------------------------------------------- delete ---


@router.callback_query(F.data.startswith(cb.CONN_DELETE_ASK_P))
async def confirm_delete_connection(
    callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None
) -> None:
    await state.clear()
    connection = await _owned_connection_for_action(callback, cb.CONN_DELETE_ASK_P, tracegate_user, allow_legacy=True)
    if connection is None:
        return
    connection_id = str(connection["id"])
    await nav.show(
        callback,
        texts.connection_delete_confirm(connection_label(connection)),
        keyboards.confirm_keyboard(
            confirm_text=texts.BTN_CONFIRM_DELETE,
            confirm_callback=cb.with_id(cb.CONN_DELETE_P, connection_id),
            back_callback=cb.connection(connection_id),
        ),
    )


@router.callback_query(F.data.startswith(cb.CONN_DELETE_P))
async def delete_connection(callback: CallbackQuery, state: FSMContext, tracegate_user: dict | None = None) -> None:
    await state.clear()
    connection = await _owned_connection_for_action(callback, cb.CONN_DELETE_P, tracegate_user, allow_legacy=True)
    if connection is None:
        return
    connection_id = str(connection["id"])
    device_id = str(connection.get("device_id") or "")
    try:
        await ctx.api.delete_connection(connection_id)
    except Exception as exc:  # noqa: BLE001
        await show_error(
            callback, exc, where="delete_connection", fallback=texts.ERR_DELETE_CONNECTION, user=tracegate_user,
            back_callback=cb.connection(connection_id),
        )
        return
    await cleanup_related_messages(callback, connection_id=connection_id)
    await show_device(
        callback,
        callback.from_user.id,
        device_id,
        tracegate_user,
        status=texts.connection_deleted(connection_label(connection)),
    )
