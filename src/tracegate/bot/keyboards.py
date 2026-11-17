"""Inline keyboards. Button texts come from ``texts``; payloads from ``callbacks``."""

from __future__ import annotations

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from tracegate.bot import callbacks as cb
from tracegate.bot import texts
from tracegate.bot.profiles import connection_kind, connection_label
from tracegate.services.connection_profiles import MAX_DEVICES_PER_USER


def _btn(text: str, callback_data: str) -> InlineKeyboardButton:
    return InlineKeyboardButton(text=text, callback_data=callback_data)


def _kb(rows: list[list[InlineKeyboardButton]]) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=rows)


def _home_row() -> list[InlineKeyboardButton]:
    return [_btn(texts.BTN_HOME, cb.MENU)]


def _back_home_row(back_callback: str) -> list[InlineKeyboardButton]:
    if back_callback == cb.MENU:
        return [_btn(texts.BTN_BACK, cb.MENU)]
    return [_btn(texts.BTN_BACK, back_callback), _btn(texts.BTN_HOME, cb.MENU)]


# ----------------------------------------------------------------- common ---


def home_keyboard() -> InlineKeyboardMarkup:
    return _kb([_home_row()])


def back_home_keyboard(back_callback: str) -> InlineKeyboardMarkup:
    return _kb([_back_home_row(back_callback)])


def cancel_keyboard(cancel_callback: str) -> InlineKeyboardMarkup:
    return _kb([[_btn(texts.BTN_CANCEL, cancel_callback)]])


def confirm_keyboard(*, confirm_text: str, confirm_callback: str, back_callback: str) -> InlineKeyboardMarkup:
    return _kb([[_btn(confirm_text, confirm_callback)], _back_home_row(back_callback)])


def welcome_keyboard(step: int) -> InlineKeyboardMarkup:
    if step == 1:
        return _kb([[_btn(texts.BTN_WELCOME_CONTINUE, cb.WELCOME_1)]])
    return _kb([[_btn(texts.BTN_WELCOME_ACCEPT, cb.WELCOME_2)]])


def main_menu_keyboard(*, is_admin: bool = False, grafana_enabled: bool = False) -> InlineKeyboardMarkup:
    rows = [
        [_btn(texts.BTN_DEVICES, cb.DEVICES)],
        [_btn(texts.BTN_TGP, cb.TGP)],
        [_btn(texts.BTN_GUIDE, cb.GUIDE)],
        [_btn(texts.BTN_FEEDBACK, cb.FEEDBACK)],
    ]
    if grafana_enabled:
        rows.append([_btn(texts.BTN_GRAFANA, cb.GRAFANA)])
    if is_admin:
        rows.append([_btn(texts.BTN_ADMIN, cb.ADMIN)])
    return _kb(rows)


# ---------------------------------------------------------------- devices ---


def devices_keyboard(devices: list[dict], connection_counts: dict[str, int] | None = None) -> InlineKeyboardMarkup:
    counts = connection_counts or {}
    rows = [
        [_btn(texts.device_button(device.get("name"), counts.get(str(device["id"]), 0)), cb.device(device["id"]))]
        for device in devices
    ]
    if len(devices) < MAX_DEVICES_PER_USER:
        rows.append([_btn(texts.BTN_ADD_DEVICE, cb.DEVICE_ADD)])
    rows.append(_home_row())
    return _kb(rows)


def device_keyboard(device_id: str, connections: list[dict], *, can_create: bool) -> InlineKeyboardMarkup:
    rows = [
        [
            _btn(
                texts.connection_button(connection_kind(connection), connection_label(connection)),
                cb.connection(connection["id"]),
            )
        ]
        for connection in connections
    ]
    if can_create:
        rows.append([_btn(texts.BTN_NEW_CONNECTION, cb.with_id(cb.CONN_NEW_P, device_id))])
    rows.append([_btn(texts.BTN_RENAME_DEVICE, cb.with_id(cb.DEVICE_RENAME_P, device_id))])
    rows.append([_btn(texts.BTN_DELETE_DEVICE, cb.with_id(cb.DEVICE_DELETE_ASK_P, device_id))])
    rows.append(_back_home_row(cb.DEVICES))
    return _kb(rows)


def create_connection_keyboard(device_id: str, enabled_specs: set[str]) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if "entry" in enabled_specs:
        rows.append([_btn(texts.BTN_MAKE_CHAIN, cb.make(cb.MAKE_ENTRY, device_id))])
    if "reality" in enabled_specs:
        rows.append([_btn(texts.BTN_MAKE_REALITY, cb.make(cb.MAKE_REALITY, device_id))])
    if "hysteria" in enabled_specs:
        rows.append([_btn(texts.BTN_MAKE_HYSTERIA, cb.with_id(cb.CONN_HYSTERIA_P, device_id))])
    rows.append(_back_home_row(cb.device(device_id)))
    return _kb(rows)


def hysteria_obfs_keyboard(device_id: str) -> InlineKeyboardMarkup:
    return _kb(
        [
            [_btn(texts.BTN_SALAMANDER, cb.make(cb.MAKE_HYSTERIA_SALAMANDER, device_id))],
            [_btn(texts.BTN_GECKO, cb.make(cb.MAKE_HYSTERIA_GECKO, device_id))],
            _back_home_row(cb.with_id(cb.CONN_NEW_P, device_id)),
        ]
    )


# ------------------------------------------------------------ connections ---


def connection_keyboard(
    connection_id: str,
    device_id: str,
    *,
    legacy: bool = False,
    has_config: bool = True,
) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if not legacy:
        if has_config:
            rows.append([_btn(texts.BTN_SHOW_CONFIG, cb.with_id(cb.CONN_SHOW_P, connection_id))])
        rows.append([_btn(texts.BTN_REISSUE, cb.with_id(cb.CONN_REISSUE_ASK_P, connection_id))])
        rows.append([_btn(texts.BTN_ADVANCED, cb.with_id(cb.CONN_ADVANCED_P, connection_id))])
    rows.append([_btn(texts.BTN_DELETE_CONNECTION, cb.with_id(cb.CONN_DELETE_ASK_P, connection_id))])
    rows.append(_back_home_row(cb.device(device_id)))
    return _kb(rows)


def slots_keyboard(connection_id: str, revisions: list[dict]) -> InlineKeyboardMarkup:
    """``revisions`` are already filtered/sorted rows with id, slot, status, created_at."""

    rows: list[list[InlineKeyboardButton]] = []
    for revision in revisions:
        revision_id = str(revision["id"])
        created_at = revision.get("created_at")
        active = str(revision.get("status") or "").strip().lower() == "active"
        if active:
            row = []
            if int(revision.get("slot") or 0) != 0:
                row.append(_btn(texts.slot_make_main_button(created_at), cb.with_id(cb.SLOT_ACTIVATE_P, revision_id)))
            row.append(_btn(texts.slot_revoke_button(created_at), cb.with_id(cb.SLOT_REVOKE_ASK_P, revision_id)))
            rows.append(row)
        else:
            rows.append([_btn(texts.slot_enable_button(created_at), cb.with_id(cb.SLOT_ACTIVATE_P, revision_id))])
    rows.append(_back_home_row(cb.connection(connection_id)))
    return _kb(rows)


def config_delivery_keyboard(*, connection_id: str, howto_callback: str = cb.GUIDE) -> InlineKeyboardMarkup:
    return _kb(
        [
            [_btn(texts.BTN_HOWTO, howto_callback)],
            [_btn(texts.BTN_TO_CONNECTION, cb.connection(connection_id))],
            _home_row(),
        ]
    )


# --------------------------------------------------------- telegram proxy ---


def tgp_keyboard() -> InlineKeyboardMarkup:
    return _kb(
        [
            [_btn(texts.BTN_TGP_SHOW, cb.TGP_SHOW)],
            [_btn(texts.BTN_TGP_ROTATE, cb.TGP_ROTATE)],
            [_btn(texts.BTN_TGP_REVOKE, cb.TGP_REVOKE_ASK)],
            _back_home_row(cb.MENU),
        ]
    )


# ------------------------------------------------------------------ guide ---


def guide_keyboard(children: list[tuple[str, str]], *, back_callback: str | None) -> InlineKeyboardMarkup:
    rows = [[_btn(text, callback_data)] for text, callback_data in children]
    rows.append(_back_home_row(back_callback) if back_callback else _home_row())
    return _kb(rows)


# ------------------------------------------------------- feedback/grafana ---


def feedback_keyboard() -> InlineKeyboardMarkup:
    return _kb([[_btn(texts.BTN_BACK, cb.MENU)]])


def grafana_keyboard(login_url: str | None) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    url = str(login_url or "").strip()
    if url:
        rows.append([InlineKeyboardButton(text=texts.BTN_GRAFANA_OPEN, url=url)])
    rows.append(_home_row())
    return _kb(rows)


# ------------------------------------------------------------------ admin ---


def admin_menu_keyboard(*, is_superadmin: bool) -> InlineKeyboardMarkup:
    rows = [
        [_btn(texts.BTN_ADMIN_USERS, cb.ADMIN_USERS)],
        [_btn(texts.BTN_ADMIN_TGP, cb.ADMIN_TGP)],
        [_btn(texts.BTN_ADMIN_REVOKE_ACCESS, cb.ADMIN_REVOKE_ACCESS)],
        [_btn(texts.BTN_ADMIN_BLOCK, cb.ADMIN_BLOCK)],
        [_btn(texts.BTN_ADMIN_UNBLOCK, cb.ADMIN_UNBLOCK)],
        [_btn(texts.BTN_ADMIN_RESET, cb.ADMIN_RESET_ASK)],
    ]
    if is_superadmin:
        rows.extend(
            [
                [_btn(texts.BTN_ADMIN_GRANT, cb.ADMIN_GRANT)],
                [_btn(texts.BTN_ADMIN_UNGRANT, cb.ADMIN_UNGRANT)],
                [_btn(texts.BTN_ADMIN_LIST, cb.ADMIN_LIST)],
            ]
        )
    rows.append(_home_row())
    return _kb(rows)


def admin_back_keyboard() -> InlineKeyboardMarkup:
    return _kb([[_btn(texts.BTN_ADMIN_BACK, cb.ADMIN), _btn(texts.BTN_HOME, cb.MENU)]])


def admin_cancel_keyboard() -> InlineKeyboardMarkup:
    return cancel_keyboard(cb.ADMIN)


def admin_tgp_keyboard() -> InlineKeyboardMarkup:
    return _kb(
        [
            [_btn(texts.BTN_ADMIN_REFRESH, cb.ADMIN_TGP)],
            [_btn(texts.BTN_ADMIN_TGP_REVOKE, cb.ADMIN_TGP_REVOKE)],
            [_btn(texts.BTN_ADMIN_BACK, cb.ADMIN), _btn(texts.BTN_HOME, cb.MENU)],
        ]
    )


def admin_notify_keyboard() -> InlineKeyboardMarkup:
    return _kb(
        [
            [_btn(texts.BTN_ADMIN_NOTIFY_YES, cb.ADMIN_NOTIFY_YES)],
            [_btn(texts.BTN_ADMIN_NOTIFY_NO, cb.ADMIN_NOTIFY_NO)],
            [_btn(texts.BTN_CANCEL, cb.ADMIN)],
        ]
    )


def admin_reset_keyboard() -> InlineKeyboardMarkup:
    return confirm_keyboard(
        confirm_text=texts.BTN_ADMIN_RESET_CONFIRM,
        confirm_callback=cb.ADMIN_RESET,
        back_callback=cb.ADMIN,
    )


def feedback_admin_keyboard(*, telegram_id: int) -> InlineKeyboardMarkup:
    return _kb([[_btn(texts.BTN_FEEDBACK_BLOCK, cb.with_id(cb.FEEDBACK_BLOCK_P, int(telegram_id)))]])
