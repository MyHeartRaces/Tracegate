from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup


def main_menu_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Устройства", callback_data="devices")],
            [InlineKeyboardButton(text="Добавить устройство", callback_data="add_device")],
        ]
    )


def devices_keyboard(devices: list[dict]) -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(text=device["name"], callback_data=f"device:{device['id']}")] for device in devices]
    rows.append([InlineKeyboardButton(text="Добавить устройство", callback_data="add_device")])
    rows.append([InlineKeyboardButton(text="Назад", callback_data="menu")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def device_actions_keyboard(device_id: str, connections: list[dict] | None = None) -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton(text="B1 VLESS direct", callback_data=f"new:b1:{device_id}")],
        [InlineKeyboardButton(text="B2 VLESS chain", callback_data=f"new:b2:{device_id}")],
        [InlineKeyboardButton(text="B3 Hysteria2", callback_data=f"new:b3:{device_id}")],
        [InlineKeyboardButton(text="B5 WireGuard", callback_data=f"new:b5:{device_id}")],
    ]
    for connection in connections or []:
        rows.append(
            [
                InlineKeyboardButton(
                    text=f"Ревизии {connection['variant']}",
                    callback_data=f"revs:{connection['id']}",
                )
            ]
        )
    rows.append([InlineKeyboardButton(text="Назад", callback_data="devices")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def sni_keyboard(spec: str, device_id: str, sni_rows: list[dict]) -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton(text=row["fqdn"], callback_data=f"sni:{spec}:{device_id}:{row['id']}")]
        for row in sni_rows
    ]
    rows.append([InlineKeyboardButton(text="Отмена", callback_data=f"device:{device_id}")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def issue_sni_keyboard(connection_id: str, sni_rows: list[dict]) -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton(text=row["fqdn"], callback_data=f"issuesni:{connection_id}:{row['id']}")]
        for row in sni_rows
    ]
    rows.append([InlineKeyboardButton(text="Отмена", callback_data=f"revs:{connection_id}")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def revisions_keyboard(connection_id: str, revisions: list[dict], is_vless: bool) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if is_vless:
        rows.append([InlineKeyboardButton(text="Новая ревизия (SNI)", callback_data=f"issuepick:{connection_id}")])
    else:
        rows.append([InlineKeyboardButton(text="Новая ревизия", callback_data=f"issueplain:{connection_id}")])
    for rev in revisions:
        rows.append(
            [
                InlineKeyboardButton(text=f"Activate slot0 {rev['slot']}", callback_data=f"activate:{rev['id']}"),
                InlineKeyboardButton(text="Revoke", callback_data=f"revoke:{rev['id']}"),
            ]
        )
    rows.append([InlineKeyboardButton(text="Обновить", callback_data=f"revs:{connection_id}")])
    return InlineKeyboardMarkup(inline_keyboard=rows)
