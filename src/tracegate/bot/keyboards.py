from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup


PROVIDER_CHOICES: list[tuple[str, str]] = [
    ("Все", "all"),
    ("МТС", "mts"),
    ("Мегафон", "megafon"),
    ("T2", "t2"),
    ("Тмобайл", "tmobile"),
    ("РТК", "rtk"),
    ("Yota", "yota"),
    ("Beeline", "beeline"),
    ("Без тега", "other"),
]

SNI_PAGE_SIZE = 20


def main_menu_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Устройства", callback_data="devices")],
            [InlineKeyboardButton(text="Добавить устройство", callback_data="add_device")],
            [InlineKeyboardButton(text="Каталог SNI", callback_data="sni_catalog")],
        ]
    )


def devices_keyboard(devices: list[dict]) -> InlineKeyboardMarkup:
    rows = [
        [
            InlineKeyboardButton(text=device["name"], callback_data=f"device:{device['id']}"),
            InlineKeyboardButton(text="Удалить", callback_data=f"deldev:{device['id']}"),
        ]
        for device in devices
    ]
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
                ),
                InlineKeyboardButton(
                    text="Удалить",
                    # Keep callback_data <= 64 bytes (Telegram limit). A UUID is 36 chars.
                    callback_data=f"delconn:{connection['id']}",
                ),
            ]
        )
    rows.append([InlineKeyboardButton(text="Назад", callback_data="devices")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def sni_keyboard(spec: str, device_id: str, sni_rows: list[dict]) -> InlineKeyboardMarkup:
    rows = [
        [
            InlineKeyboardButton(
                text=row["fqdn"],
                callback_data=f"sni:{spec}:{device_id}:{row['id']}",
            )
        ]
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


def provider_keyboard(context: str, target_id: str) -> InlineKeyboardMarkup:
    # context: "new" or "issue"
    rows = [
        [InlineKeyboardButton(text=label, callback_data=f"prov:{context}:{target_id}:{code}")]
        for (label, code) in PROVIDER_CHOICES
    ]
    rows.append([InlineKeyboardButton(text="Отмена", callback_data="devices")])
    return InlineKeyboardMarkup(inline_keyboard=rows)

def provider_keyboard_with_cancel(context: str, target_id: str, *, cancel_callback_data: str) -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton(text=label, callback_data=f"prov:{context}:{target_id}:{code}")]
        for (label, code) in PROVIDER_CHOICES
    ]
    rows.append([InlineKeyboardButton(text="Отмена", callback_data=cancel_callback_data)])
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


def sni_page_keyboard_new(
    *,
    spec: str,
    device_id: str,
    provider: str,
    page: int,
    page_count: int,
    sni_rows_page: list[dict],
) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    for row in sni_rows_page:
        rows.append(
            [
                InlineKeyboardButton(
                    text=row["fqdn"],
                    callback_data=f"sni:{spec}:{device_id}:{row['id']}",
                )
            ]
        )

    nav: list[InlineKeyboardButton] = []
    if page > 0:
        nav.append(
            InlineKeyboardButton(
                text="<<",
                callback_data=f"snipage:new:{spec}:{device_id}:{provider}:{page-1}",
            )
        )
    nav.append(InlineKeyboardButton(text=f"{page+1}/{page_count}", callback_data="noop"))
    if page + 1 < page_count:
        nav.append(
            InlineKeyboardButton(
                text=">>",
                callback_data=f"snipage:new:{spec}:{device_id}:{provider}:{page+1}",
            )
        )
    rows.append(nav)
    rows.append([InlineKeyboardButton(text="Провайдеры", callback_data=f"new:{spec}:{device_id}")])
    rows.append([InlineKeyboardButton(text="Отмена", callback_data=f"device:{device_id}")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def sni_page_keyboard_issue(
    *,
    connection_id: str,
    provider: str,
    page: int,
    page_count: int,
    sni_rows_page: list[dict],
) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    for row in sni_rows_page:
        rows.append(
            [
                InlineKeyboardButton(
                    text=row["fqdn"],
                    callback_data=f"issuesni:{connection_id}:{row['id']}",
                )
            ]
        )

    nav: list[InlineKeyboardButton] = []
    if page > 0:
        nav.append(
            InlineKeyboardButton(
                text="<<",
                callback_data=f"snipage:issue:{connection_id}:{provider}:{page-1}",
            )
        )
    nav.append(InlineKeyboardButton(text=f"{page+1}/{page_count}", callback_data="noop"))
    if page + 1 < page_count:
        nav.append(
            InlineKeyboardButton(
                text=">>",
                callback_data=f"snipage:issue:{connection_id}:{provider}:{page+1}",
            )
        )
    rows.append(nav)
    rows.append([InlineKeyboardButton(text="Провайдеры", callback_data=f"issuepick:{connection_id}")])
    rows.append([InlineKeyboardButton(text="Отмена", callback_data=f"revs:{connection_id}")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def sni_catalog_nav_keyboard(*, provider: str, page: int, page_count: int) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    nav: list[InlineKeyboardButton] = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="<<", callback_data=f"cat:{provider}:{page-1}"))
    nav.append(InlineKeyboardButton(text=f"{page+1}/{page_count}", callback_data="noop"))
    if page + 1 < page_count:
        nav.append(InlineKeyboardButton(text=">>", callback_data=f"cat:{provider}:{page+1}"))
    rows.append(nav)
    rows.append([InlineKeyboardButton(text="Провайдеры", callback_data="sni_catalog")])
    rows.append([InlineKeyboardButton(text="Меню", callback_data="menu")])
    return InlineKeyboardMarkup(inline_keyboard=rows)
