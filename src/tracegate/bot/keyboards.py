from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from tracegate.enums import ConnectionMode, ConnectionProtocol

PROVIDER_CHOICES: list[tuple[str, str]] = [
    ("Все", "all"),
    ("МТС", "mts"),
    ("Мегафон", "megafon"),
    ("T2", "t2"),
    ("Тмобайл", "tmobile"),
    ("РТК", "rtk"),
    ("Yota", "yota"),
]

SNI_PAGE_SIZE = 20


def main_menu_keyboard(*, is_admin: bool = False) -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton(text="Устройства", callback_data="devices")],
        [InlineKeyboardButton(text="Добавить устройство", callback_data="add_device")],
        [InlineKeyboardButton(text="Каталог SNI", callback_data="sni_catalog")],
        [InlineKeyboardButton(text="Статистика (Grafana)", callback_data="grafana_otp")],
    ]
    if is_admin:
        rows.append([InlineKeyboardButton(text="Админ", callback_data="admin_menu")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def admin_menu_keyboard(*, is_superadmin: bool) -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton(text="Grafana (OTP, admin)", callback_data="grafana_otp_admin")],
        [InlineKeyboardButton(text="Список пользователей", callback_data="admin_users")],
        [InlineKeyboardButton(text="Блокировать пользователя", callback_data="admin_user_block")],
        [InlineKeyboardButton(text="Снять блокировку", callback_data="admin_user_unblock")],
        [InlineKeyboardButton(text="Reset connections (ALL)", callback_data="admin_reset_connections")],
    ]
    if is_superadmin:
        rows.extend(
            [
                [InlineKeyboardButton(text="Выдать admin", callback_data="admin_grant")],
                [InlineKeyboardButton(text="Снять admin", callback_data="admin_revoke")],
                [InlineKeyboardButton(text="Список admins", callback_data="admin_list")],
            ]
        )
    rows.append([InlineKeyboardButton(text="Меню", callback_data="menu")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


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
    def _title(conn: dict) -> str:
        protocol = (conn.get("protocol") or "").strip().lower()
        mode = (conn.get("mode") or "").strip().lower()
        if protocol == ConnectionProtocol.VLESS_REALITY.value:
            return "VLESS Reality Chain" if mode == ConnectionMode.CHAIN.value else "VLESS Reality Direct"
        if protocol == ConnectionProtocol.VLESS_WS_TLS.value:
            return "VLESS TLS Chain" if mode == ConnectionMode.CHAIN.value else "VLESS TLS Direct"
        if protocol == ConnectionProtocol.HYSTERIA2.value:
            return "Hysteria2"
        if protocol == ConnectionProtocol.WIREGUARD.value:
            return "WireGuard"
        return f"{conn.get('variant')} ({conn.get('protocol')})"

    rows = [
        [InlineKeyboardButton(text="B1 - VLESS Direct", callback_data=f"vlessnew:b1:{device_id}")],
        [InlineKeyboardButton(text="B2 - VLESS Chain (через VPS-E)", callback_data=f"vlessnew:b2:{device_id}")],
        [InlineKeyboardButton(text="B3 - Hysteria2 (UDP/QUIC)", callback_data=f"new:b3:{device_id}")],
        [InlineKeyboardButton(text="B5 - WireGuard", callback_data=f"new:b5:{device_id}")],
    ]
    for connection in connections or []:
        variant = (connection.get("variant") or "").strip()
        label = (connection.get("alias") or "").strip() or _title(connection)
        if variant:
            label = f"{variant} - {label}"
        if len(label) > 52:
            label = label[:49].rstrip() + "..."
        rows.append(
            [
                InlineKeyboardButton(
                    text=f"Ревизии {label}",
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


def vless_transport_keyboard(*, spec: str, device_id: str) -> InlineKeyboardMarkup:
    # spec: "b1" | "b2" (direct/chain profile)
    # B2 chain has no transport choice (Reality is auto-selected in handler).
    rows: list[list[InlineKeyboardButton]] = []
    if spec == "b1":
        rows.append([InlineKeyboardButton(text="Reality (выбор SNI)", callback_data=f"vlesstrans:{spec}:{device_id}:reality")])
        rows.append([InlineKeyboardButton(text="TLS (WS, SNI=сертификат)", callback_data=f"vlesstrans:{spec}:{device_id}:tls")])
    rows.append([InlineKeyboardButton(text="Отмена", callback_data=f"device:{device_id}")])
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


def revisions_keyboard(connection_id: str, revisions: list[dict], is_vless: bool, device_id: str) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if is_vless:
        rows.append([InlineKeyboardButton(text="Новая ревизия (SNI)", callback_data=f"issuepick:{connection_id}")])
    else:
        rows.append([InlineKeyboardButton(text="Новая ревизия", callback_data=f"issueplain:{connection_id}")])
    for rev in revisions:
        rows.append(
            [
                InlineKeyboardButton(text=f"Сделать активной (slot {rev['slot']})", callback_data=f"activate:{rev['id']}"),
                InlineKeyboardButton(text="Удалить", callback_data=f"revoke:{rev['id']}"),
            ]
        )
    rows.append([InlineKeyboardButton(text="Обновить", callback_data=f"revs:{connection_id}")])
    rows.append([InlineKeyboardButton(text="Назад", callback_data=f"device:{device_id}")])
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


def sni_catalog_pick_keyboard(
    *,
    provider: str,
    page: int,
    page_count: int,
    has_query: bool,
) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    nav: list[InlineKeyboardButton] = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="<<", callback_data=f"cat:{provider}:{page-1}"))
    nav.append(InlineKeyboardButton(text=f"{page+1}/{page_count}", callback_data="noop"))
    if page + 1 < page_count:
        nav.append(InlineKeyboardButton(text=">>", callback_data=f"cat:{provider}:{page+1}"))
    rows.append(nav)
    if has_query:
        rows.append([InlineKeyboardButton(text="Сброс поиска", callback_data="catreset")])
    rows.append([InlineKeyboardButton(text="Провайдеры", callback_data="sni_catalog")])
    rows.append([InlineKeyboardButton(text="Меню", callback_data="menu")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def sni_catalog_action_keyboard(*, sni_id: int, provider: str, page: int) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = [
        [InlineKeyboardButton(text="Создать VLESS Direct", callback_data=f"catnewpick:b1:{sni_id}:{provider}:{page}")],
        [InlineKeyboardButton(text="Создать VLESS Chain", callback_data=f"catnewpick:b2:{sni_id}:{provider}:{page}")],
        [InlineKeyboardButton(text="Новая ревизия для VLESS", callback_data=f"catissuepick:{sni_id}:{provider}:{page}")],
        [InlineKeyboardButton(text="Назад", callback_data=f"cat:{provider}:{page}")],
        [InlineKeyboardButton(text="Меню", callback_data="menu")],
    ]
    return InlineKeyboardMarkup(inline_keyboard=rows)


def sni_catalog_device_pick_keyboard(
    *,
    spec: str,
    sni_id: int,
    devices: list[dict],
    provider: str,
    page: int,
) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    for dev in devices:
        rows.append(
            [
                InlineKeyboardButton(
                    text=dev["name"],
                    callback_data=f"catnew:{spec}:{dev['id']}:{sni_id}",
                )
            ]
        )
    rows.append([InlineKeyboardButton(text="Назад", callback_data=f"catsel:{sni_id}:{provider}:{page}")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def sni_catalog_connection_pick_keyboard(
    *,
    sni_id: int,
    vless_connections: list[dict],
    provider: str,
    page: int,
) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    for conn in vless_connections:
        rows.append(
            [
                InlineKeyboardButton(
                    text=conn["label"],
                    callback_data=f"catissue:{conn['id']}:{sni_id}",
                )
            ]
        )
    rows.append([InlineKeyboardButton(text="Назад", callback_data=f"catsel:{sni_id}:{provider}:{page}")])
    return InlineKeyboardMarkup(inline_keyboard=rows)
