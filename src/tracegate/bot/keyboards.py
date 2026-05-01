from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from tracegate.services.connection_profiles import connection_profile_display_label

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
        [InlineKeyboardButton(text="🔌 Подключения", callback_data="connections")],
        [InlineKeyboardButton(text="📱 Устройства", callback_data="devices")],
        [InlineKeyboardButton(text="📚 Справка", callback_data="guide_open")],
        [InlineKeyboardButton(text="🔐 Telegram Proxy", callback_data="mtproto_open")],
        [InlineKeyboardButton(text="📊 Grafana", callback_data="grafana_otp")],
        [InlineKeyboardButton(text="💬 Обратная связь", callback_data="feedback_start")],
    ]
    if is_admin:
        rows.append([InlineKeyboardButton(text="🛠️ Управление", callback_data="admin_menu")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def help_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🏠 Меню", callback_data="menu")],
        ]
    )


def guide_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🏠 Меню", callback_data="menu")],
        ]
    )


def cancel_only_keyboard(*, cancel_callback_data: str, cancel_text: str = "↩️ Отмена") -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=cancel_text, callback_data=cancel_callback_data)],
        ]
    )


def admin_menu_keyboard(*, is_superadmin: bool) -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton(text="👥 Сводка пользователей", callback_data="admin_users")],
        [InlineKeyboardButton(text="🔐 Telegram Proxy доступы", callback_data="admin_mtproto")],
        [InlineKeyboardButton(text="⛔ Отозвать доступ", callback_data="admin_user_revoke_access")],
        [InlineKeyboardButton(text="🚫 Заблокировать", callback_data="admin_user_block")],
        [InlineKeyboardButton(text="✅ Снять блокировку", callback_data="admin_user_unblock")],
        [InlineKeyboardButton(text="🧹 Глобальный отзыв", callback_data="admin_reset_connections")],
    ]
    if is_superadmin:
        rows.extend(
            [
                [InlineKeyboardButton(text="➕ Назначить администратора", callback_data="admin_grant")],
                [InlineKeyboardButton(text="➖ Снять администратора", callback_data="admin_revoke")],
                [InlineKeyboardButton(text="👤 Список администраторов", callback_data="admin_list")],
            ]
        )
    rows.append([InlineKeyboardButton(text="🏠 Меню", callback_data="menu")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def admin_mtproto_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🔄 Обновить", callback_data="admin_mtproto")],
            [InlineKeyboardButton(text="⛔ Отозвать Telegram Proxy", callback_data="admin_mtproto_revoke")],
            [InlineKeyboardButton(text="🛠️ Управление", callback_data="admin_menu")],
        ]
    )


def feedback_admin_keyboard(*, telegram_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🚫 Заблокировать автора", callback_data=f"feedback_block:{int(telegram_id)}")]
        ]
    )


def admin_user_revoke_notify_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="✅ Да", callback_data="admin_user_revoke_notify:yes")],
            [InlineKeyboardButton(text="↩️ Нет", callback_data="admin_user_revoke_notify:no")],
            [InlineKeyboardButton(text="↩️ Отмена", callback_data="admin_menu")],
        ]
    )


def confirm_action_keyboard(
    *,
    confirm_callback_data: str,
    cancel_callback_data: str,
    confirm_text: str = "✅ Подтвердить",
    cancel_text: str = "↩️ Назад",
) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=confirm_text, callback_data=confirm_callback_data)],
            [InlineKeyboardButton(text=cancel_text, callback_data=cancel_callback_data)],
        ]
    )


def config_delivery_keyboard(*, connection_id: str, device_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🧩 К подключению", callback_data=f"revs:{connection_id}")],
            [InlineKeyboardButton(text="🔌 К подключениям", callback_data="connections")],
        ]
    )


def mtproto_delivery_keyboard(*, allow_revoke: bool = True) -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton(text="🔁 Показать снова", callback_data="mtproto_open")],
        [InlineKeyboardButton(text="🔄 Ротировать секрет", callback_data="mtproto_rotate")],
    ]
    if allow_revoke:
        rows.append([InlineKeyboardButton(text="⛔ Отозвать доступ", callback_data="mtproto_revoke")])
    rows.append([InlineKeyboardButton(text="🏠 Меню", callback_data="menu")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def devices_keyboard(devices: list[dict], *, active_device_id: str | None = None) -> InlineKeyboardMarkup:
    rows = [
        [
            InlineKeyboardButton(
                text=f"✓ {device['name']}" if str(device.get("id")) == str(active_device_id) else str(device.get("name") or "Без имени"),
                callback_data=f"device:{device['id']}",
            ),
            InlineKeyboardButton(text="🗑️ Удалить", callback_data=f"deldevask:{device['id']}"),
        ]
        for device in devices
    ]
    rows.append([InlineKeyboardButton(text="➕ Добавить устройство", callback_data="add_device")])
    rows.append([InlineKeyboardButton(text="🏠 Меню", callback_data="menu")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def _connection_button_label(connection: dict) -> str:
    try:
        label = connection_profile_display_label(connection["protocol"], connection["mode"], connection["variant"])
    except Exception:
        label = f"{connection.get('variant')} ({connection.get('protocol')})"
    alias = str(connection.get("alias") or "").strip()
    if alias:
        label = f"{label} | {alias}"
    if len(label) > 52:
        label = label[:49].rstrip() + "..."
    return label


def connections_keyboard(connections: list[dict] | None = None, *, can_create: bool = True) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if can_create:
        rows.append([InlineKeyboardButton(text="➕ Создать подключение", callback_data="conn_create")])
    for connection in connections or []:
        rows.append(
            [
                InlineKeyboardButton(
                    text=_connection_button_label(connection),
                    callback_data=f"revs:{connection['id']}",
                ),
                InlineKeyboardButton(
                    text="🗑️ Удалить",
                    # Keep callback_data <= 64 bytes (Telegram limit). A UUID is 36 chars.
                    callback_data=f"delconnask:{connection['id']}",
                ),
            ]
        )
    rows.append([InlineKeyboardButton(text="📱 Устройства", callback_data="devices")])
    rows.append([InlineKeyboardButton(text="🏠 Меню", callback_data="menu")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def connection_create_categories_keyboard() -> InlineKeyboardMarkup:
    return connection_create_categories_keyboard_for(enabled_specs=None)


def connection_create_categories_keyboard_for(*, enabled_specs: set[str] | None = None) -> InlineKeyboardMarkup:
    enabled = enabled_specs
    return InlineKeyboardMarkup(
        inline_keyboard=[
            *(
                [[InlineKeyboardButton(text="⚡ Direct", callback_data="conncat:direct")]]
                if enabled is None or enabled & {"v1direct", "v2direct", "v3direct"}
                else []
            ),
            *(
                [[InlineKeyboardButton(text="⛓️ Chain", callback_data="conncat:chain")]]
                if enabled is None or enabled & {"v1chain", "v2chain", "v3chain"}
                else []
            ),
            *(
                [[InlineKeyboardButton(text="🧰 Other", callback_data="conncat:other")]]
                if enabled is None or enabled & {"v0ws", "v0grpc", "v0wgws"}
                else []
            ),
            [InlineKeyboardButton(text="↩️ Назад", callback_data="connections")],
        ]
    )


def connection_create_profiles_keyboard(
    *,
    category: str,
    device_id: str,
    enabled_specs: set[str] | None = None,
) -> InlineKeyboardMarkup:
    def add_row(rows: list[list[InlineKeyboardButton]], spec: str, text: str) -> None:
        if enabled_specs is None or spec in enabled_specs:
            rows.append([InlineKeyboardButton(text=text, callback_data=f"new:{spec}:{device_id}")])

    rows: list[list[InlineKeyboardButton]] = []
    if category == "direct":
        add_row(rows, "v1direct", "V1-Direct-Reality-VLESS")
        add_row(rows, "v2direct", "V2-Direct-QUIC-Hysteria")
        add_row(rows, "v3direct", "V3-Direct-ShadowTLS-Shadowsocks")
    elif category == "chain":
        add_row(rows, "v1chain", "V1-Chain-Reality-VLESS")
        add_row(rows, "v2chain", "V2-Chain-QUIC-Hysteria")
        add_row(rows, "v3chain", "V3-Chain-ShadowTLS-Shadowsocks")
    else:
        add_row(rows, "v0ws", "V0-WS-VLESS")
        add_row(rows, "v0grpc", "V0-gRPC-VLESS")
        add_row(rows, "v0wgws", "V0-WGWS-WireGuard")
    rows.append([InlineKeyboardButton(text="↩️ Назад", callback_data="conn_create")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def device_actions_keyboard(device_id: str, connections: list[dict] | None = None) -> InlineKeyboardMarkup:
    return connections_keyboard(connections, can_create=True)


def vless_transport_keyboard(*, spec: str, device_id: str) -> InlineKeyboardMarkup:
    # Legacy compatibility keyboard for old callback paths.
    rows: list[list[InlineKeyboardButton]] = []
    if spec in {"v1", "v1direct"}:
        rows.append([InlineKeyboardButton(text="🛡️ Reality (выбор SNI)", callback_data=f"vlesstrans:{spec}:{device_id}:reality")])
    rows.append([InlineKeyboardButton(text="↩️ Отмена", callback_data="connections")])
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
    rows.append([InlineKeyboardButton(text="↩️ Отмена", callback_data="connections")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def issue_sni_keyboard(connection_id: str, sni_rows: list[dict]) -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton(text=row["fqdn"], callback_data=f"issuesni:{connection_id}:{row['id']}")]
        for row in sni_rows
    ]
    rows.append([InlineKeyboardButton(text="↩️ Отмена", callback_data=f"revs:{connection_id}")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def provider_keyboard(context: str, target_id: str) -> InlineKeyboardMarkup:
    # context: "new" or "issue"
    rows = [
        [InlineKeyboardButton(text=label, callback_data=f"prov:{context}:{target_id}:{code}")]
        for (label, code) in PROVIDER_CHOICES
    ]
    rows.append([InlineKeyboardButton(text="↩️ Отмена", callback_data="connections")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def provider_keyboard_with_cancel(context: str, target_id: str, *, cancel_callback_data: str) -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton(text=label, callback_data=f"prov:{context}:{target_id}:{code}")]
        for (label, code) in PROVIDER_CHOICES
    ]
    rows.append([InlineKeyboardButton(text="↩️ Отмена", callback_data=cancel_callback_data)])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def revisions_keyboard(connection_id: str, revisions: list[dict], is_vless: bool, device_id: str) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if is_vless:
        rows.append([InlineKeyboardButton(text="➕ Новая ревизия (SNI)", callback_data=f"issuepick:{connection_id}")])
    else:
        rows.append([InlineKeyboardButton(text="➕ Новая ревизия", callback_data=f"issueplain:{connection_id}")])
    if revisions:
        rows.append([InlineKeyboardButton(text="📄 Текущий конфиг", callback_data=f"showcur:{connection_id}")])
    for rev in revisions:
        rows.append(
            [
                InlineKeyboardButton(text=f"✅ Активировать слот {rev['slot']}", callback_data=f"activate:{rev['id']}"),
                InlineKeyboardButton(text="🗑️ Удалить", callback_data=f"revokeask:{rev['id']}"),
            ]
        )
    rows.append([InlineKeyboardButton(text="🔄 Обновить", callback_data=f"revs:{connection_id}")])
    rows.append([InlineKeyboardButton(text="↩️ Назад", callback_data="connections")])
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
    rows.append([InlineKeyboardButton(text="🧭 Провайдеры", callback_data=f"new:{spec}:{device_id}")])
    rows.append([InlineKeyboardButton(text="↩️ Отмена", callback_data="connections")])
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
    rows.append([InlineKeyboardButton(text="🧭 Провайдеры", callback_data=f"issuepick:{connection_id}")])
    rows.append([InlineKeyboardButton(text="↩️ Отмена", callback_data=f"revs:{connection_id}")])
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
    rows.append([InlineKeyboardButton(text="🧭 Провайдеры", callback_data="sni_catalog")])
    rows.append([InlineKeyboardButton(text="🏠 Меню", callback_data="menu")])
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
        rows.append([InlineKeyboardButton(text="🔄 Сброс поиска", callback_data="catreset")])
    rows.append([InlineKeyboardButton(text="🧭 Провайдеры", callback_data="sni_catalog")])
    rows.append([InlineKeyboardButton(text="🏠 Меню", callback_data="menu")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def sni_catalog_action_keyboard(
    *,
    sni_id: int,
    provider: str,
    page: int,
    enabled_specs: set[str] | None = None,
) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if enabled_specs is None or "v1direct" in enabled_specs:
        rows.append(
            [
                InlineKeyboardButton(
                    text="➕ Создать V1-Direct-Reality-VLESS",
                    callback_data=f"catnewpick:v1direct:{sni_id}:{provider}:{page}",
                )
            ]
        )
    if enabled_specs is None or "v1chain" in enabled_specs:
        rows.append(
            [
                InlineKeyboardButton(
                    text="➕ Создать V1-Chain-Reality-VLESS",
                    callback_data=f"catnewpick:v1chain:{sni_id}:{provider}:{page}",
                )
            ]
        )
    rows.extend(
        [
            [InlineKeyboardButton(text="🧩 Новая ревизия для VLESS", callback_data=f"catissuepick:{sni_id}:{provider}:{page}")],
            [InlineKeyboardButton(text="↩️ Назад", callback_data=f"cat:{provider}:{page}")],
            [InlineKeyboardButton(text="🏠 Меню", callback_data="menu")],
        ]
    )
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
    rows.append([InlineKeyboardButton(text="↩️ Назад", callback_data=f"catsel:{sni_id}:{provider}:{page}")])
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
    rows.append([InlineKeyboardButton(text="↩️ Назад", callback_data=f"catsel:{sni_id}:{provider}:{page}")])
    return InlineKeyboardMarkup(inline_keyboard=rows)
