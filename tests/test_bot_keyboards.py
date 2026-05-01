from tracegate.bot.keyboards import (
    PROVIDER_CHOICES,
    admin_menu_keyboard,
    admin_mtproto_keyboard,
    admin_user_revoke_notify_keyboard,
    cancel_only_keyboard,
    confirm_action_keyboard,
    connection_create_categories_keyboard_for,
    connection_create_profiles_keyboard,
    config_delivery_keyboard,
    device_actions_keyboard,
    devices_keyboard,
    feedback_admin_keyboard,
    guide_keyboard,
    help_keyboard,
    main_menu_keyboard,
    mtproto_delivery_keyboard,
    revisions_keyboard,
    vless_transport_keyboard,
)


def _button_texts(keyboard) -> list[str]:
    out: list[str] = []
    for row in keyboard.inline_keyboard:
        for button in row:
            out.append(str(button.text))
    return out


def _has_text(texts: list[str], needle: str) -> bool:
    return any(needle in text for text in texts)


def test_vless_transport_keyboard_v1_shows_reality_only() -> None:
    kb = vless_transport_keyboard(spec="v1", device_id="dev-1")
    texts = _button_texts(kb)
    assert _has_text(texts, "Reality (выбор SNI)")
    assert not _has_text(texts, "gRPC (HTTP/2 TLS)")
    assert not _has_text(texts, "WS+TLS (legacy)")


def test_vless_transport_keyboard_v2_has_no_transport_choices() -> None:
    kb = vless_transport_keyboard(spec="v2", device_id="dev-2")
    texts = _button_texts(kb)
    assert not _has_text(texts, "Reality (выбор SNI)")
    assert not _has_text(texts, "gRPC (HTTP/2 TLS)")
    assert not _has_text(texts, "WS+TLS (legacy)")
    assert _has_text(texts, "Отмена")


def test_provider_choices_exclude_beeline_and_other() -> None:
    provider_codes = {code for _, code in PROVIDER_CHOICES}
    assert "beeline" not in provider_codes
    assert "other" not in provider_codes


def test_main_menu_does_not_include_sni_catalog_button() -> None:
    kb = main_menu_keyboard(is_admin=False)
    texts = _button_texts(kb)
    assert not _has_text(texts, "Каталог SNI")


def test_main_menu_uses_grafana_button_caption() -> None:
    kb = main_menu_keyboard(is_admin=False)
    texts = _button_texts(kb)
    assert _has_text(texts, "Grafana")
    assert not _has_text(texts, "Наблюдаемость")


def test_main_menu_includes_guide_button() -> None:
    kb = main_menu_keyboard(is_admin=False)
    texts = _button_texts(kb)
    assert _has_text(texts, "Справка")
    assert kb.inline_keyboard[2][0].text == "📚 Справка"
    assert kb.inline_keyboard[2][0].callback_data == "guide_open"


def test_help_keyboard_returns_to_menu_without_extra_links() -> None:
    kb = help_keyboard()
    assert len(kb.inline_keyboard) == 1
    assert kb.inline_keyboard[0][0].text == "🏠 Меню"
    assert kb.inline_keyboard[0][0].callback_data == "menu"


def test_main_menu_uses_unified_devices_section() -> None:
    kb = main_menu_keyboard(is_admin=False)
    texts = _button_texts(kb)
    assert _has_text(texts, "Подключения")
    assert _has_text(texts, "Устройства")
    assert not _has_text(texts, "Добавить устройство")
    assert not _has_text(texts, "Новое устройство")


def test_main_menu_includes_feedback_button() -> None:
    kb = main_menu_keyboard(is_admin=False)
    texts = _button_texts(kb)
    assert _has_text(texts, "Обратная связь")


def test_main_menu_includes_mtproto_button() -> None:
    kb = main_menu_keyboard(is_admin=False)
    texts = _button_texts(kb)
    assert _has_text(texts, "Telegram Proxy")


def test_feedback_admin_keyboard_uses_targeted_callback() -> None:
    kb = feedback_admin_keyboard(telegram_id=123456789)
    button = kb.inline_keyboard[0][0]
    assert button.text == "🚫 Заблокировать автора"
    assert button.callback_data == "feedback_block:123456789"


def test_admin_menu_keyboard_includes_targeted_access_revoke_action() -> None:
    kb = admin_menu_keyboard(is_superadmin=False)
    texts = _button_texts(kb)
    assert _has_text(texts, "Отозвать доступ")
    assert _has_text(texts, "Сводка пользователей")
    assert _has_text(texts, "Telegram Proxy доступы")
    assert _has_text(texts, "Глобальный отзыв")


def test_admin_menu_keyboard_uses_tracegate2_role_labels() -> None:
    kb = admin_menu_keyboard(is_superadmin=True)
    texts = _button_texts(kb)
    assert _has_text(texts, "Telegram Proxy доступы")
    assert not _has_text(texts, "Наблюдаемость (админ)")
    assert _has_text(texts, "Назначить администратора")
    assert _has_text(texts, "Снять администратора")
    assert _has_text(texts, "Список администраторов")


def test_admin_user_revoke_notify_keyboard_has_yes_no_actions() -> None:
    kb = admin_user_revoke_notify_keyboard()
    assert kb.inline_keyboard[0][0].text == "✅ Да"
    assert kb.inline_keyboard[0][0].callback_data == "admin_user_revoke_notify:yes"
    assert kb.inline_keyboard[1][0].text == "↩️ Нет"
    assert kb.inline_keyboard[1][0].callback_data == "admin_user_revoke_notify:no"


def test_admin_mtproto_keyboard_exposes_refresh_and_revoke_actions() -> None:
    kb = admin_mtproto_keyboard()
    texts = _button_texts(kb)
    assert _has_text(texts, "Обновить")
    assert _has_text(texts, "Отозвать Telegram Proxy")
    assert _has_text(texts, "Управление")


def test_guide_keyboard_returns_to_menu() -> None:
    kb = guide_keyboard()
    assert len(kb.inline_keyboard) == 1
    assert kb.inline_keyboard[0][0].text == "🏠 Меню"
    assert kb.inline_keyboard[0][0].callback_data == "menu"


def test_cancel_only_keyboard_uses_single_cancel_action() -> None:
    kb = cancel_only_keyboard(cancel_callback_data="admin_menu")
    assert kb.inline_keyboard[0][0].text == "↩️ Отмена"
    assert kb.inline_keyboard[0][0].callback_data == "admin_menu"


def test_confirm_action_keyboard_uses_confirm_and_back_actions() -> None:
    kb = confirm_action_keyboard(confirm_callback_data="confirm:1", cancel_callback_data="back:1")
    assert kb.inline_keyboard[0][0].text == "✅ Подтвердить"
    assert kb.inline_keyboard[0][0].callback_data == "confirm:1"
    assert kb.inline_keyboard[1][0].text == "↩️ Назад"
    assert kb.inline_keyboard[1][0].callback_data == "back:1"


def test_config_delivery_keyboard_links_back_to_connection_and_connections() -> None:
    kb = config_delivery_keyboard(connection_id="conn-1", device_id="dev-1")
    assert kb.inline_keyboard[0][0].text == "🧩 К подключению"
    assert kb.inline_keyboard[0][0].callback_data == "revs:conn-1"
    assert kb.inline_keyboard[1][0].text == "🔌 К подключениям"
    assert kb.inline_keyboard[1][0].callback_data == "connections"


def test_mtproto_delivery_keyboard_exposes_repeat_rotate_and_revoke_actions() -> None:
    kb = mtproto_delivery_keyboard()
    texts = _button_texts(kb)
    assert _has_text(texts, "Показать снова")
    assert _has_text(texts, "Ротировать секрет")
    assert _has_text(texts, "Отозвать доступ")
    assert _has_text(texts, "Меню")


def test_connection_create_profiles_keyboard_uses_new_profile_names() -> None:
    kb = connection_create_profiles_keyboard(category="direct", device_id="dev-42")
    texts = _button_texts(kb)
    assert "V1-Direct-Reality-VLESS" in texts
    assert "V2-Direct-QUIC-Hysteria" in texts
    assert "V3-Direct-ShadowTLS-Shadowsocks" in texts

    kb = connection_create_profiles_keyboard(category="chain", device_id="dev-42")
    texts = _button_texts(kb)
    assert "V1-Chain-Reality-VLESS" in texts
    assert "V2-Chain-QUIC-Hysteria" in texts
    assert "V3-Chain-ShadowTLS-Shadowsocks" in texts

    kb = connection_create_profiles_keyboard(category="other", device_id="dev-42")
    texts = _button_texts(kb)
    assert "V0-WS-VLESS" in texts
    assert "V0-gRPC-VLESS" in texts
    assert "V0-WGWS-WireGuard" in texts


def test_connection_create_keyboards_hide_disabled_profiles() -> None:
    enabled = {"v1direct", "v2direct", "v0ws", "v0grpc"}
    categories = _button_texts(connection_create_categories_keyboard_for(enabled_specs=enabled))
    assert "⚡ Direct" in categories
    assert "🧰 Other" in categories
    assert "⛓️ Chain" not in categories

    direct = _button_texts(connection_create_profiles_keyboard(category="direct", device_id="dev-42", enabled_specs=enabled))
    assert "V1-Direct-Reality-VLESS" in direct
    assert "V2-Direct-QUIC-Hysteria" in direct
    assert "V3-Direct-ShadowTLS-Shadowsocks" not in direct

    other = _button_texts(connection_create_profiles_keyboard(category="other", device_id="dev-42", enabled_specs=enabled))
    assert "V0-WS-VLESS" in other
    assert "V0-gRPC-VLESS" in other
    assert "V0-WGWS-WireGuard" not in other


def test_devices_keyboard_uses_delete_confirmation_callback() -> None:
    kb = devices_keyboard([{"id": "dev-1", "name": "Laptop"}])
    delete_button = kb.inline_keyboard[0][1]
    assert delete_button.callback_data == "deldevask:dev-1"


def test_device_actions_keyboard_uses_delete_confirmation_callback() -> None:
    kb = device_actions_keyboard(
        "dev-42",
        connections=[{"id": "conn-1", "protocol": "vless_reality", "mode": "direct", "variant": "V1"}],
    )
    delete_button = next(button for row in kb.inline_keyboard for button in row if button.callback_data == "delconnask:conn-1")
    assert delete_button.callback_data == "delconnask:conn-1"


def test_revisions_keyboard_uses_delete_confirmation_callback() -> None:
    kb = revisions_keyboard(
        "conn-1",
        [{"id": "rev-1", "slot": 0, "status": "ACTIVE"}],
        True,
        "dev-1",
    )
    delete_button = kb.inline_keyboard[2][1]
    assert delete_button.callback_data == "revokeask:rev-1"
