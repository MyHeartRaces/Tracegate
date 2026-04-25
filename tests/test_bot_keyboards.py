from tracegate.bot.keyboards import (
    PROVIDER_CHOICES,
    admin_menu_keyboard,
    admin_mtproto_keyboard,
    admin_user_revoke_notify_keyboard,
    cancel_only_keyboard,
    confirm_action_keyboard,
    config_delivery_keyboard,
    device_actions_keyboard,
    devices_keyboard,
    feedback_admin_keyboard,
    guide_keyboard,
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


def test_vless_transport_keyboard_v1_shows_reality_and_tls() -> None:
    kb = vless_transport_keyboard(spec="v1", device_id="dev-1")
    texts = _button_texts(kb)
    assert "Reality (выбор SNI)" in texts
    assert "gRPC (HTTP/2 TLS)" in texts
    assert "WS+TLS (legacy)" in texts


def test_vless_transport_keyboard_v2_has_no_transport_choices() -> None:
    kb = vless_transport_keyboard(spec="v2", device_id="dev-2")
    texts = _button_texts(kb)
    assert "Reality (выбор SNI)" not in texts
    assert "gRPC (HTTP/2 TLS)" not in texts
    assert "WS+TLS (legacy)" not in texts
    assert "Отмена" in texts


def test_provider_choices_exclude_beeline_and_other() -> None:
    provider_codes = {code for _, code in PROVIDER_CHOICES}
    assert "beeline" not in provider_codes
    assert "other" not in provider_codes


def test_main_menu_does_not_include_sni_catalog_button() -> None:
    kb = main_menu_keyboard(is_admin=False)
    texts = _button_texts(kb)
    assert "Каталог SNI" not in texts


def test_main_menu_uses_grafana_button_caption() -> None:
    kb = main_menu_keyboard(is_admin=False)
    texts = _button_texts(kb)
    assert "Grafana" in texts
    assert "Наблюдаемость" not in texts


def test_main_menu_includes_guide_button() -> None:
    kb = main_menu_keyboard(is_admin=False)
    texts = _button_texts(kb)
    assert "Справка" in texts


def test_main_menu_uses_add_device_caption() -> None:
    kb = main_menu_keyboard(is_admin=False)
    texts = _button_texts(kb)
    assert "Добавить устройство" in texts
    assert "Новое устройство" not in texts


def test_main_menu_includes_feedback_button() -> None:
    kb = main_menu_keyboard(is_admin=False)
    texts = _button_texts(kb)
    assert "Обратная связь" in texts


def test_main_menu_includes_mtproto_button() -> None:
    kb = main_menu_keyboard(is_admin=False)
    texts = _button_texts(kb)
    assert "Telegram Proxy" in texts


def test_feedback_admin_keyboard_uses_targeted_callback() -> None:
    kb = feedback_admin_keyboard(telegram_id=123456789)
    button = kb.inline_keyboard[0][0]
    assert button.text == "Заблокировать автора"
    assert button.callback_data == "feedback_block:123456789"


def test_admin_menu_keyboard_includes_targeted_access_revoke_action() -> None:
    kb = admin_menu_keyboard(is_superadmin=False)
    texts = _button_texts(kb)
    assert "Отозвать доступ" in texts
    assert "Сводка пользователей" in texts
    assert "Telegram Proxy доступы" in texts
    assert "Глобальный отзыв" in texts


def test_admin_menu_keyboard_uses_tracegate2_role_labels() -> None:
    kb = admin_menu_keyboard(is_superadmin=True)
    texts = _button_texts(kb)
    assert "Telegram Proxy доступы" in texts
    assert "Наблюдаемость (админ)" not in texts
    assert "Назначить администратора" in texts
    assert "Снять администратора" in texts
    assert "Список администраторов" in texts


def test_admin_user_revoke_notify_keyboard_has_yes_no_actions() -> None:
    kb = admin_user_revoke_notify_keyboard()
    assert kb.inline_keyboard[0][0].text == "Да"
    assert kb.inline_keyboard[0][0].callback_data == "admin_user_revoke_notify:yes"
    assert kb.inline_keyboard[1][0].text == "Нет"
    assert kb.inline_keyboard[1][0].callback_data == "admin_user_revoke_notify:no"


def test_admin_mtproto_keyboard_exposes_refresh_and_revoke_actions() -> None:
    kb = admin_mtproto_keyboard()
    texts = _button_texts(kb)
    assert "Обновить" in texts
    assert "Отозвать Telegram Proxy" in texts
    assert "Меню" in texts


def test_guide_keyboard_returns_to_menu() -> None:
    kb = guide_keyboard()
    assert kb.inline_keyboard[0][0].text == "Меню"
    assert kb.inline_keyboard[0][0].callback_data == "menu"


def test_cancel_only_keyboard_uses_single_cancel_action() -> None:
    kb = cancel_only_keyboard(cancel_callback_data="admin_menu")
    assert kb.inline_keyboard[0][0].text == "Отмена"
    assert kb.inline_keyboard[0][0].callback_data == "admin_menu"


def test_confirm_action_keyboard_uses_confirm_and_back_actions() -> None:
    kb = confirm_action_keyboard(confirm_callback_data="confirm:1", cancel_callback_data="back:1")
    assert kb.inline_keyboard[0][0].text == "Подтвердить"
    assert kb.inline_keyboard[0][0].callback_data == "confirm:1"
    assert kb.inline_keyboard[1][0].text == "Назад"
    assert kb.inline_keyboard[1][0].callback_data == "back:1"


def test_config_delivery_keyboard_links_back_to_revisions_and_device() -> None:
    kb = config_delivery_keyboard(connection_id="conn-1", device_id="dev-1")
    assert kb.inline_keyboard[0][0].text == "К ревизиям"
    assert kb.inline_keyboard[0][0].callback_data == "revs:conn-1"
    assert kb.inline_keyboard[1][0].text == "К устройству"
    assert kb.inline_keyboard[1][0].callback_data == "device:dev-1"


def test_mtproto_delivery_keyboard_exposes_repeat_rotate_and_revoke_actions() -> None:
    kb = mtproto_delivery_keyboard()
    texts = _button_texts(kb)
    assert "Показать снова" in texts
    assert "Ротировать секрет" in texts
    assert "Отозвать доступ" in texts
    assert "Меню" in texts


def test_device_actions_keyboard_uses_new_profile_names() -> None:
    kb = device_actions_keyboard("dev-42")
    texts = _button_texts(kb)
    assert "V1-VLESS-Reality-Direct" in texts
    assert "V1-VLESS-gRPC-TLS-Direct" in texts
    assert "V1-VLESS-WS-TLS-Direct" in texts
    assert "V2-VLESS-Reality-Chain" in texts
    assert "V3-Hysteria2-QUIC-Direct" in texts
    assert "V4-Hysteria2-QUIC-Chain" in texts
    assert "V5-Shadowsocks2022-ShadowTLS-Direct" in texts
    assert "V6-Shadowsocks2022-ShadowTLS-Chain" in texts
    assert "V7-WireGuard-WSTunnel-Direct" in texts


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
