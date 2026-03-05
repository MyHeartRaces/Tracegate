from tracegate.bot.keyboards import PROVIDER_CHOICES, device_actions_keyboard, main_menu_keyboard, vless_transport_keyboard


def _button_texts(keyboard) -> list[str]:
    out: list[str] = []
    for row in keyboard.inline_keyboard:
        for button in row:
            out.append(str(button.text))
    return out


def test_vless_transport_keyboard_b1_shows_reality_and_tls() -> None:
    kb = vless_transport_keyboard(spec="b1", device_id="dev-1")
    texts = _button_texts(kb)
    assert "Reality (выбор SNI)" in texts
    assert "TLS (WS, SNI=сертификат)" in texts


def test_vless_transport_keyboard_b2_has_no_transport_choices() -> None:
    kb = vless_transport_keyboard(spec="b2", device_id="dev-2")
    texts = _button_texts(kb)
    assert "Reality (выбор SNI)" not in texts
    assert "TLS (WS, SNI=сертификат)" not in texts
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
    assert "Статистика (Grafana)" not in texts


def test_device_actions_keyboard_uses_new_profile_names() -> None:
    kb = device_actions_keyboard("dev-42")
    texts = _button_texts(kb)
    assert "B1 - VLESS Direct" in texts
    assert "B2 - VLESS Chain" in texts
    assert "B3 - Hysteria Direct" in texts
    assert "B4 - Hysteria Chain" in texts
    assert "B5 - WireGuard" in texts
