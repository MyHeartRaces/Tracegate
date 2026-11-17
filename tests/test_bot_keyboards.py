from __future__ import annotations

import pytest

import test_bot_support  # noqa: F401
from test_bot_support import button_texts, buttons, callback_datas, new_id
from tracegate.bot import callbacks as cb
from tracegate.bot import keyboards, texts
from tracegate.services.connection_profiles import MAX_CONNECTIONS_PER_DEVICE, MAX_DEVICES_PER_USER

UUID = "11111111-2222-3333-4444-555555555555"


def test_main_menu_layout_for_user() -> None:
    kb = keyboards.main_menu_keyboard(is_admin=False, grafana_enabled=False)
    assert button_texts(kb) == ["📱 Мои устройства", "✈️ Telegram Proxy", "📖 Инструкция", "💬 Написать админу"]
    assert callback_datas(kb) == [cb.DEVICES, cb.TGP, cb.GUIDE, cb.FEEDBACK]


def test_main_menu_grafana_and_admin_are_conditional() -> None:
    kb = keyboards.main_menu_keyboard(is_admin=True, grafana_enabled=True)
    assert button_texts(kb)[-2:] == ["📊 Grafana", "🛠 Управление"]
    assert callback_datas(kb)[-2:] == [cb.GRAFANA, cb.ADMIN]
    assert "📊 Grafana" not in button_texts(keyboards.main_menu_keyboard(is_admin=True, grafana_enabled=False))


def test_devices_keyboard_shows_counts_and_hides_add_at_limit() -> None:
    devices = [{"id": new_id(), "name": f"Устройство {i}"} for i in range(MAX_DEVICES_PER_USER)]
    kb = keyboards.devices_keyboard(devices[:1], {devices[0]["id"]: 3})
    assert button_texts(kb) == ["📱 Устройство 0 · 3", texts.BTN_ADD_DEVICE, texts.BTN_HOME]
    assert callback_datas(kb)[0] == f"dev:{devices[0]['id']}"
    full = keyboards.devices_keyboard(devices, {})
    assert texts.BTN_ADD_DEVICE not in button_texts(full)
    assert button_texts(full)[-1] == texts.BTN_HOME


def test_device_keyboard_lists_connections_with_russian_labels() -> None:
    connections = [
        {"id": new_id(), "protocol": "vless_reality", "mode": "chain", "variant": "V1"},
        {"id": new_id(), "protocol": "hysteria2", "mode": "direct", "variant": "V2", "custom_overrides_json": {"hysteria_obfs": "gecko"}},
        {"id": new_id(), "protocol": "vless_ws_tls", "mode": "direct", "variant": "V0"},
    ]
    kb = keyboards.device_keyboard(UUID, connections, can_create=True)
    assert button_texts(kb) == [
        "🔗 Chain",
        "🚀 Direct Hysteria · Gecko",
        "🗂 Устаревшее подключение",
        texts.BTN_NEW_CONNECTION,
        texts.BTN_RENAME_DEVICE,
        texts.BTN_DELETE_DEVICE,
        texts.BTN_BACK,
        texts.BTN_HOME,
    ]
    datas = callback_datas(kb)
    assert datas[0] == f"conn:{connections[0]['id']}"
    assert f"cnew:{UUID}" in datas
    assert f"devren:{UUID}" in datas
    assert f"devdelq:{UUID}" in datas
    assert datas[-2:] == [cb.DEVICES, cb.MENU]


def test_device_keyboard_hides_new_connection_at_limit() -> None:
    connections = [{"id": new_id(), "protocol": "vless_reality", "mode": "chain"} for _ in range(MAX_CONNECTIONS_PER_DEVICE)]
    kb = keyboards.device_keyboard(UUID, connections, can_create=False)
    assert texts.BTN_NEW_CONNECTION not in button_texts(kb)


def test_create_keyboard_offers_chain_first_and_hides_disabled() -> None:
    kb = keyboards.create_connection_keyboard(UUID, {"entry", "reality", "hysteria"})
    assert button_texts(kb) == [
        texts.BTN_MAKE_CHAIN, texts.BTN_MAKE_REALITY, texts.BTN_MAKE_HYSTERIA, texts.BTN_BACK, texts.BTN_HOME
    ]
    assert callback_datas(kb) == [f"cmk:entry:{UUID}", f"cmk:reality:{UUID}", f"chy:{UUID}", f"dev:{UUID}", cb.MENU]
    only_reality = keyboards.create_connection_keyboard(UUID, {"reality"})
    assert button_texts(only_reality) == [texts.BTN_MAKE_REALITY, texts.BTN_BACK, texts.BTN_HOME]
    none = keyboards.create_connection_keyboard(UUID, set())
    assert button_texts(none) == [texts.BTN_BACK, texts.BTN_HOME]


def test_hysteria_obfs_keyboard() -> None:
    kb = keyboards.hysteria_obfs_keyboard(UUID)
    assert button_texts(kb) == ["Salamander — рекомендуется", "Gecko", texts.BTN_BACK, texts.BTN_HOME]
    assert callback_datas(kb) == [f"cmk:hy-salamander:{UUID}", f"cmk:hy-gecko:{UUID}", f"cnew:{UUID}", cb.MENU]


def test_connection_keyboard_regular_and_legacy() -> None:
    regular = keyboards.connection_keyboard(UUID, UUID)
    assert button_texts(regular) == [
        texts.BTN_SHOW_CONFIG,
        texts.BTN_REISSUE,
        texts.BTN_ADVANCED,
        texts.BTN_DELETE_CONNECTION,
        texts.BTN_BACK,
        texts.BTN_HOME,
    ]
    assert callback_datas(regular)[:4] == [f"cshow:{UUID}", f"creq:{UUID}", f"cadv:{UUID}", f"cdelq:{UUID}"]
    no_config = keyboards.connection_keyboard(UUID, UUID, has_config=False)
    assert texts.BTN_SHOW_CONFIG not in button_texts(no_config)
    legacy = keyboards.connection_keyboard(UUID, UUID, legacy=True)
    assert button_texts(legacy) == [texts.BTN_DELETE_CONNECTION, texts.BTN_BACK, texts.BTN_HOME]


def test_slots_keyboard_actions_per_slot() -> None:
    main_id, reserve_id, old_id = new_id(), new_id(), new_id()
    kb = keyboards.slots_keyboard(
        UUID,
        [
            {"id": main_id, "slot": 0, "status": "active", "created_at": "2026-11-17T10:00:00Z"},
            {"id": reserve_id, "slot": 1, "status": "active", "created_at": "2026-11-16T09:00:00Z"},
            {"id": old_id, "slot": 1, "status": "revoked", "created_at": "2026-11-15T08:00:00Z"},
        ],
    )
    rows = [[(b.text, b.callback_data) for b in row] for row in kb.inline_keyboard]
    assert rows[0] == [("🗑 Отключить · 17.11 10:00", f"srevq:{main_id}")]
    assert rows[1] == [("⭐ Сделать основной · 16.11 09:00", f"sact:{reserve_id}"), ("🗑 Отключить · 16.11 09:00", f"srevq:{reserve_id}")]
    assert rows[2] == [("♻️ Включить снова · 15.11 08:00", f"sact:{old_id}")]
    assert rows[3] == [(texts.BTN_BACK, f"conn:{UUID}"), (texts.BTN_HOME, cb.MENU)]


def test_config_delivery_keyboard_links_guide_connection_and_menu() -> None:
    kb = keyboards.config_delivery_keyboard(connection_id=UUID, howto_callback="g:apps")
    assert button_texts(kb) == [texts.BTN_HOWTO, texts.BTN_TO_CONNECTION, texts.BTN_HOME]
    assert callback_datas(kb) == ["g:apps", f"conn:{UUID}", cb.MENU]


def test_tgp_keyboard_back_goes_to_menu() -> None:
    kb = keyboards.tgp_keyboard()
    assert callback_datas(kb) == [cb.TGP_SHOW, cb.TGP_ROTATE, cb.TGP_REVOKE_ASK, cb.MENU]
    assert button_texts(kb)[-1] == texts.BTN_BACK


def test_guide_keyboard_root_and_page() -> None:
    root = keyboards.guide_keyboard([("🚀 Быстрый старт", "g:quick")], back_callback=None)
    assert callback_datas(root) == ["g:quick", cb.MENU]
    page = keyboards.guide_keyboard([], back_callback="g:apps")
    assert button_texts(page) == [texts.BTN_BACK, texts.BTN_HOME]
    assert callback_datas(page) == ["g:apps", cb.MENU]


def test_admin_menu_keyboard_by_role() -> None:
    admin = keyboards.admin_menu_keyboard(is_superadmin=False)
    assert callback_datas(admin) == [
        cb.ADMIN_USERS,
        cb.ADMIN_TGP,
        cb.ADMIN_REVOKE_ACCESS,
        cb.ADMIN_BLOCK,
        cb.ADMIN_UNBLOCK,
        cb.ADMIN_RESET_ASK,
        cb.MENU,
    ]
    superadmin = keyboards.admin_menu_keyboard(is_superadmin=True)
    for callback_data in (cb.ADMIN_GRANT, cb.ADMIN_UNGRANT, cb.ADMIN_LIST):
        assert callback_data in callback_datas(superadmin)


def test_admin_cancel_keyboard_is_one_consistent_cancel() -> None:
    kb = keyboards.admin_cancel_keyboard()
    assert button_texts(kb) == ["↩️ Отмена"]
    assert callback_datas(kb) == [cb.ADMIN]
    notify = keyboards.admin_notify_keyboard()
    assert callback_datas(notify) == [cb.ADMIN_NOTIFY_YES, cb.ADMIN_NOTIFY_NO, cb.ADMIN]


def test_feedback_admin_keyboard_keeps_targeted_callback() -> None:
    kb = keyboards.feedback_admin_keyboard(telegram_id=123456789)
    assert callback_datas(kb) == ["feedback_block:123456789"]


def test_grafana_keyboard_uses_login_url() -> None:
    kb = keyboards.grafana_keyboard("https://grafana.example.test/login?code=x")
    assert buttons(kb)[0].url == "https://grafana.example.test/login?code=x"
    assert button_texts(keyboards.grafana_keyboard(None)) == [texts.BTN_HOME]


@pytest.mark.parametrize(
    "data",
    [
        cb.make(cb.MAKE_HYSTERIA_SALAMANDER, UUID),
        cb.with_id(cb.DEVICE_DELETE_ASK_P, UUID),
        cb.with_id(cb.CONN_DELETE_ASK_P, UUID),
        cb.with_id(cb.SLOT_REVOKE_ASK_P, UUID),
        cb.with_id(cb.FEEDBACK_BLOCK_P, 10**15),
        cb.ADMIN_NOTIFY_YES,
    ],
)
def test_callbacks_fit_telegram_limit(data: str) -> None:
    assert len(data.encode()) <= 64


def test_every_keyboard_callback_fits_with_uuid_ids() -> None:
    connections = [{"id": UUID, "protocol": "hysteria2", "mode": "direct", "custom_overrides_json": {"hysteria_obfs": "salamander"}}]
    revisions = [{"id": UUID, "slot": 1, "status": "active", "created_at": "2026-11-17T10:00:00Z"}]
    built = [
        keyboards.devices_keyboard([{"id": UUID, "name": "x" * 200}], {}),
        keyboards.device_keyboard(UUID, connections, can_create=True),
        keyboards.create_connection_keyboard(UUID, {"entry", "reality", "hysteria"}),
        keyboards.hysteria_obfs_keyboard(UUID),
        keyboards.connection_keyboard(UUID, UUID),
        keyboards.slots_keyboard(UUID, revisions),
        keyboards.config_delivery_keyboard(connection_id=UUID),
    ]
    for keyboard in built:
        for data in callback_datas(keyboard):
            assert cb.fits(data), data


def test_callback_parsers_reject_malformed_ids() -> None:
    assert cb.parse_id(f"dev:{UUID}", cb.DEVICE_P) == UUID
    assert cb.parse_id("dev:not-a-uuid", cb.DEVICE_P) is None
    assert cb.parse_make(f"cmk:entry:{UUID}") == ("entry", UUID)
    assert cb.parse_make(f"cmk:backup-ws:{UUID}") is None
    assert cb.parse_telegram_id("feedback_block:42", cb.FEEDBACK_BLOCK_P) == 42
    assert cb.parse_telegram_id("feedback_block:abc", cb.FEEDBACK_BLOCK_P) is None


def test_long_device_names_are_clipped_in_buttons() -> None:
    kb = keyboards.devices_keyboard([{"id": UUID, "name": "Очень" * 30}], {UUID: 1})
    assert len(button_texts(kb)[0]) < 60


def test_confirm_keyboard_has_back_and_home() -> None:
    kb = keyboards.confirm_keyboard(confirm_text="🗑 Да, удалить", confirm_callback=f"cdel:{UUID}", back_callback=f"conn:{UUID}")
    assert callback_datas(kb) == [f"cdel:{UUID}", f"conn:{UUID}", cb.MENU]
