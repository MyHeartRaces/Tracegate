from __future__ import annotations

from types import SimpleNamespace

import pytest

import test_bot_support  # noqa: F401
from test_bot_support import (
    DummyBot,
    DummyCallback,
    DummyMessage,
    DummyState,
    FakeApi,
    button_texts,
    callback_datas,
    new_id,
)
from aiogram.types import CallbackQuery, Message

from tracegate.bot import callbacks as cb
from tracegate.bot import context as ctx
from tracegate.bot import delivery, nav, texts
from tracegate.bot.client import ApiClientError
from tracegate.bot.handlers import connections, devices, fallback, feedback, mtproto, start
from tracegate.bot.middleware import BotAccessMiddleware
from tracegate.bot.states import DeviceFlow, FeedbackFlow
from tracegate.services.connection_profiles import MAX_CONNECTIONS_PER_DEVICE, MAX_DEVICES_PER_USER


@pytest.fixture
def api(monkeypatch: pytest.MonkeyPatch) -> FakeApi:
    fake = FakeApi()
    monkeypatch.setattr(ctx, "api", fake)
    monkeypatch.setattr(ctx.settings, "enabled_client_profiles", None)
    monkeypatch.setattr(ctx.settings, "bot_guide_path", "")
    monkeypatch.setattr(ctx.settings, "grafana_enabled", False)
    monkeypatch.setattr(ctx.settings, "bot_welcome_required", True)
    monkeypatch.setattr(ctx.settings, "bot_welcome_version", "v-test")
    monkeypatch.setattr(delivery, "build_qr_png", lambda payload: payload.encode("utf-8"))
    monkeypatch.setattr(mtproto, "build_qr_png", lambda payload: payload.encode("utf-8"))
    return fake


USER = {"telegram_id": 1, "role": "user"}
ADMIN = {"telegram_id": 1, "role": "admin"}


def _uri_export(**overrides):  # noqa: ANN003, ANN202
    values = dict(
        kind="uri",
        title="VLESS REALITY link",
        content="vless://user@example.com:443?security=reality#Tracegate",
        alternate_title=None,
        alternate_content=None,
        extra_messages=(),
        attachment_content=None,
        attachment_filename=None,
        attachment_mime=None,
    )
    values.update(overrides)
    return SimpleNamespace(**values)


# --------------------------------------------------------- middlewares ---


class _Callback(CallbackQuery):
    """Real CallbackQuery type with a recording answer()."""

    async def answer(self, text=None, **kwargs):  # noqa: ANN001, ANN003, ANN201
        self.__dict__.setdefault("recorded", []).append((text, kwargs))


class _Message(Message):
    async def answer(self, text, **kwargs):  # noqa: ANN001, ANN003, ANN201
        self.__dict__.setdefault("recorded", []).append((text, kwargs))


def _from_user(user_id: int = 1) -> SimpleNamespace:
    return SimpleNamespace(id=user_id, username="alice", first_name=None, last_name=None)


@pytest.mark.asyncio
async def test_callback_answer_first_middleware_answers_once_before_handler() -> None:
    order: list[str] = []
    event = _Callback.model_construct(id="1", data="menu")

    async def _handler(evt, data):  # noqa: ANN001, ANN202
        order.append(f"handler:{len(evt.__dict__.get('recorded', []))}")
        return "done"

    result = await nav.CallbackAnswerFirstMiddleware()(_handler, event, {})
    assert result == "done"
    assert order == ["handler:1"]
    assert event.__dict__["recorded"] == [(None, {})]


@pytest.mark.asyncio
async def test_access_middleware_gates_unaccepted_welcome_and_blocked_users(api: FakeApi) -> None:
    middleware = BotAccessMiddleware()
    handled: list[object] = []

    async def _handler(evt, data):  # noqa: ANN001, ANN202
        handled.append(data.get("tracegate_user"))

    # Not accepted: a plain message gets welcome step 1 instead of the handler.
    message = _Message.model_construct(text="привет")
    await middleware(_handler, message, {"event_from_user": _from_user()})
    assert handled == []
    assert message.__dict__["recorded"][0][1]["reply_markup"].inline_keyboard[0][0].callback_data == cb.WELCOME_1

    # /start and the welcome buttons pass through.
    await middleware(_handler, _Message.model_construct(text="/start"), {"event_from_user": _from_user()})
    await middleware(_handler, _Callback.model_construct(id="1", data=cb.WELCOME_2, message=DummyMessage()), {"event_from_user": _from_user()})
    assert len(handled) == 2

    # Other buttons are refused with an alert and the welcome is sent again.
    other = _Callback.model_construct(id="2", data=cb.DEVICES, message=DummyMessage())
    await middleware(_handler, other, {"event_from_user": _from_user()})
    assert len(handled) == 2
    assert other.__dict__["recorded"] == [(texts.WELCOME_REQUIRED_ALERT, {"show_alert": True})]
    from tracegate.bot.welcome import welcome_text

    assert other.message.answers[0][0] == welcome_text()

    # Blocked users never reach handlers.
    api.users[1].update(bot_blocked_until="2999-01-01T00:00:00+00:00", bot_block_reason="spam")
    blocked = _Message.model_construct(text="/start")
    await middleware(_handler, blocked, {"event_from_user": _from_user()})
    assert len(handled) == 2
    assert blocked.__dict__["recorded"][0][0].startswith("⚠️ Доступ к боту временно ограничен")


@pytest.mark.asyncio
async def test_ack_swallows_stale_query_errors() -> None:
    callback = DummyCallback("menu")

    async def _boom(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        raise RuntimeError("query is too old")

    callback.answer = _boom
    await nav.ack(callback)


@pytest.mark.asyncio
async def test_handlers_never_answer_callbacks_themselves(api: FakeApi) -> None:
    device = api.add_device()
    connection = api.add_connection(device)
    for data, handler in [
        (cb.MENU, start.menu),
        (cb.DEVICES, devices.devices_list),
        (cb.device(device["id"]), devices.device_page),
        (cb.connection(connection["id"]), connections.connection_page),
        (cb.with_id(cb.CONN_REISSUE_ASK_P, connection["id"]), connections.confirm_reissue),
        ("sni_catalog", fallback.stale_callback),
    ]:
        callback = DummyCallback(data)
        await handler(callback, DummyState(), tracegate_user=USER)
        assert callback.answers == [], data


# -------------------------------------------------------------- welcome ---


@pytest.mark.asyncio
async def test_start_requires_two_step_welcome_before_menu(api: FakeApi, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctx.settings, "bot_welcome_message", "[welcome-placeholder]")
    monkeypatch.setattr(ctx.settings, "bot_welcome_message_file", "")
    message = DummyMessage("/start")
    state = DummyState(state="something")
    await start.start(message, state, tracegate_user=dict(api.users[1]))
    assert state.state is None
    text, kwargs = message.answers[0]
    assert text == "[welcome-placeholder]"
    assert callback_datas(kwargs["reply_markup"]) == [cb.WELCOME_1]
    assert button_texts(kwargs["reply_markup"]) == ["✅ Продолжить"]

    first = DummyCallback(cb.WELCOME_1)
    await start.welcome_continue_1(first, DummyState(), tracegate_user=dict(api.users[1]))
    assert first.message.screens == [texts.WELCOME_RULES]
    assert callback_datas(first.message.last_keyboard()) == [cb.WELCOME_2]

    second = DummyCallback(cb.WELCOME_2)
    await start.welcome_continue_2(second, DummyState(), tracegate_user=dict(api.users[1]))
    assert api.users[1]["bot_welcome_version"] == "v-test"
    assert second.message.screens == [texts.MAIN_MENU]
    assert callback_datas(second.message.last_keyboard())[0] == cb.DEVICES


@pytest.mark.asyncio
async def test_start_for_accepted_user_sends_menu(api: FakeApi) -> None:
    user = {"telegram_id": 1, "role": "admin", "bot_welcome_accepted_at": "2026-01-01", "bot_welcome_version": "v-test"}
    message = DummyMessage("/start")
    await start.start(message, DummyState(), tracegate_user=user)
    assert message.sent_texts == [texts.MAIN_MENU]
    assert cb.ADMIN in callback_datas(message.last_keyboard())


@pytest.mark.asyncio
async def test_cancel_clears_state_and_shows_menu(api: FakeApi) -> None:
    message = DummyMessage("/cancel")
    state = DummyState(state=DeviceFlow.waiting_for_name)
    await start.cancel(message, state, tracegate_user=USER)
    assert state.state is None
    assert message.sent_texts[0].startswith(texts.CANCELLED)


@pytest.mark.asyncio
async def test_grafana_disabled_and_enabled(api: FakeApi, monkeypatch: pytest.MonkeyPatch) -> None:
    callback = DummyCallback(cb.GRAFANA)
    await start.grafana(callback, DummyState(), tracegate_user=USER)
    assert callback.message.screens == [texts.GRAFANA_DISABLED]

    monkeypatch.setattr(ctx.settings, "grafana_enabled", True)
    admin_callback = DummyCallback(cb.GRAFANA)
    await start.grafana(admin_callback, DummyState(), tracegate_user=ADMIN)
    assert api.called("create_grafana_otp")[-1][1] == {"scope": "admin"}
    assert "администраторский" in admin_callback.message.screens[0]
    assert admin_callback.message.last_keyboard().inline_keyboard[0][0].url.startswith("https://grafana.example.test")


# -------------------------------------------------------------- devices ---


@pytest.mark.asyncio
async def test_device_list_empty_and_with_counts(api: FakeApi) -> None:
    callback = DummyCallback(cb.DEVICES)
    await devices.devices_list(callback, DummyState(), tracegate_user=USER)
    assert "Пока пусто" in callback.message.screens[0]

    device = api.add_device(name="Ноутбук")
    api.add_connection(device)
    api.add_connection(device, mode="direct")
    callback = DummyCallback(cb.DEVICES)
    await devices.devices_list(callback, DummyState(), tracegate_user=USER)
    assert "Устройств: 1 из 4" in callback.message.screens[0]
    assert button_texts(callback.message.last_keyboard())[0] == "📱 Ноутбук · 2"


@pytest.mark.asyncio
async def test_add_device_flow(api: FakeApi) -> None:
    callback = DummyCallback(cb.DEVICE_ADD)
    state = DummyState()
    await devices.add_device(callback, state, tracegate_user=USER)
    assert state.state == DeviceFlow.waiting_for_name
    assert callback.message.screens == [texts.DEVICE_NAME_PROMPT]
    assert callback_datas(callback.message.last_keyboard()) == [cb.DEVICES]

    empty = DummyMessage("   ")
    await devices.receive_device_name(empty, state, tracegate_user=USER)
    assert empty.sent_texts == [texts.DEVICE_NAME_EMPTY]
    assert state.state == DeviceFlow.waiting_for_name

    message = DummyMessage("Телефон")
    await devices.receive_device_name(message, state, tracegate_user=USER)
    assert state.state is None
    assert message.sent_texts[0].startswith(texts.device_added("Телефон"))
    assert texts.BTN_NEW_CONNECTION in button_texts(message.last_keyboard())


@pytest.mark.asyncio
async def test_add_device_at_limit_shows_limit_without_prompt(api: FakeApi) -> None:
    for index in range(MAX_DEVICES_PER_USER):
        api.add_device(name=f"Устройство {index}")
    callback = DummyCallback(cb.DEVICE_ADD)
    state = DummyState()
    await devices.add_device(callback, state, tracegate_user=USER)
    assert state.state is None
    assert callback.message.screens[0].startswith(texts.ERR_DEVICE_LIMIT)


@pytest.mark.asyncio
async def test_create_device_api_error_is_mapped(api: FakeApi) -> None:
    api.fail["create_device"] = ApiClientError(status_code=400, path="/devices", detail='{"detail":"Device limit reached (4)"}')
    message = DummyMessage("Планшет")
    await devices.receive_device_name(message, DummyState(state=DeviceFlow.waiting_for_name), tracegate_user=USER)
    assert message.sent_texts == [texts.ERR_DEVICE_LIMIT]


@pytest.mark.asyncio
async def test_rename_device_flow(api: FakeApi) -> None:
    device = api.add_device(name="Старое")
    callback = DummyCallback(cb.with_id(cb.DEVICE_RENAME_P, device["id"]))
    state = DummyState()
    await devices.rename_device(callback, state, tracegate_user=USER)
    assert state.state == DeviceFlow.waiting_for_rename
    assert "Старое" in callback.message.screens[0]

    message = DummyMessage("Новое имя")
    await devices.receive_device_rename(message, state, tracegate_user=USER)
    assert api.called("rename_device") == [((device["id"], "Новое имя"), {})]
    assert message.sent_texts[0].startswith(texts.device_renamed("Новое имя"))


@pytest.mark.asyncio
async def test_foreign_device_is_not_found(api: FakeApi) -> None:
    foreign = api.add_device(user_id=2, name="Чужое")
    for handler, prefix in [
        (devices.device_page, cb.DEVICE_P),
        (devices.rename_device, cb.DEVICE_RENAME_P),
        (devices.confirm_delete_device, cb.DEVICE_DELETE_ASK_P),
        (devices.delete_device, cb.DEVICE_DELETE_P),
    ]:
        callback = DummyCallback(cb.with_id(prefix, foreign["id"]))
        await handler(callback, DummyState(), tracegate_user=USER)
        assert callback.message.screens[0].startswith(texts.ERR_DEVICE_NOT_FOUND)
    assert not api.called("delete_device")
    assert not api.called("rename_device")


@pytest.mark.asyncio
async def test_delete_device_confirm_then_parent_with_status(api: FakeApi) -> None:
    device = api.add_device(name="Телефон")
    ask = DummyCallback(cb.with_id(cb.DEVICE_DELETE_ASK_P, device["id"]))
    await devices.confirm_delete_device(ask, DummyState(), tracegate_user=USER)
    assert ask.message.screens[0] == texts.device_delete_confirm("Телефон")
    assert callback_datas(ask.message.last_keyboard()) == [f"devdel:{device['id']}", f"dev:{device['id']}", cb.MENU]

    confirm = DummyCallback(cb.with_id(cb.DEVICE_DELETE_P, device["id"]))
    await devices.delete_device(confirm, DummyState(), tracegate_user=USER)
    assert api.called("cleanup_bot_messages")[-1][1]["device_id"] == device["id"]
    assert confirm.message.screens[0].startswith(texts.device_deleted("Телефон"))
    assert confirm.message.answers == []


# ---------------------------------------------------------- connections ---


@pytest.mark.asyncio
async def test_create_menu_lists_enabled_options(api: FakeApi, monkeypatch: pytest.MonkeyPatch) -> None:
    device = api.add_device()
    callback = DummyCallback(cb.with_id(cb.CONN_NEW_P, device["id"]))
    await connections.create_menu(callback, DummyState(), tracegate_user=USER)
    screen = callback.message.screens[0]
    assert "🔗 Chain — работает почти везде" in screen
    assert button_texts(callback.message.last_keyboard())[:3] == [
        texts.BTN_MAKE_CHAIN,
        texts.BTN_MAKE_REALITY,
        texts.BTN_MAKE_HYSTERIA,
    ]

    monkeypatch.setattr(ctx.settings, "enabled_client_profiles", ["reality"])
    callback = DummyCallback(cb.with_id(cb.CONN_NEW_P, device["id"]))
    await connections.create_menu(callback, DummyState(), tracegate_user=USER)
    assert "Chain" not in callback.message.screens[0]
    assert button_texts(callback.message.last_keyboard()) == [texts.BTN_MAKE_REALITY, texts.BTN_BACK, texts.BTN_HOME]


@pytest.mark.asyncio
async def test_create_menu_at_connection_limit(api: FakeApi) -> None:
    device = api.add_device()
    for _ in range(MAX_CONNECTIONS_PER_DEVICE):
        api.add_connection(device)
    callback = DummyCallback(cb.with_id(cb.CONN_NEW_P, device["id"]))
    await connections.create_menu(callback, DummyState(), tracegate_user=USER)
    assert callback.message.screens[0].count(texts.ERR_CONNECTION_LIMIT) == 1
    assert texts.BTN_NEW_CONNECTION not in button_texts(callback.message.last_keyboard())


@pytest.mark.asyncio
async def test_create_chain_edits_to_connection_page_and_delivers_config(api: FakeApi, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(delivery, "export_client_config", lambda _effective: _uri_export())
    device = api.add_device()
    callback = DummyCallback(cb.make(cb.MAKE_ENTRY, device["id"]))
    await connections.create_connection(callback, DummyState(), tracegate_user=USER)

    (args, _kwargs), = api.called("create_connection_and_revision")
    assert [value.value if hasattr(value, "value") else value for value in args[2:5]] == ["vless_reality", "chain", "V1"]
    assert args[6] is None
    assert callback.message.screens[0].startswith(texts.connection_created("Chain"))
    header = callback.message.sent_texts[0]
    assert header.startswith("✅ Готово! Вот настройки для «Chain».")
    assert callback.message.sent_texts[1].startswith("vless://")
    assert callback.message.photos[0]["caption"] == texts.qr_caption("Chain")
    assert callback_datas(callback.message.answers[0][1]["reply_markup"])[1] == cb.connection(
        next(iter(api.connections))
    )
    # Every delivery message is registered for later cleanup.
    assert len(api.called("register_bot_message")) == 3


@pytest.mark.asyncio
async def test_create_hysteria_passes_obfs_override(api: FakeApi, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(delivery, "export_client_config", lambda _effective: _uri_export(content="hysteria2://x"))
    device = api.add_device()
    menu = DummyCallback(cb.with_id(cb.CONN_HYSTERIA_P, device["id"]))
    await connections.hysteria_menu(menu, DummyState(), tracegate_user=USER)
    assert menu.message.screens == [texts.HYSTERIA_OBFS_SCREEN]

    callback = DummyCallback(cb.make(cb.MAKE_HYSTERIA_SALAMANDER, device["id"]))
    await connections.create_connection(callback, DummyState(), tracegate_user=USER)
    (args, _kwargs), = api.called("create_connection_and_revision")
    assert args[6] == {"hysteria_obfs": "salamander"}
    assert "Direct Hysteria · Salamander" in callback.message.sent_texts[0]


@pytest.mark.asyncio
async def test_create_disabled_profile_is_refused(api: FakeApi, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctx.settings, "enabled_client_profiles", ["reality"])
    device = api.add_device()
    callback = DummyCallback(cb.make(cb.MAKE_ENTRY, device["id"]))
    await connections.create_connection(callback, DummyState(), tracegate_user=USER)
    assert not api.called("create_connection_and_revision")
    assert callback.message.screens == [texts.ERR_PROFILE_DISABLED]


@pytest.mark.asyncio
async def test_create_failure_shows_russian_error_without_details(api: FakeApi) -> None:
    api.fail["create_connection_and_revision"] = ApiClientError(
        status_code=500, path="/revisions/by-connection/abc", detail="Internal Server Error: trace"
    )
    device = api.add_device()
    callback = DummyCallback(cb.make(cb.MAKE_REALITY, device["id"]))
    await connections.create_connection(callback, DummyState(), tracegate_user=USER)
    assert callback.message.screens == [texts.ERR_CREATE_CONNECTION]
    admin_callback = DummyCallback(cb.make(cb.MAKE_REALITY, device["id"]))
    await connections.create_connection(admin_callback, DummyState(), tracegate_user=ADMIN)
    assert "код ответа API 500" in admin_callback.message.screens[0]
    assert "/revisions" not in admin_callback.message.screens[0]
    assert "trace" not in admin_callback.message.screens[0]


@pytest.mark.asyncio
async def test_connection_page_shows_status_and_formats(api: FakeApi, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        delivery,
        "export_client_config",
        lambda _effective: _uri_export(attachment_content=b"{}", attachment_filename="x.xray.json"),
    )
    device = api.add_device(name="Телефон")
    connection = api.add_connection(device, mode="direct")
    callback = DummyCallback(cb.connection(connection["id"]))
    await connections.connection_page(callback, DummyState(), tracegate_user=USER)
    screen = callback.message.screens[0]
    assert screen.startswith("⚡ Direct VLESS\n📱 Устройство: Телефон")
    assert "Настройки действуют с 10.11.2026." in screen
    assert "Пришлю: ссылку, QR-код и файл .json." in screen
    assert connection["id"] not in screen


@pytest.mark.asyncio
async def test_retired_connection_allows_only_delete(api: FakeApi) -> None:
    device = api.add_device()
    legacy = api.add_connection(device, protocol="vless_ws_tls", mode="direct", variant="V0")
    callback = DummyCallback(cb.connection(legacy["id"]))
    await connections.connection_page(callback, DummyState(), tracegate_user=USER)
    assert callback.message.screens[0].startswith("🗂 Устаревшее подключение")
    assert button_texts(callback.message.last_keyboard()) == [texts.BTN_DELETE_CONNECTION, texts.BTN_BACK, texts.BTN_HOME]

    for handler, prefix in [
        (connections.show_config, cb.CONN_SHOW_P),
        (connections.reissue, cb.CONN_REISSUE_P),
        (connections.advanced, cb.CONN_ADVANCED_P),
    ]:
        action = DummyCallback(cb.with_id(prefix, legacy["id"]))
        await handler(action, DummyState(), tracegate_user=USER)
        assert action.message.screens[0].startswith(texts.ERR_RETIRED)
    assert not api.called("issue_revision")

    delete = DummyCallback(cb.with_id(cb.CONN_DELETE_P, legacy["id"]))
    await connections.delete_connection(delete, DummyState(), tracegate_user=USER)
    assert api.called("delete_connection")


@pytest.mark.asyncio
async def test_foreign_connection_is_not_found(api: FakeApi) -> None:
    foreign = api.add_connection(api.add_device(user_id=2))
    for handler, prefix in [
        (connections.connection_page, cb.CONN_P),
        (connections.reissue, cb.CONN_REISSUE_P),
        (connections.delete_connection, cb.CONN_DELETE_P),
    ]:
        callback = DummyCallback(cb.with_id(prefix, foreign["id"]))
        await handler(callback, DummyState(), tracegate_user=USER)
        assert callback.message.screens[0].startswith(texts.ERR_CONNECTION_NOT_FOUND)
    assert not api.called("issue_revision")
    assert not api.called("delete_connection")


@pytest.mark.asyncio
async def test_show_config_cleans_old_messages_and_uses_current_context(api: FakeApi, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(delivery, "export_client_config", lambda _effective: _uri_export())
    connection = api.add_connection(api.add_device())
    callback = DummyCallback(cb.with_id(cb.CONN_SHOW_P, connection["id"]))
    await connections.show_config(callback, DummyState(), tracegate_user=USER)
    assert api.called("cleanup_bot_messages")[0][1]["connection_id"] == connection["id"]
    assert callback.message.screens[0].startswith(texts.CONFIG_SENT)
    assert callback.message.sent_texts[0].startswith("📲 Вот настройки для «Chain».")


@pytest.mark.asyncio
async def test_reissue_confirm_then_issue(api: FakeApi, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(delivery, "export_client_config", lambda _effective: _uri_export())
    connection = api.add_connection(api.add_device())
    ask = DummyCallback(cb.with_id(cb.CONN_REISSUE_ASK_P, connection["id"]))
    await connections.confirm_reissue(ask, DummyState(), tracegate_user=USER)
    assert ask.message.screens == [texts.reissue_confirm("Chain")]
    assert callback_datas(ask.message.last_keyboard()) == [f"cre:{connection['id']}", f"conn:{connection['id']}", cb.MENU]
    assert not api.called("issue_revision")

    confirm = DummyCallback(cb.with_id(cb.CONN_REISSUE_P, connection["id"]))
    await connections.reissue(confirm, DummyState(), tracegate_user=USER)
    assert api.called("issue_revision") == [((connection["id"],), {})]
    assert api.called("cleanup_bot_messages")[0][1]["connection_id"] == connection["id"]
    assert confirm.message.screens[0].startswith(texts.REISSUED)
    assert "новые настройки" in confirm.message.sent_texts[0]


@pytest.mark.asyncio
async def test_slots_screen_activate_and_revoke(api: FakeApi) -> None:
    connection = api.add_connection(api.add_device(), revisions=2)
    revoked = api.add_revision(connection, slot=1, status="revoked")
    callback = DummyCallback(cb.with_id(cb.CONN_ADVANCED_P, connection["id"]))
    await connections.advanced(callback, DummyState(), tracegate_user=USER)
    screen = callback.message.screens[0]
    assert "• Основная" in screen and "• Запасная" in screen and "• Отключена" in screen
    assert callback_datas(callback.message.last_keyboard())[-2:] == [f"conn:{connection['id']}", cb.MENU]

    activate = DummyCallback(cb.with_id(cb.SLOT_ACTIVATE_P, revoked["id"]))
    await connections.activate_slot(activate, DummyState(), tracegate_user=USER)
    assert api.called("activate_revision") == [((revoked["id"],), {})]
    assert activate.message.screens[0].startswith(texts.SLOT_ACTIVATED)


@pytest.mark.asyncio
async def test_revoking_last_active_slot_returns_to_device(api: FakeApi) -> None:
    device = api.add_device(name="Телефон")
    connection = api.add_connection(device, revisions=1)
    (revision,) = [r for r in api.revisions.values() if r["connection_id"] == connection["id"]]
    ask = DummyCallback(cb.with_id(cb.SLOT_REVOKE_ASK_P, revision["id"]))
    await connections.confirm_revoke_slot(ask, DummyState(), tracegate_user=USER)
    assert "последние действующие настройки" in ask.message.screens[0]

    confirm = DummyCallback(cb.with_id(cb.SLOT_REVOKE_P, revision["id"]))
    await connections.revoke_slot(confirm, DummyState(), tracegate_user=USER)
    assert api.called("cleanup_bot_messages")[0][1]["revision_id"] == revision["id"]
    assert confirm.message.screens[0].startswith(texts.SLOT_REVOKED_CONNECTION_GONE)
    assert "📱 Телефон" in confirm.message.screens[0]


@pytest.mark.asyncio
async def test_delete_connection_returns_to_device_with_status(api: FakeApi) -> None:
    device = api.add_device(name="Телефон")
    connection = api.add_connection(device, mode="direct")
    ask = DummyCallback(cb.with_id(cb.CONN_DELETE_ASK_P, connection["id"]))
    await connections.confirm_delete_connection(ask, DummyState(), tracegate_user=USER)
    assert ask.message.screens == [texts.connection_delete_confirm("Direct VLESS")]

    confirm = DummyCallback(cb.with_id(cb.CONN_DELETE_P, connection["id"]))
    await connections.delete_connection(confirm, DummyState(), tracegate_user=USER)
    assert confirm.message.screens[0].startswith(texts.connection_deleted("Direct VLESS"))
    assert "Подключений: 0 из 5." in confirm.message.screens[0]
    assert confirm.message.answers == []


# ------------------------------------------------------- config delivery ---


async def _deliver(api: FakeApi, monkeypatch: pytest.MonkeyPatch, exported) -> DummyCallback:  # noqa: ANN001
    monkeypatch.setattr(delivery, "export_client_config", lambda _effective: exported)
    connection = api.add_connection(api.add_device(), mode="direct")
    revision = next(r for r in api.revisions.values() if r["connection_id"] == connection["id"])
    callback = DummyCallback("x")
    assert await delivery.send_client_config(callback, revision, context="created")
    return callback


@pytest.mark.asyncio
async def test_delivery_uri_hides_local_socks_and_sends_qr(api: FakeApi, monkeypatch: pytest.MonkeyPatch) -> None:
    exported = _uri_export(extra_messages=(("Local SOCKS5 credentials", "Host: 127.0.0.1\nPassword: local-pass"),))
    callback = await _deliver(api, monkeypatch, exported)
    assert len(callback.message.answers) == 2
    assert callback.message.sent_texts[1].startswith("vless://")
    assert len(callback.message.photos) == 1
    assert not any("local-pass" in text or "SOCKS5" in text for text in callback.message.sent_texts)


@pytest.mark.asyncio
async def test_delivery_attachment_only_sends_document_without_qr(api: FakeApi, monkeypatch: pytest.MonkeyPatch) -> None:
    exported = _uri_export(
        kind="attachment",
        content="Use the attached sing-box config.",
        attachment_content=b'{"log":{}}',
        attachment_filename="v5.singbox.json",
    )
    callback = await _deliver(api, monkeypatch, exported)
    assert len(callback.message.documents) == 1
    assert callback.message.photos == []
    assert "sing-box" in callback.message.sent_texts[0]
    assert not any("Use the attached" in text for text in callback.message.sent_texts)


@pytest.mark.asyncio
async def test_delivery_alternate_link_and_translated_extras(api: FakeApi, monkeypatch: pytest.MonkeyPatch) -> None:
    exported = _uri_export(
        content="hysteria2://primary",
        alternate_title="Hysteria2 fallback",
        alternate_content="hysteria2://alternate",
        extra_messages=(("Client compatibility", "Salamander is the broadly compatible Hysteria2 obfs mode."),),
        attachment_content=b"{}",
        attachment_filename="tracegate.singbox.json",
    )
    callback = await _deliver(api, monkeypatch, exported)
    sent = callback.message.sent_texts
    assert sent[2] == f"{texts.ALTERNATE_LINK_TITLE}\n\nhysteria2://alternate"
    assert sent[3].startswith("ℹ️ Совместимость")
    assert "broadly" not in sent[3]
    assert callback.message.documents[0]["caption"].startswith("📎 Файл для импорта")
    assert len(api.called("register_bot_message")) == 6


@pytest.mark.asyncio
async def test_delivery_export_error_is_russian(api: FakeApi, monkeypatch: pytest.MonkeyPatch) -> None:
    from tracegate.client_export.config import ClientConfigExportError

    def _raise(_effective):  # noqa: ANN001, ANN202
        raise ClientConfigExportError("Unsupported VLESS transport for export: 'x'")

    monkeypatch.setattr(delivery, "export_client_config", _raise)
    connection = api.add_connection(api.add_device())
    revision = next(r for r in api.revisions.values() if r["connection_id"] == connection["id"])
    callback = DummyCallback("x")
    assert not await delivery.send_client_config(callback, revision)
    assert callback.message.sent_texts == [texts.ERR_SHOW_CONFIG]


@pytest.mark.asyncio
async def test_cleanup_connection_messages_deduplicates_ids(api: FakeApi) -> None:
    api.cleanup_refs = [{"chat_id": 1, "message_id": 77}]
    callback = DummyCallback("x")
    await delivery.cleanup_connection_messages(callback, ["c-1", "c-2", "c-1", "", None])
    assert [kwargs["connection_id"] for _args, kwargs in api.called("cleanup_bot_messages")] == ["c-1", "c-2"]
    assert callback.bot.deleted == [(1, 77), (1, 77)]


# --------------------------------------------------------- Telegram Proxy ---


@pytest.mark.asyncio
async def test_tgp_screen_show_rotate_and_revoke(api: FakeApi) -> None:
    opened = DummyCallback(cb.TGP)
    await mtproto.tgp_open(opened, DummyState())
    assert "доступа пока нет" in opened.message.screens[0]
    assert callback_datas(opened.message.last_keyboard())[-1] == cb.MENU

    show = DummyCallback(cb.TGP_SHOW)
    await mtproto.tgp_show(show, DummyState(), tracegate_user={"telegram_id": 1, "telegram_username": "alice"})
    assert api.called("issue_mtproto_access")[-1][1] == {
        "telegram_id": 1,
        "label": "@alice",
        "rotate": False,
        "issued_by": "bot",
    }
    assert show.message.screens[0].startswith(texts.TGP_SENT_NEW)
    assert show.message.sent_texts[0].splitlines()[-1] == texts.MTPROTO_UPDATE_TELEGRAM_HINT
    assert show.message.photos[0]["caption"] == "📷 Основной маршрут"
    assert "node-a" not in show.message.screens[0] + show.message.sent_texts[0]

    rotate = DummyCallback(cb.TGP_ROTATE)
    await mtproto.tgp_rotate(rotate, DummyState(), tracegate_user={"telegram_id": 1})
    assert api.called("issue_mtproto_access")[-1][1]["rotate"] is True
    assert rotate.message.screens[0].startswith(texts.TGP_ROTATED)

    ask = DummyCallback(cb.TGP_REVOKE_ASK)
    await mtproto.tgp_revoke_ask(ask, DummyState())
    assert ask.message.screens == [texts.TGP_REVOKE_CONFIRM]
    revoke = DummyCallback(cb.TGP_REVOKE)
    await mtproto.tgp_revoke(revoke, DummyState(), tracegate_user=USER)
    assert revoke.message.screens[0].startswith(texts.TGP_REVOKED)
    again = DummyCallback(cb.TGP_REVOKE)
    await mtproto.tgp_revoke(again, DummyState(), tracegate_user=USER)
    assert again.message.screens[0].startswith(texts.TGP_NOT_FOUND)


@pytest.mark.asyncio
async def test_tgp_multiple_links_get_one_qr_each(api: FakeApi) -> None:
    async def _issue(**kwargs):  # noqa: ANN003, ANN202
        return {
            "profile": {
                "links": [
                    {"port": 8443, "httpsUrl": "https://t.me/proxy?port=8443"},
                    {"port": 443, "httpsUrl": "https://t.me/proxy?port=443"},
                ],
                "reused": True,
            }
        }

    api.issue_mtproto_access = _issue
    callback = DummyCallback(cb.TGP_SHOW)
    await mtproto.tgp_show(callback, DummyState(), tracegate_user={"telegram_id": 1})
    assert callback.message.screens[0].startswith(texts.TGP_SENT_AGAIN)
    assert [photo["caption"] for photo in callback.message.photos] == ["📷 Маршрут 1", "📷 Маршрут 2"]


@pytest.mark.asyncio
async def test_tgp_issue_error_is_mapped(api: FakeApi) -> None:
    api.fail["issue_mtproto_access"] = ApiClientError(status_code=503, path="/mtproto/access/issue", detail="down")
    callback = DummyCallback(cb.TGP_SHOW)
    await mtproto.tgp_show(callback, DummyState(), tracegate_user=USER)
    assert callback.message.screens == [texts.ERR_TGP]


# --------------------------------------------------------------- feedback ---


@pytest.mark.asyncio
async def test_feedback_flow_delivers_to_admins(api: FakeApi, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctx.settings, "superadmin_telegram_ids", [])
    monkeypatch.setattr(feedback.asyncio, "sleep", _no_sleep)
    api.users[7] = {"telegram_id": 7, "role": "admin"}
    callback = DummyCallback(cb.FEEDBACK)
    state = DummyState()
    await feedback.feedback_start(callback, state)
    assert state.state == FeedbackFlow.waiting_for_message
    assert callback.message.screens == [texts.FEEDBACK_PROMPT]

    sticker = DummyMessage(None)
    await feedback.feedback_message(sticker, state, tracegate_user=USER)
    assert sticker.sent_texts == [texts.FEEDBACK_NOT_TEXT]
    assert state.state == FeedbackFlow.waiting_for_message

    bot = DummyBot()
    message = DummyMessage("Не работает", bot=bot)
    await feedback.feedback_message(message, state, tracegate_user=dict(api.users[1]))
    assert state.state is None
    assert [row["chat_id"] for row in bot.sent] == [7]
    assert callback_datas(bot.sent[0]["reply_markup"]) == ["feedback_block:1"]
    assert message.sent_texts[0].startswith(texts.FEEDBACK_SENT)


@pytest.mark.asyncio
async def test_feedback_without_reachable_admins_reports_error(api: FakeApi, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctx.settings, "superadmin_telegram_ids", [])
    message = DummyMessage("Привет")
    await feedback.feedback_message(message, DummyState(state=FeedbackFlow.waiting_for_message), tracegate_user=USER)
    assert message.sent_texts == [texts.ERR_FEEDBACK]


async def _no_sleep(_seconds: float) -> None:
    return None


# ------------------------------------------------------- stale callbacks ---


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        ("connections", ("devices", None)),
        ("devices", ("devices", None)),
        ("guide_open", ("guide", None)),
        ("help_open", ("guide", None)),
        ("mtproto_open", ("tgp", None)),
        ("device:11111111-2222-3333-4444-555555555555", ("device", "11111111-2222-3333-4444-555555555555")),
        ("revs:11111111-2222-3333-4444-555555555555", ("connection", "11111111-2222-3333-4444-555555555555")),
        ("device:garbage", ("outdated", None)),
        ("new:entry:11111111-2222-3333-4444-555555555555", ("outdated", None)),
        ("vlessnew:v1:dev", ("outdated", None)),
        ("vlesstrans:v1:dev:reality", ("outdated", None)),
        ("prov:new:v1:dev:mts", ("outdated", None)),
        ("snipage:new:v1:dev:all:1", ("outdated", None)),
        ("catsel:1:all:0", ("outdated", None)),
        ("issuepick:conn", ("outdated", None)),
        ("delconn:11111111-2222-3333-4444-555555555555", ("outdated", None)),
        ("admin_user_revoke_notify:yes", ("outdated", None)),
        ("noop", ("outdated", None)),
        ("", ("outdated", None)),
    ],
)
def test_resolve_legacy(data: str, expected: tuple) -> None:
    assert fallback.resolve_legacy(data) == expected


@pytest.mark.asyncio
async def test_stale_callbacks_open_new_screens_or_outdated_menu(api: FakeApi) -> None:
    device = api.add_device(name="Телефон")
    connection = api.add_connection(device)

    old_device = DummyCallback(f"device:{device['id']}")
    await fallback.stale_callback(old_device, DummyState(), tracegate_user=USER)
    assert old_device.message.screens[0].startswith("📱 Телефон")

    old_revs = DummyCallback(f"revs:{connection['id']}")
    await fallback.stale_callback(old_revs, DummyState(), tracegate_user=USER)
    assert old_revs.message.screens[0].startswith("🔗 Chain")

    old_tgp = DummyCallback("mtproto_open")
    await fallback.stale_callback(old_tgp, DummyState(), tracegate_user=USER)
    assert old_tgp.message.screens[0].startswith("✈️ Telegram Proxy")
    assert not api.called("issue_mtproto_access")

    old_delete = DummyCallback(f"delconn:{connection['id']}")
    await fallback.stale_callback(old_delete, DummyState(), tracegate_user=USER)
    assert old_delete.message.screens == [texts.with_status(texts.MENU_OUTDATED, texts.MAIN_MENU)]
    assert not api.called("delete_connection")


@pytest.mark.asyncio
async def test_retired_profile_button_from_old_message_is_outdated(api: FakeApi) -> None:
    callback = DummyCallback(f"new:backup-ws:{new_id()}")
    await fallback.stale_callback(callback, DummyState(), tracegate_user=USER)
    assert callback.message.screens[0].startswith(texts.MENU_OUTDATED)
    assert not api.called("create_connection_and_revision")


@pytest.mark.asyncio
async def test_malformed_new_style_ids_are_outdated(api: FakeApi) -> None:
    for handler, data in [
        (devices.device_page, "dev:not-a-uuid"),
        (connections.connection_page, "conn:../../etc"),
        (connections.create_connection, "cmk:entry:zzz"),
        (connections.activate_slot, "sact:1"),
    ]:
        callback = DummyCallback(data)
        await handler(callback, DummyState(), tracegate_user=USER)
        assert callback.message.screens[0].startswith(texts.MENU_OUTDATED), data
    assert not [name for name, _a, _k in api.calls if name not in {"get_or_create_user"}]


@pytest.mark.asyncio
async def test_stray_text_message_gets_menu(api: FakeApi) -> None:
    message = DummyMessage("привет")
    await fallback.stray_message(message, tracegate_user=USER)
    assert message.sent_texts[0].startswith(texts.UNKNOWN_MESSAGE)


@pytest.mark.asyncio
async def test_safe_edit_falls_back_to_new_message_when_original_was_deleted() -> None:
    from aiogram.exceptions import TelegramBadRequest

    message = DummyMessage()
    message.edit_error = TelegramBadRequest(method=SimpleNamespace(), message="Bad Request: message to edit not found")
    assert await nav.safe_edit(message, "fresh text") is True
    assert message.sent_texts == ["fresh text"]


@pytest.mark.asyncio
async def test_unhandled_errors_get_generic_russian_notice() -> None:
    message = DummyMessage()
    event = SimpleNamespace(
        exception=ApiClientError(status_code=500, path="/x", detail="secret"),
        update=SimpleNamespace(callback_query=SimpleNamespace(message=message), message=None),
    )
    assert await nav.on_error(event) is True
    assert message.sent_texts == [texts.ERR_GENERIC]
