import sys
import types
from types import SimpleNamespace

import pytest


_qrcode_stub = types.ModuleType("qrcode")
_qrcode_stub.QRCode = object
_qrcode_stub.constants = types.SimpleNamespace(ERROR_CORRECT_M=0)
_orig_qrcode = sys.modules.get("qrcode")
_prom_stub = types.ModuleType("prometheus_client")
_prom_stub.Counter = lambda *args, **kwargs: None
_prom_stub.Gauge = lambda *args, **kwargs: None
_prom_stub.Histogram = lambda *args, **kwargs: None
_prom_stub.start_http_server = lambda *args, **kwargs: None
_orig_prometheus_client = sys.modules.get("prometheus_client")
sys.modules["qrcode"] = _qrcode_stub
sys.modules["prometheus_client"] = _prom_stub
try:
    from tracegate.bot import main
    from tracegate.settings import Settings
finally:
    if _orig_qrcode is None:
        sys.modules.pop("qrcode", None)
    else:
        sys.modules["qrcode"] = _orig_qrcode
    if _orig_prometheus_client is None:
        sys.modules.pop("prometheus_client", None)
    else:
        sys.modules["prometheus_client"] = _orig_prometheus_client


def test_format_config_delivery_message_uses_next_step_flow() -> None:
    text = main._format_config_delivery_message(
        marker="V1 - 1 - dev-1 - conn-1",
        title="VLESS Direct",
        revision={"id": "rev-1", "slot": 0},
        context="created",
    )

    assert "Конфигурация готова" in text
    assert "Подключение создано и готово к импорту." in text
    assert "Ревизия: rev-1" in text
    assert "Слот: 0" in text
    assert "1. Скопируйте ссылку" in text
    assert "2. Или используйте QR" in text
    assert "К устройству" not in text


def test_format_config_delivery_message_humanizes_current_revision_flow() -> None:
    text = main._format_config_delivery_message(
        marker="V3 - 1 - dev-2 - conn-2",
        title="Hysteria Direct",
        revision={"id": "rev-2", "slot": 1},
        context="current",
    )

    assert "Текущая активная ревизия готова к повторному импорту." in text
    assert "Ревизия: rev-2" in text
    assert "Слот: 1" in text


def test_format_config_delivery_message_mentions_attachment_when_available() -> None:
    text = main._format_config_delivery_message(
        marker="V1 - 1 - dev-1 - conn-1",
        title="VLESS Direct",
        revision={"id": "rev-1", "slot": 0},
        context="created",
        has_attachment=True,
    )

    assert "приложенный `.json` файл" in text
    assert "4. После импорта" in text


def test_format_config_delivery_message_mentions_hysteria_fallbacks() -> None:
    text = main._format_config_delivery_message(
        marker="V3 - 1 - dev-1 - conn-1",
        title="Hysteria2 Direct",
        revision={"id": "rev-1", "slot": 0},
        context="created",
        has_attachment=True,
        has_alternate_uri=True,
        has_extra_messages=True,
    )

    assert "raw-token fallback URI" in text
    assert "дополнительные параметры транспорта" in text
    assert "локальный SOCKS5" not in text


def test_format_grafana_otp_message_uses_tracegate2_copy() -> None:
    text = main._format_grafana_otp_message(
        scope="admin",
        otp={"expires_at": "2026-04-10T12:00:00Z", "login_url": "https://grafana.example.test/login"},
    )

    assert "Grafana" in text
    assert "Контур: административный" in text
    assert "Действует до: 2026-04-10T12:00:00Z" in text
    assert "Откройте доступ кнопкой ниже" in text
    assert "https://grafana.example.test/login" not in text
    assert "expires_at" not in text
    assert "link:" not in text


def test_grafana_otp_keyboard_uses_full_login_url() -> None:
    keyboard = main._grafana_otp_keyboard(
        {"login_url": "https://tracegate.test/grafana/login?code=otp-code&scope=user"}
    )

    assert keyboard is not None
    button = keyboard.inline_keyboard[0][0]
    assert button.text == "Открыть Grafana"
    assert button.url == "https://tracegate.test/grafana/login?code=otp-code&scope=user"


def test_format_mtproto_delivery_message_humanizes_reused_profile() -> None:
    text = main._format_mtproto_delivery_message(
        result={
            "node": "transit-a",
            "grant": {
                "label": "@user101",
                "updated_at": "2026-04-17T02:00:00Z",
            },
            "profile": {
                "server": "proxied.tracegate.test",
                "domain": "proxied.tracegate.test",
                "reused": True,
            },
        },
        rotate=False,
    )

    assert "Telegram Proxy" in text
    assert "Текущий постоянный Telegram Proxy-профиль отправлен повторно." in text
    assert "Transit: transit-a" in text
    assert "Метка: @user101" in text
    assert "Домен: proxied.tracegate.test" in text
    assert "Синхронизация: 2026-04-17T02:00:00Z" in text


def test_format_mtproto_delivery_message_humanizes_rotation() -> None:
    text = main._format_mtproto_delivery_message(
        result={
            "node": "transit-a",
            "grant": {},
            "profile": {"server": "proxied.tracegate.test"},
        },
        rotate=True,
    )

    assert "Секрет ротирован и готов к повторному запуску Telegram." in text


def test_main_menu_text_uses_tracegate2_copy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "_app_version", lambda: "2.0")

    text = main._main_menu_text()

    assert "Tracegate 2" in text
    assert "выбери активное устройство" in text
    assert "активного устройства" in text
    assert "Подключения" in text


def test_provider_label_uses_public_provider_caption() -> None:
    assert main._provider_label("all") == "Все"
    assert main._provider_label("mts") == "МТС"
    assert main._provider_label("unknown") == "unknown"


def test_connection_profile_label_uses_variant_and_family() -> None:
    assert main._connection_profile_label({"protocol": "vless_reality", "mode": "direct", "variant": "V1"}) == "V1-Direct-Reality-VLESS"
    assert main._connection_profile_label({"protocol": "hysteria2", "mode": "chain", "variant": "V2"}) == "V2-Chain-QUIC-Hysteria"
    assert main._connection_profile_label({"protocol": "vless_grpc_tls", "mode": "direct", "variant": "V0"}) == "V0-gRPC-VLESS"
    assert main._connection_profile_label({"protocol": "vless_ws_tls", "mode": "direct", "variant": "V0"}) == "V0-WS-VLESS"
    assert (
        main._connection_profile_label(
            {"protocol": "shadowsocks2022_shadowtls", "mode": "direct", "variant": "V3"}
        )
        == "V3-Direct-ShadowTLS-Shadowsocks"
    )
    assert (
        main._connection_profile_label({"protocol": "wireguard_wstunnel", "mode": "direct", "variant": "V0"})
        == "V0-WGWS-WireGuard"
    )


@pytest.mark.asyncio
async def test_render_device_page_uses_device_context_and_connection_cards(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _get_device(device_id: str) -> dict:
        return {"id": device_id, "name": "Laptop"}

    async def _list_connections(_device_id: str) -> list[dict]:
        return [
            {
                "id": "conn-1",
                "protocol": "vless_reality",
                "mode": "direct",
                "variant": "V1",
                "alias": "@alice (1) - Laptop - conn-1",
            },
            {
                "id": "conn-2",
                "protocol": "hysteria2",
                "mode": "chain",
                "variant": "V2",
                "alias": "",
            },
            {
                "id": "conn-3",
                "protocol": "shadowsocks2022_shadowtls",
                "mode": "direct",
                "variant": "V3",
                "alias": "",
            },
        ]

    monkeypatch.setattr(main.api, "get_device", _get_device)
    monkeypatch.setattr(main.api, "list_connections", _list_connections)

    text, _keyboard = await main.render_device_page("dev-1")

    assert "🔌 Устройство" in text
    assert "Имя: Laptop" in text
    assert "Подключений: 3" in text
    assert "• V1-Direct-Reality-VLESS" in text
    assert "• V2-Chain-QUIC-Hysteria" in text
    assert "• V3-Direct-ShadowTLS-Shadowsocks" in text
    assert "ID: conn-1" in text


@pytest.mark.asyncio
async def test_render_revisions_page_humanizes_revision_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _get_device(device_id: str) -> dict:
        return {"id": device_id, "name": "Laptop"}

    async def _get_connection(connection_id: str) -> dict:
        return {
            "id": connection_id,
            "protocol": "vless_reality",
            "mode": "direct",
            "alias": "",
            "variant": "V1",
            "user_id": "1",
            "device_id": "dev-1",
            "device_name": "Laptop",
        }

    async def _list_revisions(_connection_id: str) -> list[dict]:
        return [
            {"id": "rev-1", "slot": 0, "status": "ACTIVE"},
            {"id": "rev-2", "slot": 1, "status": "REVOKED"},
        ]

    monkeypatch.setattr(main.api, "get_device", _get_device)
    monkeypatch.setattr(main.api, "get_connection", _get_connection)
    monkeypatch.setattr(main.api, "list_revisions", _list_revisions)

    text, _keyboard = await main.render_revisions_page("conn-1")

    assert "🧩 Ревизии" in text
    assert "Профиль: V1-Direct-Reality-VLESS" in text
    assert "Устройство: Laptop" in text
    assert "Текущая ревизия: слот 0 · rev-1" in text
    assert "Слот 0 · активна" in text
    assert "Слот 1 · отозвана" in text


class _DummyMessage:
    def __init__(self) -> None:
        self.from_user = SimpleNamespace(id=1)
        self.answer_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        self.edit_text_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        self.answer_photo_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        self.answer_document_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    async def answer(self, *_args, **_kwargs):
        self.answer_calls.append((_args, _kwargs))
        return SimpleNamespace(message_id=1000 + len(self.answer_calls))

    async def edit_text(self, *_args, **_kwargs):
        self.edit_text_calls.append((_args, _kwargs))
        return None

    async def answer_photo(self, *_args, **_kwargs):
        self.answer_photo_calls.append((_args, _kwargs))
        return SimpleNamespace(message_id=2000 + len(self.answer_photo_calls))

    async def answer_document(self, *_args, **_kwargs):
        self.answer_document_calls.append((_args, _kwargs))
        return SimpleNamespace(message_id=3000 + len(self.answer_document_calls))


class _DummyCallback:
    def __init__(self, data: str) -> None:
        self.data = data
        self.message = _DummyMessage()
        self.answers: list[str] = []
        self.from_user = SimpleNamespace(id=1)

    async def answer(self, text: str | None = None, **_kwargs) -> None:
        self.answers.append(text or "")


class _DummyState:
    def __init__(self) -> None:
        self.states: list[object] = []
        self.cleared = 0

    async def set_state(self, value: object) -> None:
        self.states.append(value)

    async def clear(self) -> None:
        self.cleared += 1


def test_guide_text_defaults_to_external_placeholder(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main.settings, "bot_guide_path", "")
    monkeypatch.setattr(main.settings, "bot_guide_message", "[test-private-guide-placeholder]")

    assert main._load_guide_text() == "[test-private-guide-placeholder]"


def test_default_guide_copy_includes_client_settings_and_desktop_throne() -> None:
    guide = str(Settings.model_fields["bot_guide_message"].default)

    assert "Tracegate 2: гайдлайн" in guide
    assert "Рекомендуемые клиенты: Karing, INCY, Shadowrocket." in guide
    assert "Нормальные варианты для десктопа: Karing, INCY, Throne." in guide
    assert "в первую очередь для мобильного телефона" in guide
    assert "Для Karing: включай VPN/TUN mode" in guide
    assert "Для INCY: предпочитай VPN/TUN mode, а не proxy-only режим" in guide
    assert "Для Shadowrocket: не включай Proxy Sharing" in guide
    assert "External controller/API, web dashboard, debug API и HandlerService" in guide
    assert "Не импортируй один и тот же конфиг" in guide
    assert "Throne: https://throneproj.github.io/get_started/installation/" in guide
    assert "GitHub: https://github.com/MyHeartRaces/Tracegate" in guide


def test_guide_chunks_keep_app_links_in_second_message(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main.settings, "bot_guide_path", "")
    monkeypatch.setattr(
        main.settings,
        "bot_guide_message",
        (
            "Tracegate 2: гайдлайн\n\n"
            "Основной текст.\n\n"
            "Ссылки на приложения:\n\n"
            "Karing: https://karing.app/en/download/\n\n"
            "INCY: https://incy.cc\n\n"
            "Если не работает:\n"
            "Проверь активное устройство.\n\n"
            "GitHub: https://github.com/MyHeartRaces/Tracegate"
        ),
    )

    chunks = main._guide_chunks()

    assert len(chunks) == 2
    assert "Основной текст" in chunks[0]
    assert "Если не работает" in chunks[0]
    assert chunks[0].endswith("GitHub: https://github.com/MyHeartRaces/Tracegate")
    assert "Ссылки на приложения" not in chunks[0]
    assert "Karing: https://karing.app/en/download/" not in chunks[0]
    assert chunks[1].startswith("Ссылки на приложения:")
    assert "Karing: https://karing.app/en/download/" in chunks[1]
    assert "INCY: https://incy.cc" in chunks[1]
    assert "Если не работает" not in chunks[1]
    assert "GitHub:" not in chunks[1]


@pytest.mark.asyncio
async def test_help_button_opens_guide_directly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main.settings, "bot_guide_path", "")
    monkeypatch.setattr(main.settings, "bot_guide_message", "[test-guide-direct]")

    callback = _DummyCallback("help_open")
    await main.help_open(callback, _DummyState())

    args, kwargs = callback.message.edit_text_calls[0]
    assert "[test-guide-direct]" in str(args[0])
    keyboard = kwargs["reply_markup"]
    assert len(keyboard.inline_keyboard) == 1
    assert keyboard.inline_keyboard[0][0].callback_data == "menu"


@pytest.mark.asyncio
async def test_help_button_splits_long_guide(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main.settings, "bot_guide_path", "")
    monkeypatch.setattr(main.settings, "bot_guide_message", "A" * 4100)

    callback = _DummyCallback("guide_open")
    await main.guide_open(callback, _DummyState())

    assert len(callback.message.edit_text_calls) == 1
    assert callback.message.answer_calls
    assert len(str(callback.message.edit_text_calls[0][0][0])) <= main._TELEGRAM_TEXT_CHUNK_LIMIT
    assert all(len(str(args[0])) <= main._TELEGRAM_TEXT_CHUNK_LIMIT for args, _kwargs in callback.message.answer_calls)
    assert "reply_markup" not in callback.message.edit_text_calls[0][1]
    assert callback.message.answer_calls[-1][1]["reply_markup"].inline_keyboard[0][0].callback_data == "menu"


def test_format_config_delivery_message_supports_attachment_only_flow() -> None:
    text = main._format_config_delivery_message(
        marker="V3 - 1 - dev-1 - conn-1",
        title="Shadowsocks config",
        revision={"id": "rev-1", "slot": 0},
        context="created",
        has_attachment=True,
        has_primary_uri=False,
        has_extra_messages=True,
    )

    assert "Скачайте приложенный `.json` файл" in text
    assert "поддерживает sing-box JSON" in text
    assert "Скопируйте ссылку" not in text
    assert "QR" not in text


@pytest.mark.asyncio
async def test_send_client_config_handles_attachment_only_export(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _get_connection(_connection_id: str) -> dict:
        return {
            "id": "conn-1",
            "user_id": 1,
            "device_id": "dev-1",
            "device_name": "Laptop",
            "protocol": "shadowsocks2022_shadowtls",
            "mode": "direct",
            "variant": "V3",
        }

    exported = SimpleNamespace(
        kind="attachment",
        title="Shadowsocks-2022 + ShadowTLS config",
        content="Use the attached sing-box config.",
        alternate_title=None,
        alternate_content=None,
        extra_messages=(("Local SOCKS5 credentials", "Host: 127.0.0.1"),),
        attachment_content=b'{"log":{"level":"warn"}}',
        attachment_filename="v5.singbox.json",
        attachment_mime="application/json",
    )

    monkeypatch.setattr(main.api, "get_connection", _get_connection)
    monkeypatch.setattr(main, "export_client_config", lambda _effective: exported)

    callback = _DummyCallback("send")
    await main._send_client_config(
        callback,
        {
            "id": "rev-1",
            "slot": 0,
            "connection_id": "conn-1",
            "effective_config_json": {"protocol": "shadowsocks2022_shadowtls"},
        },
        context="created",
    )

    assert len(callback.message.answer_document_calls) == 1
    assert len(callback.message.answer_photo_calls) == 0
    assert not any("Неизвестный тип экспорта" in str(args[0]) for args, _kwargs in callback.message.answer_calls)
    assert "Скачайте приложенный `.json` файл" in str(callback.message.answer_calls[0][0][0])
    assert not any("Local SOCKS5 credentials" in str(args[0]) for args, _kwargs in callback.message.answer_calls)
    assert not any("Host: 127.0.0.1" in str(args[0]) for args, _kwargs in callback.message.answer_calls)


@pytest.mark.asyncio
async def test_send_client_config_hides_local_socks_extra_message(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _get_connection(_connection_id: str) -> dict:
        return {
            "id": "conn-1",
            "user_id": 1,
            "device_id": "dev-1",
            "device_name": "Phone",
            "protocol": "vless_reality",
            "mode": "direct",
            "variant": "V1",
        }

    exported = SimpleNamespace(
        kind="uri",
        title="VLESS Reality Direct",
        content="vless://user@example.com:443?security=reality#Tracegate",
        alternate_title=None,
        alternate_content=None,
        extra_messages=(("Local SOCKS5 credentials", "Host: 127.0.0.1\nPassword: local-pass"),),
        attachment_content=None,
        attachment_filename=None,
        attachment_mime=None,
    )

    monkeypatch.setattr(main.api, "get_connection", _get_connection)
    monkeypatch.setattr(main, "export_client_config", lambda _effective: exported)
    monkeypatch.setattr(main, "_build_qr_png", lambda payload: payload.encode("utf-8"))

    callback = _DummyCallback("send")
    await main._send_client_config(
        callback,
        {
            "id": "rev-1",
            "slot": 0,
            "connection_id": "conn-1",
            "effective_config_json": {"protocol": "vless_reality"},
        },
        context="created",
    )

    assert len(callback.message.answer_calls) == 2
    assert str(callback.message.answer_calls[1][0][0]).startswith("vless://")
    assert len(callback.message.answer_photo_calls) == 1
    assert not any("Local SOCKS5 credentials" in str(args[0]) for args, _kwargs in callback.message.answer_calls)
    assert not any("Password: local-pass" in str(args[0]) for args, _kwargs in callback.message.answer_calls)


@pytest.mark.asyncio
async def test_start_requires_two_step_welcome_before_menu(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main.settings, "bot_welcome_required", True)
    monkeypatch.setattr(main.settings, "bot_welcome_message", "[test-private-welcome-placeholder]")
    monkeypatch.setattr(main.settings, "bot_welcome_message_file", "")
    monkeypatch.setattr(main.settings, "bot_welcome_version", "v-test")

    async def _ensure_user(_telegram_id: int) -> dict:
        return {"telegram_id": 1, "role": "user", "bot_welcome_accepted_at": None, "bot_welcome_version": None}

    monkeypatch.setattr(main, "ensure_user", _ensure_user)

    message = _DummyMessage()
    await main.start(message)

    args, kwargs = message.answer_calls[0]
    assert "[test-private-welcome-placeholder]" in str(args[0])
    button = kwargs["reply_markup"].inline_keyboard[0][0]
    assert button.callback_data == "welcome_continue_1"
    assert button.text == "✅ Продолжить"


@pytest.mark.asyncio
async def test_welcome_continue_flow_persists_acceptance_and_opens_menu(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main.settings, "bot_welcome_required", True)
    monkeypatch.setattr(main.settings, "bot_welcome_version", "v-test")
    users = [
        {"telegram_id": 1, "role": "user", "bot_welcome_accepted_at": None, "bot_welcome_version": None},
        {"telegram_id": 1, "role": "user", "bot_welcome_accepted_at": None, "bot_welcome_version": None},
    ]
    accepted: dict[str, object] = {}

    async def _ensure_user(_telegram_id: int) -> dict:
        return users.pop(0) if users else accepted

    async def _accept_bot_welcome(telegram_id: int, *, version: str) -> dict:
        accepted.update(
            {
                "telegram_id": telegram_id,
                "role": "user",
                "bot_welcome_accepted_at": "2026-04-25T00:00:00+00:00",
                "bot_welcome_version": version,
            }
        )
        return accepted

    monkeypatch.setattr(main, "ensure_user", _ensure_user)
    monkeypatch.setattr(main.api, "accept_bot_welcome", _accept_bot_welcome)

    first = _DummyCallback("welcome_continue_1")
    await main.welcome_continue_1(first, _DummyState())
    args, kwargs = first.message.edit_text_calls[0]
    assert "Перед продолжением" in str(args[0])
    assert "Подтверди три правила" in str(args[0])
    button = kwargs["reply_markup"].inline_keyboard[0][0]
    assert button.callback_data == "welcome_continue_2"
    assert button.text == "✅ Подтверждаю и открываю меню"

    second = _DummyCallback("welcome_continue_2")
    await main.welcome_continue_2(second, _DummyState())
    args, kwargs = second.message.edit_text_calls[0]
    assert "Tracegate 2" in str(args[0])
    assert kwargs["reply_markup"].inline_keyboard[2][0].text == "📚 Справка"
    assert kwargs["reply_markup"].inline_keyboard[2][0].callback_data == "guide_open"
    assert accepted["bot_welcome_version"] == "v-test"


@pytest.mark.asyncio
async def test_feedback_start_uses_admin_copy_without_tracegate_team() -> None:
    callback = _DummyCallback("feedback_start")
    state = _DummyState()

    await main.feedback_start(callback, state)

    args, _kwargs = callback.message.answer_calls[0]
    text = str(args[0])
    assert "Напиши сообщение в обратную связь" in text
    assert "Его получат администраторы" in text
    assert "команды Tracegate" not in text


@pytest.mark.asyncio
async def test_mtproto_open_issues_profile_and_sends_links(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _ensure_user(_telegram_id: int) -> dict:
        return {
            "telegram_id": 1,
            "telegram_username": "alice",
            "telegram_first_name": "Alice",
            "telegram_last_name": None,
        }

    async def _issue_mtproto_access(**kwargs) -> dict:
        assert kwargs == {
            "telegram_id": 1,
            "label": "@alice",
            "rotate": False,
            "issued_by": "bot",
        }
        return {
            "node": "transit-a",
            "grant": {"label": "@alice", "updated_at": "2026-04-17T02:00:00Z"},
            "profile": {
                "server": "proxied.tracegate.test",
                "domain": "proxied.tracegate.test",
                "httpsUrl": "https://t.me/proxy?server=proxied.tracegate.test&port=443&secret=ee0011",
                "tgUri": "tg://proxy?server=proxied.tracegate.test&port=443&secret=ee0011",
                "reused": False,
            },
        }

    monkeypatch.setattr(main, "ensure_user", _ensure_user)
    monkeypatch.setattr(main.api, "issue_mtproto_access", _issue_mtproto_access)
    monkeypatch.setattr(main, "_build_qr_png", lambda payload: payload.encode("utf-8"))

    callback = _DummyCallback("mtproto_open")
    await main.mtproto_open(callback)

    assert len(callback.message.answer_calls) == 2
    assert "Telegram Proxy" in callback.message.answer_calls[0][0][0]
    assert "https://t.me/proxy" in callback.message.answer_calls[1][0][0]
    assert len(callback.message.answer_photo_calls) == 1
    assert "Telegram Proxy отправлен" in callback.answers[-1]


@pytest.mark.asyncio
async def test_show_current_revision_config_cleans_connection_and_uses_current_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    async def _list_revisions(_connection_id: str) -> list[dict]:
        return [{"id": "rev-1", "slot": 0, "status": "ACTIVE", "connection_id": "conn-1"}]

    async def _cleanup_related_messages(_callback, **kwargs) -> None:
        captured["cleanup"] = kwargs

    async def _send_client_config(_callback, revision: dict, *, context: str = "default") -> None:
        captured["revision"] = revision["id"]
        captured["context"] = context

    monkeypatch.setattr(main.api, "list_revisions", _list_revisions)
    monkeypatch.setattr(main, "_cleanup_related_messages", _cleanup_related_messages)
    monkeypatch.setattr(main, "_send_client_config", _send_client_config)

    callback = _DummyCallback("showcur:conn-1")
    await main.show_current_revision_config(callback)

    assert captured["cleanup"] == {"connection_id": "conn-1"}
    assert captured["revision"] == "rev-1"
    assert captured["context"] == "current"
    assert any("Конфиг отправлен в чат" in answer for answer in callback.answers)


@pytest.mark.asyncio
async def test_cleanup_connection_messages_deduplicates_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[dict[str, str]] = []

    async def _cleanup_related_messages(_callback, **kwargs) -> None:
        captured.append(kwargs)

    monkeypatch.setattr(main, "_cleanup_related_messages", _cleanup_related_messages)

    callback = _DummyCallback("noop")
    await main._cleanup_connection_messages(callback, ["conn-1", "conn-2", "conn-1", "", None])

    assert captured == [{"connection_id": "conn-1"}, {"connection_id": "conn-2"}]


@pytest.mark.asyncio
async def test_issue_revision_cleans_connection_and_uses_issued_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    async def _issue_revision(_connection_id: str) -> dict:
        return {"id": "rev-2", "slot": 1, "connection_id": "conn-1"}

    async def _render_revisions_page(_connection_id: str) -> tuple[str, object]:
        return ("revisions", object())

    async def _safe_edit_text(_message, _text: str, reply_markup: object | None = None) -> bool:
        captured["edited"] = bool(reply_markup)
        return True

    async def _cleanup_related_messages(_callback, **kwargs) -> None:
        captured["cleanup"] = kwargs

    async def _send_client_config(_callback, revision: dict, *, context: str = "default") -> None:
        captured["revision"] = revision["id"]
        captured["context"] = context

    monkeypatch.setattr(main.api, "issue_revision", _issue_revision)
    monkeypatch.setattr(main, "render_revisions_page", _render_revisions_page)
    monkeypatch.setattr(main, "_safe_edit_text", _safe_edit_text)
    monkeypatch.setattr(main, "_cleanup_related_messages", _cleanup_related_messages)
    monkeypatch.setattr(main, "_send_client_config", _send_client_config)

    callback = _DummyCallback("issueplain:conn-1")
    await main.issue_revision(callback)

    assert captured["edited"] is True
    assert captured["cleanup"] == {"connection_id": "conn-1"}
    assert captured["revision"] == "rev-2"
    assert captured["context"] == "issued"


@pytest.mark.asyncio
async def test_add_device_prompt_includes_inline_cancel() -> None:
    callback = _DummyCallback("add_device")
    state = _DummyState()

    await main.add_device(callback, state)

    assert state.states
    args, kwargs = callback.message.answer_calls[0]
    assert "Введите имя устройства" in str(args[0])
    button = kwargs["reply_markup"].inline_keyboard[0][0]
    assert button.text == "↩️ Отмена"
    assert button.callback_data == "menu"
