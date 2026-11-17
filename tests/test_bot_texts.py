from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

import test_bot_support  # noqa: F401  (imports the bot with a complete metrics stub)
from tracegate.bot import keyboards, nav, profiles, texts
from tracegate.bot.access import blocked_message
from tracegate.bot.client import ApiClientError
from tracegate.services import connection_profiles
from tracegate.settings import Settings

ROOT = Path(__file__).resolve().parents[1]
BOT_DIR = ROOT / "src" / "tracegate" / "bot"

FORMAL_WORDS = re.compile(r"\b(вы|вас|вам|вами|ваш\w*)\b", re.IGNORECASE)
FORMAL_IMPERATIVES = re.compile(
    r"\b(Введите|Выберите|Откройте|Нажмите|Скопируйте|Скачайте|Используйте|Подтвердите|Добавьте|"
    r"Попробуйте|Напишите|Импортируйте|Отправьте|Укажите|Проверьте|Повторите|Обновите|Перевыпустите|"
    r"Удалите|Создайте|Запросите)\b",
    re.IGNORECASE,
)
ALLOWED_LATIN_WORDS = {
    "Chain",
    "Direct",
    "Tracegate",
    "Telegram",
    "Proxy",
    "VLESS",
    "Hysteria",
    "Salamander",
    "Gecko",
    "Grafana",
    "QR",
    "iPhone",
    "iPad",
    "Android",
    "Windows",
    "macOS",
    "Linux",
}


def _russian_sources() -> dict[str, str]:
    sources = {
        "texts.py": (BOT_DIR / "texts.py").read_text(encoding="utf-8"),
        "keyboards.py": (BOT_DIR / "keyboards.py").read_text(encoding="utf-8"),
        "default bot_guide_message": str(Settings.model_fields["bot_guide_message"].default),
        "default bot_welcome_message": str(Settings.model_fields["bot_welcome_message"].default),
    }
    return sources


@pytest.mark.parametrize("name", list(_russian_sources()))
def test_user_strings_use_informal_ty(name: str) -> None:
    source = _russian_sources()[name]
    assert not FORMAL_WORDS.findall(source), name
    assert not FORMAL_IMPERATIVES.findall(source), name


def _all_button_texts() -> list[str]:
    from tracegate.bot import callbacks as cb

    device_id = "11111111-2222-3333-4444-555555555555"
    connection = {"id": device_id, "protocol": "vless_reality", "mode": "chain", "variant": "V1"}
    revisions = [
        {"id": device_id, "slot": 0, "status": "active", "created_at": "2026-11-17T10:00:00Z"},
        {"id": device_id, "slot": 1, "status": "active", "created_at": "2026-11-16T10:00:00Z"},
        {"id": device_id, "slot": 1, "status": "revoked", "created_at": "2026-11-15T10:00:00Z"},
    ]
    built = [
        keyboards.main_menu_keyboard(is_admin=True, grafana_enabled=True),
        keyboards.devices_keyboard([{"id": device_id, "name": "Телефон"}], {device_id: 2}),
        keyboards.device_keyboard(device_id, [connection], can_create=True),
        keyboards.create_connection_keyboard(device_id, {"entry", "reality", "hysteria"}),
        keyboards.hysteria_obfs_keyboard(device_id),
        keyboards.connection_keyboard(device_id, device_id),
        keyboards.slots_keyboard(device_id, revisions),
        keyboards.config_delivery_keyboard(connection_id=device_id),
        keyboards.tgp_keyboard(),
        keyboards.feedback_keyboard(),
        keyboards.grafana_keyboard("https://grafana.example.test"),
        keyboards.admin_menu_keyboard(is_superadmin=True),
        keyboards.admin_back_keyboard(),
        keyboards.admin_cancel_keyboard(),
        keyboards.admin_tgp_keyboard(),
        keyboards.admin_notify_keyboard(),
        keyboards.admin_reset_keyboard(),
        keyboards.feedback_admin_keyboard(telegram_id=42),
        keyboards.welcome_keyboard(1),
        keyboards.welcome_keyboard(2),
        keyboards.guide_keyboard([], back_callback=cb.GUIDE),
    ]
    out = [str(button.text) for keyboard in built for row in keyboard.inline_keyboard for button in row]
    out.extend(value for name, value in vars(texts).items() if name.startswith("BTN_"))
    for kind in ("entry", "reality", "hysteria", "legacy", "other"):
        out.append(texts.connection_button(kind, texts.LABEL_DIRECT_HYSTERIA + " · " + texts.LABEL_SALAMANDER))
    return out


def test_buttons_have_no_english_words_except_product_names() -> None:
    offenders: set[str] = set()
    for text in _all_button_texts():
        for word in re.findall(r"[A-Za-z][A-Za-z0-9]*", text):
            if word not in ALLOWED_LATIN_WORDS:
                offenders.add(f"{word!r} in {text!r}")
    assert not offenders


def test_main_menu_is_versionless_tracegate() -> None:
    assert texts.MAIN_MENU.startswith("🏠 Tracegate\n")
    assert "Tracegate 3" not in texts.MAIN_MENU
    assert not re.search(r"Tracegate \d", texts.MAIN_MENU)


def test_welcome_rules_drop_active_device_and_use_tracegate4_wording() -> None:
    assert "активного устройства" not in texts.WELCOME_RULES
    assert "одно устройство и одно приложение" in texts.WELCOME_RULES
    assert "LAN" in texts.WELCOME_RULES


def test_default_guide_uses_tracegate4_terms_without_private_app_content() -> None:
    guide = str(Settings.model_fields["bot_guide_message"].default)
    for needle in ("Chain", "Direct VLESS", "Direct Hysteria", "Перевыпустить"):
        assert needle in guide
    for needle in ("Tracegate 3", "ревизи", "Karing", "INCY", "Shadowrocket", "Throne", "http://", "https://"):
        assert needle not in guide
    welcome = str(Settings.model_fields["bot_welcome_message"].default)
    assert "Tracegate 3" not in welcome
    assert "Мои устройства" in welcome


# ------------------------------------------------------------ delivery ---


def test_config_delivery_uri_flow_has_three_steps() -> None:
    text = texts.config_delivery_message(label="Chain", context="created")
    assert text.startswith("✅ Готово! Вот настройки для «Chain».")
    assert "1. Открой приложение" in text
    assert "2. Импортируй настройки: скопируй ссылку" in text
    assert "3. Включи подключение" in text
    assert "файл .json" not in text
    assert "Ревизия" not in text and "Слот" not in text


def test_config_delivery_contexts() -> None:
    assert "новые настройки" in texts.config_delivery_message(label="X", context="issued")
    assert texts.config_delivery_message(label="X", context="current").startswith("📲 Вот настройки")


def test_config_delivery_mentions_attachment_fallback() -> None:
    text = texts.config_delivery_message(label="X", has_attachment=True)
    assert "Если ссылка не подходит, импортируй файл .json." in text


def test_config_delivery_can_prefer_xray_attachment() -> None:
    text = texts.config_delivery_message(label="X", has_attachment=True, prefer_attachment=True)
    assert "2. Импортируй файл .json из сообщения ниже. Если приложение его не принимает" in text
    assert "скопируй ссылку" not in text


def test_config_delivery_attachment_only_flow() -> None:
    text = texts.config_delivery_message(label="X", has_primary_uri=False, has_attachment=True)
    assert "sing-box" in text
    assert "QR" not in text
    assert "скопируй ссылку" not in text


def test_config_delivery_mentions_alternate_and_extras() -> None:
    text = texts.config_delivery_message(label="X", has_alternate_uri=True, has_extra_messages=True)
    assert "запасная ссылка" in text
    assert "пояснения" in text


def test_extra_messages_are_translated() -> None:
    gecko = texts.extra_message(
        "Client compatibility",
        "Gecko requires the official Hysteria client with Gecko support; sing-box does not support Gecko.",
    )
    assert gecko.startswith("ℹ️ Совместимость")
    assert "официальном приложении Hysteria" in gecko
    assert "requires" not in gecko


# ------------------------------------------------------------- labels ---


@pytest.mark.parametrize(
    ("connection", "label"),
    [
        ({"protocol": "vless_reality", "mode": "chain", "variant": "V1"}, "Chain"),
        ({"protocol": "vless_reality", "mode": "direct", "variant": "V1"}, "Direct VLESS"),
        (
            {"protocol": "hysteria2", "mode": "direct", "variant": "V2", "custom_overrides_json": {"hysteria_obfs": "salamander"}},
            "Direct Hysteria · Salamander",
        ),
        (
            {"protocol": "hysteria2", "mode": "direct", "variant": "V2", "custom_overrides_json": {"hysteria_obfs": "gecko"}},
            "Direct Hysteria · Gecko",
        ),
        ({"protocol": "hysteria2", "mode": "direct", "variant": "V2"}, "Direct Hysteria"),
        ({"protocol": "vless_ws_tls", "mode": "direct", "variant": "V0"}, "Устаревшее подключение"),
        ({"protocol": "vless_grpc_tls", "mode": "chain", "variant": "V5"}, "Устаревшее подключение"),
        ({"protocol": "hysteria2", "mode": "chain", "variant": "V2"}, "Устаревшее подключение"),
        ({"protocol": "shadowsocks2022_shadowtls", "mode": "direct", "variant": "V3"}, "Подключение"),
    ],
)
def test_connection_labels_are_russian(connection: dict, label: str) -> None:
    assert profiles.connection_label(connection) == label


def test_connection_label_hides_auto_alias_with_id_but_shows_custom_alias() -> None:
    connection_id = "11111111-2222-3333-4444-555555555555"
    auto = {"id": connection_id, "protocol": "vless_reality", "mode": "chain", "alias": f"@a (1) - Phone - {connection_id}"}
    assert profiles.connection_label(auto) == "Chain"
    custom = {**auto, "alias": "Рабочий"}
    assert profiles.connection_label(custom) == "Chain · Рабочий"


def test_reissue_confirm_matches_server_revision_semantics() -> None:
    # services/revisions.py keeps the previous revision ACTIVE in the reserve
    # slot after an issue and revokes older ones. The copy depends on it.
    assert connection_profiles.MAX_ACTIVE_REVISIONS_PER_CONNECTION == 2
    assert connection_profiles.RESERVE_REVISION_SLOT == 1
    text = texts.reissue_confirm("Chain")
    assert "Старые настройки продолжат работать, пока не перевыпустишь ещё раз" in text


# ------------------------------------------------------- telegram proxy ---


def test_mtproto_link_message_lists_every_route_then_update_hint() -> None:
    text = texts.format_mtproto_link_message(
        {
            "links": [
                {"port": 8443, "httpsUrl": "https://t.me/proxy?port=8443", "tgUri": "tg://proxy?port=8443"},
                {"port": 443, "httpsUrl": "https://t.me/proxy?port=443", "tgUri": "tg://proxy?port=443"},
            ]
        }
    )
    assert "Порт 8443" in text and "port=8443" in text
    assert "Порт 443" in text and "tg://proxy?port=443" in text
    assert text.splitlines()[-1] == texts.MTPROTO_UPDATE_TELEGRAM_HINT


def test_tgp_screen_states() -> None:
    assert "доступ выдан" in texts.tgp_screen(has_access=True)
    assert "доступа пока нет" in texts.tgp_screen(has_access=False)
    assert "Статус" not in texts.tgp_screen(has_access=None)


# ------------------------------------------------------- error mapping ---


def test_error_mapping_never_exposes_api_details() -> None:
    exc = ApiClientError(status_code=500, path="/connections/abc-123", detail='{"detail":"Traceback secret"}')
    text = nav.user_error_text(exc, fallback=texts.ERR_CREATE_CONNECTION)
    assert text == texts.ERR_CREATE_CONNECTION
    admin_text = nav.user_error_text(exc, fallback=texts.ERR_CREATE_CONNECTION, admin=True)
    assert "500" in admin_text
    for leaked in ("/connections", "abc-123", "Traceback", "secret", "detail"):
        assert leaked not in text
        assert leaked not in admin_text


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (ApiClientError(status_code=400, path="/devices", detail='{"detail":"Device limit reached (4)"}'), texts.ERR_DEVICE_LIMIT),
        (
            ApiClientError(status_code=403, path="/devices", detail='{"detail":"Cannot issue new device in grace/blocked state"}'),
            texts.ERR_ISSUE_FORBIDDEN,
        ),
        (ValueError(connection_profiles.RETIRED_CLIENT_PROTOCOL_MESSAGE), texts.ERR_RETIRED),
        (profiles.ProfileDisabledError("hysteria"), texts.ERR_PROFILE_DISABLED),
        (ValueError("invalid literal for int() with base 10: 'abc'"), texts.ERR_GENERIC),
        (RuntimeError("boom"), texts.ERR_GENERIC),
    ],
)
def test_error_mapping_known_cases(exc: BaseException, expected: str) -> None:
    assert nav.user_error_text(exc) == expected


def test_blocked_message_keeps_existing_format() -> None:
    text = blocked_message({"bot_blocked_until": "2026-03-06T12:00:00+00:00", "bot_block_reason": "abuse"})
    assert "временно ограничен до 2026-03-06T12:00:00+00:00" in text
    assert "Причина: abuse" in text


def test_block_notification_uses_ty() -> None:
    text = texts.block_notification(
        blocked_at=datetime(2026, 11, 17, 10, 0, tzinfo=timezone.utc), hours=72, until=None, reason=None
    )
    assert text.startswith("⚠️ Администратор ограничил тебе доступ")
    assert "72 ч." in text


def test_handlers_have_no_cyrillic_literals() -> None:
    # All user-facing copy lives in texts.py.
    for path in sorted((BOT_DIR / "handlers").glob("*.py")) + [BOT_DIR / "main.py", BOT_DIR / "nav.py"]:
        source = path.read_text(encoding="utf-8")
        code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))
        # Docstrings may describe screens in Russian; string literals in code may not.
        code = re.sub(r'"""[\s\S]*?"""', "", code)
        assert not re.search(r"[А-Яа-яЁё]", code), path.name
