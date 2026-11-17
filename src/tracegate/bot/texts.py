"""All user-facing bot strings (Russian, informal "ты").

Handlers and keyboards must not contain user-facing literals; they take them
from here. Admin report tables live in ``admin_tools.py``.
"""

from __future__ import annotations

from datetime import datetime, timezone

from tracegate.services.bot_blocks import (
    MAX_TIMED_BOT_BLOCK_HOURS,
    PERMANENT_BOT_BLOCK_HOURS,
    is_permanent_bot_block_hours,
)
from tracegate.services.connection_profiles import (
    MAX_CONNECTIONS_PER_DEVICE,
    MAX_DEVICES_PER_USER,
)

DEVICE_NAME_MAX_LENGTH = 128
BLOCK_REASON_MAX_LENGTH = 255

# ---------------------------------------------------------------- buttons ---

BTN_HOME = "🏠 Меню"
BTN_BACK = "↩️ Назад"
BTN_CANCEL = "↩️ Отмена"

BTN_DEVICES = "📱 Мои устройства"
BTN_TGP = "✈️ Telegram Proxy"
BTN_GUIDE = "📖 Инструкция"
BTN_FEEDBACK = "💬 Написать админу"
BTN_GRAFANA = "📊 Grafana"
BTN_ADMIN = "🛠 Управление"

BTN_ADD_DEVICE = "➕ Добавить устройство"
BTN_NEW_CONNECTION = "➕ Новое подключение"
BTN_RENAME_DEVICE = "✏️ Переименовать"
BTN_DELETE_DEVICE = "🗑 Удалить устройство"
BTN_CONFIRM_DELETE = "🗑 Да, удалить"

BTN_MAKE_CHAIN = "🔗 Chain — рекомендуется"
BTN_MAKE_REALITY = "⚡ Direct VLESS"
BTN_MAKE_HYSTERIA = "🚀 Direct Hysteria"
BTN_SALAMANDER = "Salamander — рекомендуется"
BTN_GECKO = "Gecko"

BTN_SHOW_CONFIG = "📲 Показать настройки"
BTN_REISSUE = "🔄 Перевыпустить"
BTN_CONFIRM_REISSUE = "🔄 Да, перевыпустить"
BTN_ADVANCED = "⚙️ Дополнительно"
BTN_DELETE_CONNECTION = "🗑 Удалить подключение"
BTN_HOWTO = "📖 Как подключить"
BTN_TO_CONNECTION = "🔙 К подключению"
BTN_CONFIRM_SLOT_REVOKE = "🗑 Да, отключить"

BTN_TGP_SHOW = "📲 Показать ссылку"
BTN_TGP_ROTATE = "🔄 Сменить ссылку"
BTN_TGP_REVOKE = "⛔ Отозвать доступ"
BTN_TGP_CONFIRM_REVOKE = "⛔ Да, отозвать"

BTN_GRAFANA_OPEN = "📊 Открыть Grafana"

BTN_WELCOME_CONTINUE = "✅ Продолжить"
BTN_WELCOME_ACCEPT = "✅ Принимаю, открыть меню"

BTN_ADMIN_USERS = "👥 Пользователи"
BTN_ADMIN_TGP = "✈️ Telegram Proxy"
BTN_ADMIN_REVOKE_ACCESS = "⛔ Отозвать доступ"
BTN_ADMIN_BLOCK = "🚫 Заблокировать"
BTN_ADMIN_UNBLOCK = "✅ Разблокировать"
BTN_ADMIN_RESET = "🧹 Отозвать всё у всех"
BTN_ADMIN_RESET_CONFIRM = "🧹 Да, отозвать всё"
BTN_ADMIN_GRANT = "➕ Назначить админа"
BTN_ADMIN_UNGRANT = "➖ Снять админа"
BTN_ADMIN_LIST = "👤 Список админов"
BTN_ADMIN_REFRESH = "🔄 Обновить"
BTN_ADMIN_TGP_REVOKE = "⛔ Отозвать Telegram Proxy"
BTN_ADMIN_NOTIFY_YES = "✅ Да, уведомить"
BTN_ADMIN_NOTIFY_NO = "🔕 Нет, без уведомления"
BTN_ADMIN_BACK = "↩️ К управлению"
BTN_FEEDBACK_BLOCK = "🚫 Заблокировать автора"

# Bot command menu (set_my_commands).
COMMANDS: tuple[tuple[str, str], ...] = (
    ("start", "Меню"),
    ("guide", "Инструкция"),
    ("cancel", "Отмена"),
)

# ------------------------------------------------------------- generic ------

PRIVATE_CHAT_ONLY = "Эта команда работает только в личном чате с ботом."
CANCELLED = "Отменил."
MENU_OUTDATED = "⌛ Это меню устарело — вот актуальное."
UNKNOWN_MESSAGE = "Я понимаю только кнопки и команды. Вот меню:"
ACCESS_LIMITED_ALERT = "Доступ ограничен"
WELCOME_REQUIRED_ALERT = "Сначала прочитай приветствие и нажми кнопку под ним"

ERR_GENERIC = "Что-то пошло не так. Попробуй ещё раз чуть позже."
ERR_LOAD = "Не получилось загрузить данные. Попробуй ещё раз чуть позже."
ERR_CREATE_CONNECTION = "Не получилось создать подключение. Попробуй ещё раз чуть позже."
ERR_REISSUE = "Не получилось перевыпустить настройки. Попробуй ещё раз чуть позже."
ERR_SHOW_CONFIG = "Не получилось подготовить настройки. Попробуй «🔄 Перевыпустить» или напиши админу."
ERR_DELETE_CONNECTION = "Не получилось удалить подключение. Попробуй ещё раз чуть позже."
ERR_ADD_DEVICE = "Не получилось добавить устройство. Попробуй ещё раз чуть позже."
ERR_RENAME_DEVICE = "Не получилось переименовать устройство. Попробуй ещё раз чуть позже."
ERR_DELETE_DEVICE = "Не получилось удалить устройство. Попробуй ещё раз чуть позже."
ERR_SLOT = "Не получилось изменить настройки. Попробуй ещё раз чуть позже."
ERR_TGP = "Не получилось выдать ссылку на Telegram Proxy. Попробуй ещё раз чуть позже."
ERR_TGP_REVOKE = "Не получилось отозвать доступ к Telegram Proxy. Попробуй ещё раз чуть позже."
ERR_FEEDBACK = "Не получилось отправить сообщение. Попробуй ещё раз чуть позже."
ERR_GRAFANA = "Не получилось выдать ссылку на Grafana. Попробуй ещё раз чуть позже."
ERR_ADMIN = "Не получилось выполнить действие. Попробуй ещё раз чуть позже."
ERR_DEVICE_LIMIT = (
    f"Можно добавить не больше {MAX_DEVICES_PER_USER} устройств. Удали ненужное, чтобы добавить новое."
)
ERR_CONNECTION_LIMIT = (
    f"На одном устройстве может быть не больше {MAX_CONNECTIONS_PER_DEVICE} подключений. "
    "Удали ненужное, чтобы создать новое."
)
ERR_ISSUE_FORBIDDEN = "Сейчас выпуск новых настроек для тебя закрыт. Напиши админу."
ERR_DEVICE_NOT_FOUND = "Устройство не найдено — возможно, его уже удалили."
ERR_CONNECTION_NOT_FOUND = "Подключение не найдено — возможно, его уже удалили."
ERR_PROFILE_DISABLED = "Этот вариант подключения сейчас выключен. Выбери другой."
ERR_RETIRED = "Этот тип подключения больше не поддерживается. Создай новое — лучше «🔗 Chain»."


def admin_error_reference(status_code: int | None, error_name: str | None = None) -> str:
    if status_code:
        return f"Для админа: код ответа API {int(status_code)}."
    return f"Для админа: {error_name or 'ошибка'}."


def warn(text: str) -> str:
    return f"⚠️ {text}"


def with_status(status: str | None, body: str) -> str:
    status_text = str(status or "").strip()
    if not status_text:
        return body
    return f"{status_text}\n\n{body}"


def clip(value: object, max_len: int = 40) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= max_len:
        return text
    return text[: max_len - 1].rstrip() + "…"


def _parse_datetime(raw: object) -> datetime | None:
    if isinstance(raw, datetime):
        value = raw
    else:
        text = str(raw or "").strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            value = datetime.fromisoformat(text)
        except ValueError:
            return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def format_date(raw: object) -> str:
    value = _parse_datetime(raw)
    return value.strftime("%d.%m.%Y") if value else "—"


def format_datetime(raw: object) -> str:
    value = _parse_datetime(raw)
    return value.strftime("%d.%m.%Y %H:%M UTC") if value else "—"


def format_short_datetime(raw: object) -> str:
    value = _parse_datetime(raw)
    return value.strftime("%d.%m %H:%M") if value else "—"


def _join_ru(items: list[str]) -> str:
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " и " + items[-1]


# -------------------------------------------------------------- welcome -----

WELCOME_FALLBACK = (
    "Привет! Это Tracegate.\n\n"
    "Здесь ты получаешь подключения для своих устройств. Начни с «📱 Мои устройства»."
)

WELCOME_RULES = (
    "⚙️ Перед началом — два правила\n\n"
    "1. Одни настройки — одно устройство и одно приложение. Для нового телефона, ноутбука "
    "или другого приложения добавь отдельное устройство.\n"
    "2. Не включай в приложении раздачу по локальной сети (LAN / Port / Proxy Sharing) и не открывай "
    "в сеть локальный прокси, API, панель управления или HandlerService.\n\n"
    "Если что-то не получается, загляни в «📖 Инструкцию» или напиши админу из меню.\n\n"
    "Нажми кнопку ниже, чтобы принять правила и открыть меню."
)

# ----------------------------------------------------------------- menu -----

MAIN_MENU = "🏠 Tracegate\n\nВыбери, что нужно. Чтобы получить подключение, открой «📱 Мои устройства»."

# -------------------------------------------------------------- devices -----

DEVICE_NAME_PROMPT = (
    "➕ Новое устройство\n\n"
    "Как назвать устройство? Напиши имя одним сообщением, например: Телефон, Ноутбук, Планшет.\n\n"
    "Для каждого устройства и каждого приложения — свои настройки."
)
DEVICE_NAME_EMPTY = "Имя не может быть пустым. Напиши его обычным текстом или нажми «↩️ Отмена»."
DEVICE_NAME_TOO_LONG = f"Слишком длинное имя — можно не больше {DEVICE_NAME_MAX_LENGTH} символов. Попробуй короче."


def devices_screen(devices: list[dict]) -> str:
    header = "📱 Мои устройства"
    if not devices:
        return (
            f"{header}\n\n"
            "Пока пусто. Добавь первое устройство — например, телефон или ноутбук, — "
            "а потом создай для него подключение.\n\n"
            f"Можно добавить до {MAX_DEVICES_PER_USER} устройств."
        )
    return (
        f"{header}\n\n"
        f"Устройств: {len(devices)} из {MAX_DEVICES_PER_USER}. "
        "Рядом с именем — сколько у устройства подключений.\n\n"
        "Выбери устройство, чтобы получить настройки или создать подключение."
    )


def device_button(name: object, connection_count: int) -> str:
    return f"📱 {clip(name or 'Без имени', 40)} · {int(connection_count)}"


def device_screen(device: dict, connections: list[dict]) -> str:
    name = clip(device.get("name") or "Без имени", 64)
    lines = [f"📱 {name}", "", f"Подключений: {len(connections)} из {MAX_CONNECTIONS_PER_DEVICE}."]
    if not connections:
        lines.append("Подключений пока нет. Нажми «➕ Новое подключение» — лучше начать с «Chain».")
    else:
        lines.append("Выбери подключение, чтобы получить настройки или перевыпустить их.")
    if len(connections) >= MAX_CONNECTIONS_PER_DEVICE:
        lines.append("")
        lines.append(ERR_CONNECTION_LIMIT)
    return "\n".join(lines)


def device_added(name: object) -> str:
    return f"✅ Устройство «{clip(name, 64)}» добавлено. Теперь создай для него подключение."


def device_rename_prompt(name: object) -> str:
    return (
        f"✏️ Новое имя для «{clip(name, 64)}»\n\n"
        "Напиши его одним сообщением, например: Рабочий ноутбук."
    )


def device_renamed(name: object) -> str:
    return f"✅ Готово, теперь устройство называется «{clip(name, 64)}»."


def device_delete_confirm(name: object) -> str:
    return (
        f"🗑 Удалить устройство «{clip(name, 64)}»?\n\n"
        "Все его подключения перестанут работать, а сообщения с настройками я удалю из чата. "
        "Это нельзя отменить."
    )


def device_deleted(name: object) -> str:
    return f"✅ Устройство «{clip(name, 64)}» удалено."


# ---------------------------------------------------------- connections -----

LABEL_CHAIN = "Chain"
LABEL_DIRECT_VLESS = "Direct VLESS"
LABEL_DIRECT_HYSTERIA = "Direct Hysteria"
LABEL_SALAMANDER = "Salamander"
LABEL_GECKO = "Gecko"
LABEL_LEGACY = "Устаревшее подключение"
LABEL_OTHER = "Подключение"

_LABEL_EMOJI = {
    "entry": "🔗",
    "reality": "⚡",
    "hysteria": "🚀",
    "legacy": "🗂",
    "other": "🔌",
}


def connection_button(kind: str, label: str) -> str:
    return f"{_LABEL_EMOJI.get(kind, '🔌')} {clip(label, 56)}"


def connection_title(kind: str, label: str) -> str:
    return f"{_LABEL_EMOJI.get(kind, '🔌')} {label}"


def create_connection_screen(device_name: object, enabled_specs: set[str]) -> str:
    lines = [f"➕ Новое подключение для «{clip(device_name, 64)}»", ""]
    if not enabled_specs & {"entry", "reality", "hysteria"}:
        lines.append("Сейчас новые подключения создать нельзя: все варианты выключены. Напиши админу.")
        return "\n".join(lines)
    lines.append("Выбери вариант:")
    if "entry" in enabled_specs:
        lines.append("🔗 Chain — работает почти везде, в том числе в мобильной сети. Если сомневаешься — выбирай Chain.")
    if "reality" in enabled_specs:
        lines.append("⚡ Direct VLESS — напрямую к серверу, без промежуточного узла.")
    if "hysteria" in enabled_specs:
        lines.append("🚀 Direct Hysteria — быстрое, но нужен стабильный UDP; в мобильной сети может не работать.")
    return "\n".join(lines)


HYSTERIA_OBFS_SCREEN = (
    "🚀 Direct Hysteria\n\n"
    "Выбери режим маскировки:\n"
    "Salamander — рекомендуется, его понимает большинство приложений.\n"
    "Gecko — только для официального приложения Hysteria с поддержкой Gecko."
)


def connection_created(label: str) -> str:
    return f"✅ Подключение «{label}» создано. Настройки ниже."


def connection_screen(
    *,
    title: str,
    device_name: object,
    active_since: object | None,
    formats: list[str],
) -> str:
    lines = [title, f"📱 Устройство: {clip(device_name, 64)}", ""]
    if active_since is None:
        lines.append("Действующих настроек нет. Нажми «🔄 Перевыпустить», чтобы получить новые.")
    else:
        lines.append(f"Настройки действуют с {format_date(active_since)}.")
        if formats:
            lines.append(f"Пришлю: {_join_ru(formats)}.")
        lines.append("")
        lines.append("📲 «Показать настройки» — пришлю их ещё раз.")
        lines.append("🔄 «Перевыпустить» — выдам новые, если старые перестали работать.")
    return "\n".join(lines)


def legacy_connection_screen(device_name: object) -> str:
    return (
        f"🗂 {LABEL_LEGACY}\n"
        f"📱 Устройство: {clip(device_name, 64)}\n\n"
        "Этот тип подключения больше не поддерживается: получить или перевыпустить настройки нельзя. "
        "Удали его и создай новое — лучше «🔗 Chain»."
    )


FORMAT_LINK = "ссылку"
FORMAT_QR = "QR-код"
FORMAT_FILE = "файл .json"
FORMAT_ALTERNATE = "запасную ссылку"

CONFIG_SENT = "📲 Настройки ниже."


def reissue_confirm(label: str) -> str:
    # Matches services/revisions.py: issuing a revision keeps the previous one
    # ACTIVE in the reserve slot and revokes anything older.
    return (
        f"🔄 Перевыпустить настройки «{label}»?\n\n"
        "Я выдам новые настройки для этого подключения. Старые настройки продолжат работать, "
        "пока не перевыпустишь ещё раз, — так что успеешь обновить их в приложении.\n\n"
        "Старые сообщения с настройками я удалю из чата."
    )


REISSUED = "✅ Готово, новые настройки ниже."


def connection_delete_confirm(label: str) -> str:
    return (
        f"🗑 Удалить подключение «{label}»?\n\n"
        "Оно перестанет работать, а сообщения с его настройками я удалю из чата. Это нельзя отменить."
    )


def connection_deleted(label: str) -> str:
    return f"✅ Подключение «{label}» удалено."


# ---------------------------------------------------------------- slots -----

SLOT_MAIN = "Основная"
SLOT_RESERVE = "Запасная"
SLOT_REVOKED = "Отключена"


def slots_screen(label: str, rows: list[tuple[str, object]]) -> str:
    lines = [
        f"⚙️ Дополнительно · {label}",
        "",
        # Two active revisions: services/connection_profiles.MAX_ACTIVE_REVISIONS_PER_CONNECTION.
        "Здесь версии настроек этого подключения. Действовать могут сразу две: "
        "основная и запасная. Обычно сюда заходить не нужно — хватает кнопки «🔄 Перевыпустить».",
        "",
    ]
    if not rows:
        lines.append("Версий пока нет.")
    for status_label, created_at in rows:
        lines.append(f"• {status_label} — от {format_datetime(created_at)}")
    return "\n".join(lines)


def slot_make_main_button(created_at: object) -> str:
    return f"⭐ Сделать основной · {format_short_datetime(created_at)}"


def slot_enable_button(created_at: object) -> str:
    return f"♻️ Включить снова · {format_short_datetime(created_at)}"


def slot_revoke_button(created_at: object) -> str:
    return f"🗑 Отключить · {format_short_datetime(created_at)}"


def slot_revoke_confirm(created_at: object, *, last_active: bool) -> str:
    text = (
        f"🗑 Отключить настройки от {format_datetime(created_at)}?\n\n"
        "Они перестанут работать, а сообщения с ними я удалю из чата."
    )
    if last_active:
        text += "\n\nЭто последние действующие настройки: вместе с ними пропадёт и само подключение."
    return text


SLOT_ACTIVATED = "✅ Готово, эти настройки теперь основные."
SLOT_REVOKED_DONE = "✅ Настройки отключены."
SLOT_REVOKED_CONNECTION_GONE = "✅ Настройки отключены. Действующих не осталось, поэтому подключение удалено."

# ------------------------------------------------------------- delivery -----


def config_delivery_message(
    *,
    label: str,
    context: str = "created",
    has_primary_uri: bool = True,
    has_attachment: bool = False,
    prefer_attachment: bool = False,
    has_alternate_uri: bool = False,
    has_extra_messages: bool = False,
) -> str:
    headers = {
        "created": f"✅ Готово! Вот настройки для «{label}».",
        "issued": f"✅ Готово! Вот новые настройки для «{label}».",
        "current": f"📲 Вот настройки для «{label}».",
    }
    header = headers.get(str(context or "").strip().lower(), headers["created"])

    if has_primary_uri and has_attachment and prefer_attachment:
        import_step = (
            "Импортируй файл .json из сообщения ниже. Если приложение его не принимает, "
            "используй ссылку или QR-код."
        )
    elif has_primary_uri:
        import_step = "Импортируй настройки: скопируй ссылку из следующего сообщения целиком или отсканируй QR-код."
        if has_attachment:
            import_step += " Если ссылка не подходит, импортируй файл .json."
    else:
        import_step = "Импортируй файл .json из сообщения ниже — нужно приложение, которое понимает формат sing-box."

    steps = [
        "Открой приложение на этом устройстве.",
        import_step,
        "Включи подключение — готово.",
    ]
    lines = [header, "", "Что дальше:"]
    lines.extend(f"{index}. {step}" for index, step in enumerate(steps, start=1))
    notes: list[str] = []
    if has_alternate_uri:
        notes.append("Ниже есть запасная ссылка — пригодится, если основная не импортируется.")
    if has_extra_messages:
        notes.append("Ниже — пояснения к этому подключению.")
    if notes:
        lines.append("")
        lines.extend(notes)
    lines.extend(["", "Не получается? Нажми «📖 Как подключить»."])
    return "\n".join(lines)


ALTERNATE_LINK_TITLE = "🔁 Запасная ссылка"


def qr_caption(label: str) -> str:
    return f"📷 QR-код для импорта · {label}"


def file_caption(label: str) -> str:
    return f"📎 Файл для импорта · {label}"


# Exporter extras are English; translate the ones that reach users.
_EXTRA_TITLES = {
    "client compatibility": "ℹ️ Совместимость",
}
_EXTRA_CONTENT = {
    "Gecko requires the official Hysteria client with Gecko support; sing-box does not support Gecko.": (
        "Gecko работает только в официальном приложении Hysteria с поддержкой Gecko. "
        "Приложения на основе sing-box его не поддерживают."
    ),
    "Salamander is the broadly compatible Hysteria2 obfs mode.": (
        "Salamander поддерживается большинством приложений с Hysteria2."
    ),
}


def extra_message(title: str, content: str) -> str:
    normalized_title = str(title or "").strip()
    translated_title = _EXTRA_TITLES.get(normalized_title.lower(), normalized_title)
    normalized_content = str(content or "").strip()
    translated_content = _EXTRA_CONTENT.get(normalized_content, normalized_content)
    if not translated_title:
        return translated_content
    return f"{translated_title}\n\n{translated_content}"


# ------------------------------------------------------- telegram proxy -----

# Kept verbatim: tests/test_mtproto_entry_only_route.py pins this exact line.
MTPROTO_UPDATE_TELEGRAM_HINT = "Обнови Telegram до последней версии: прокси рассчитан на актуальные версии приложения."


def tgp_screen(*, has_access: bool | None) -> str:
    lines = [
        "✈️ Telegram Proxy",
        "",
        "Отдельный прокси только для Telegram. Он не заменяет подключение для устройства.",
        "",
    ]
    if has_access is True:
        lines.append("Статус: доступ выдан.")
    elif has_access is False:
        lines.append("Статус: доступа пока нет.")
    lines.append("Нажми «📲 Показать ссылку», открой её на устройстве с Telegram и подтверди подключение.")
    return "\n".join(lines)


TGP_SENT_NEW = "✅ Доступ выдан. Ссылка ниже — открой её на устройстве с Telegram."
TGP_SENT_AGAIN = "📲 Твоя ссылка ниже — открой её на устройстве с Telegram."
TGP_ROTATED = "✅ Ссылка сменена. Новая ниже, старая скоро перестанет работать."
TGP_REVOKE_CONFIRM = (
    "⛔ Отозвать доступ к Telegram Proxy?\n\n"
    "Твоя ссылка перестанет работать. Новую можно получить в любой момент."
)
TGP_REVOKED = "✅ Доступ к Telegram Proxy отозван."
TGP_NOT_FOUND = "У тебя сейчас нет доступа к Telegram Proxy."


def format_mtproto_link_message(profile: dict) -> str:
    https_url = str(profile.get("httpsUrl") or "").strip()
    tg_uri = str(profile.get("tgUri") or "").strip()
    delivered: list[tuple[str, str, int, str, str]] = []
    if isinstance(profile.get("links"), list):
        for row in profile["links"]:
            if not isinstance(row, dict):
                continue
            row_https_url = str(row.get("httpsUrl") or "").strip()
            if not row_https_url:
                continue
            try:
                row_port = int(row.get("port") or 0)
            except (TypeError, ValueError):
                row_port = 0
            delivered.append(
                (
                    str(row.get("label") or "").strip(),
                    str(row.get("server") or "").strip(),
                    row_port,
                    row_https_url,
                    str(row.get("tgUri") or "").strip(),
                )
            )
    if not delivered:
        try:
            port = int(profile.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        delivered.append(("", str(profile.get("server") or "").strip(), port, https_url, tg_uri))

    lines = ["🔗 Ссылки для Telegram"]
    for route_label, server, port, row_https_url, row_tg_uri in delivered:
        label = route_label or (f"Порт {port}" if port > 0 else "Основная")
        lines.extend(["", f"{label}:", row_https_url])
        if server:
            lines.append(f"Сервер: {server}")
        if row_tg_uri:
            lines.extend(["tg://:", row_tg_uri])
    lines.extend(["", MTPROTO_UPDATE_TELEGRAM_HINT])
    return "\n".join(lines)


def mtproto_route_label(index: int) -> str:
    return f"Маршрут {index}"


MTPROTO_MAIN_ROUTE = "Основной маршрут"


def mtproto_qr_caption(label: str) -> str:
    return f"📷 {label}"


# ---------------------------------------------------------------- guide -----

GUIDE_DEFAULT_TITLE = "📖 Инструкция"
GUIDE_UNAVAILABLE = "📖 Инструкция временно недоступна.\n\nПопробуй позже или напиши админу из меню."
GUIDE_EMPTY = "📖 Инструкция пока пустая."

# ------------------------------------------------------------- feedback -----

FEEDBACK_PROMPT = (
    "💬 Написать админу\n\n"
    "Напиши одним сообщением, что случилось или что хочешь спросить. "
    "Сообщение получат администраторы вместе с твоим именем и Telegram ID."
)
FEEDBACK_NOT_TEXT = "Пока я умею передавать только текст. Напиши сообщение словами или нажми «↩️ Назад»."
FEEDBACK_SENT = "✅ Отправил администраторам."

# -------------------------------------------------------------- grafana -----

GRAFANA_DISABLED = (
    "📊 Grafana пока не включена.\n\n"
    "Когда панель заработает, эта кнопка будет выдавать ссылку для входа."
)


def grafana_screen(*, scope: str, expires_at: object) -> str:
    scope_label = "администраторский" if str(scope or "").strip().lower() == "admin" else "личный"
    return (
        "📊 Grafana\n\n"
        f"Доступ: {scope_label}.\n"
        f"Ссылка одноразовая и действует до {format_datetime(expires_at)}.\n"
        "Нажми кнопку ниже, чтобы войти."
    )


# ---------------------------------------------------------------- admin -----

NO_RIGHTS = "⛔ Недостаточно прав."
SUPERADMIN_ONLY = "⛔ Это доступно только суперадмину."
ADMIN_MENU = "🛠 Управление\n\nЧто нужно сделать?"
ADMIN_SESSION_EXPIRED = "Сессия истекла. Начни заново из «🛠 Управление»."
ADMIN_BAD_ID = (
    "Нужен числовой Telegram ID — только цифры, например 123456789. "
    "Пришли ещё раз или нажми «↩️ Отмена»."
)
ADMIN_USER_NOT_FOUND = "Пользователь с таким ID не найден."
ADMIN_CANT_MANAGE = "⛔ Недостаточно прав для действий с этим пользователем."
ADMIN_CANT_REVOKE_SUPERADMIN = "Нельзя снять роль суперадмина."
ADMIN_NOTIFY_FAILED = "Готово, но уведомление пользователю отправить не удалось."
ADMIN_TGP_NOT_FOUND = "У этого пользователя нет активного доступа к Telegram Proxy."
ADMIN_LIST_EMPTY = "Список администраторов пуст."

BLOCK_HOURS_HINT = (
    f"Срок — от 1 до {MAX_TIMED_BOT_BLOCK_HOURS} часов или {PERMANENT_BOT_BLOCK_HOURS}, чтобы заблокировать навсегда."
)

ADMIN_PROMPT_GRANT = "➕ Назначить админа\n\nПришли Telegram ID пользователя (только цифры)."
ADMIN_PROMPT_UNGRANT = "➖ Снять админа\n\nПришли Telegram ID администратора (только цифры)."
ADMIN_PROMPT_REVOKE_ACCESS = (
    "⛔ Отозвать доступ\n\n"
    "Пришли Telegram ID пользователя. Я отзову все его устройства, подключения и Telegram Proxy. "
    "Это не блокировка: доступ можно будет получить заново."
)
ADMIN_PROMPT_TGP_REVOKE = (
    "⛔ Отозвать Telegram Proxy\n\n"
    "Пришли Telegram ID пользователя. Отзову только его доступ к Telegram Proxy."
)
ADMIN_PROMPT_BLOCK = (
    "🚫 Заблокировать\n\n"
    "Пришли одной строкой: ID, срок в часах и, если хочешь, причину.\n"
    f"{BLOCK_HOURS_HINT}\n"
    "Пример: 123456789 72 спам"
)
ADMIN_PROMPT_UNBLOCK = "✅ Разблокировать\n\nПришли Telegram ID пользователя (только цифры)."
ADMIN_PROMPT_ANNOUNCE = "📣 Рассылка\n\nПришли текст, который получат все пользователи бота."
ADMIN_ANNOUNCE_EMPTY = "Текст рассылки не может быть пустым. Пришли его ещё раз или нажми «↩️ Отмена»."
ADMIN_RESET_CONFIRM = (
    "🧹 Отозвать всё у всех?\n\n"
    "У всех пользователей будут отозваны подключения и доступы к Telegram Proxy. "
    "Пользователи и устройства останутся.\n\n"
    "Это нельзя отменить."
)

BLOCK_ERR_FORMAT = "Формат: ID, срок в часах и причина (необязательно). Пример: 123456789 72 спам"
BLOCK_ERR_FORMAT_TARGETED = "Формат: срок в часах и причина (необязательно). Пример: 72 спам"
BLOCK_ERR_EMPTY = "Пустая строка. Пришли данные для блокировки."
BLOCK_ERR_BAD_ID = "ID должен быть числом, например 123456789."
BLOCK_ERR_BAD_HOURS = f"Срок должен быть целым числом. {BLOCK_HOURS_HINT}"
BLOCK_ERR_HOURS_RANGE = f"Неверный срок. {BLOCK_HOURS_HINT}"
BLOCK_ERR_REASON_TOO_LONG = f"Причина слишком длинная — можно не больше {BLOCK_REASON_MAX_LENGTH} символов."


def admin_block_targeted_prompt(target_label: str) -> str:
    return (
        f"🚫 Заблокировать автора: {target_label}\n\n"
        "Пришли срок в часах и, если хочешь, причину.\n"
        f"{BLOCK_HOURS_HINT}\n"
        "Пример: 72 спам"
    )


def admin_revoke_notify_question(target_label: str) -> str:
    return (
        f"⛔ Отозвать все устройства, подключения и Telegram Proxy у {target_label}?\n\n"
        "Отправить пользователю уведомление?"
    )


def admin_access_revoked(target_label: str, *, connections: int, devices: int, tgp: bool) -> str:
    return (
        f"✅ Доступ отозван у {target_label}.\n"
        f"Подключений: {connections}\n"
        f"Устройств: {devices}\n"
        f"Telegram Proxy: {'да' if tgp else 'нет'}"
    )


def admin_tgp_revoked(target_label: str) -> str:
    return f"✅ Доступ к Telegram Proxy отозван у {target_label}."


def block_duration_label(hours: int) -> str:
    if is_permanent_bot_block_hours(hours):
        return "навсегда"
    return f"{int(hours)} ч."


def block_until_label(until: datetime | None) -> str:
    if until is None:
        return "не определено"
    if until.year >= 9999:
        return "навсегда"
    return format_datetime(until)


def admin_blocked(target_label: str, until: datetime | None) -> str:
    return f"✅ Блокировка применена.\n{target_label}\nДо: {block_until_label(until)}"


def admin_unblocked(target_label: str) -> str:
    return f"✅ Блокировка снята.\n{target_label}"


def admin_role_granted(telegram_id: int) -> str:
    return f"✅ Готово: {int(telegram_id)} теперь администратор."


def admin_role_revoked(telegram_id: int) -> str:
    return f"✅ Готово: {int(telegram_id)} теперь обычный пользователь."


def admin_list(superadmins: list[str], admins: list[str]) -> str:
    lines = ["👑 Суперадмины"]
    lines.extend(f"• {label}" for label in superadmins)
    if not superadmins:
        lines.append("—")
    lines.extend(["", "🛡 Администраторы"])
    lines.extend(f"• {label}" for label in admins)
    if not admins:
        lines.append("—")
    return "\n".join(lines)


def admin_reset_done(*, connections: int, tgp: int) -> str:
    return f"✅ Всё отозвано.\nПодключений: {connections}\nTelegram Proxy: {tgp}"


def admin_announce_done(*, sent: int, failed: int) -> str:
    return f"✅ Рассылка завершена.\nДоставлено: {sent}\nНе доставлено: {failed}"


# -------------------------------------------------------- notifications -----


def block_notification(*, blocked_at: datetime, hours: int, until: datetime | None, reason: str | None) -> str:
    reason_text = (reason or "").strip() or "не указана"
    return (
        "⚠️ Администратор ограничил тебе доступ к боту.\n"
        f"Когда: {format_datetime(blocked_at)}\n"
        f"Срок: {block_duration_label(hours)}\n"
        f"До: {block_until_label(until)}\n"
        f"Причина: {reason_text}"
    )


def unblock_notification(*, unblocked_at: datetime) -> str:
    return (
        "✅ Администратор снял ограничение — доступ к боту снова открыт.\n"
        f"Когда: {format_datetime(unblocked_at)}"
    )


def access_revoked_notification(*, revoked_at: datetime) -> str:
    return (
        "⚠️ Администратор отозвал твои устройства, подключения и доступ к Telegram Proxy.\n"
        f"Когда: {format_datetime(revoked_at)}\n"
        "Это не блокировка: если доступ нужен, напиши админу через меню."
    )


# Block notices shown by the access middleware (see access.blocked_message).
BLOCKED_GENERIC = "Доступ временно ограничен."
BLOCKED_PERMANENT = "Доступ к боту перманентно ограничен."


def blocked_until(until_iso: str) -> str:
    return f"Доступ к боту временно ограничен до {until_iso}."


def blocked_reason(reason: str) -> str:
    return f"Причина: {reason}"
