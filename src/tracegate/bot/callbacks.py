"""Callback data scheme for the Telegram bot.

Every callback payload must stay within Telegram's 64-byte limit. Ids are
UUIDs (36 chars), so prefixes are kept short. Legacy payloads from earlier
releases are resolved in ``handlers/fallback.py``.
"""

from __future__ import annotations

from uuid import UUID

CALLBACK_DATA_LIMIT = 64

# Exact payloads.
MENU = "menu"
DEVICES = "devs"
DEVICE_ADD = "devadd"
GUIDE = "g"
FEEDBACK = "fb"
GRAFANA = "grafana"
TGP = "tgp"
TGP_SHOW = "tgp:show"
TGP_ROTATE = "tgp:rot"
TGP_REVOKE_ASK = "tgp:revq"
TGP_REVOKE = "tgp:rev"
WELCOME_1 = "welcome_continue_1"
WELCOME_2 = "welcome_continue_2"

ADMIN = "admin_menu"
ADMIN_USERS = "adm:users"
ADMIN_TGP = "adm:tgp"
ADMIN_TGP_REVOKE = "adm:tgprev"
ADMIN_REVOKE_ACCESS = "adm:revoke"
ADMIN_NOTIFY_YES = "adm:notify:yes"
ADMIN_NOTIFY_NO = "adm:notify:no"
ADMIN_BLOCK = "adm:block"
ADMIN_UNBLOCK = "adm:unblock"
ADMIN_RESET_ASK = "adm:reset"
ADMIN_RESET = "adm:resetok"
ADMIN_GRANT = "adm:grant"
ADMIN_UNGRANT = "adm:ungrant"
ADMIN_LIST = "adm:list"

# Prefixes followed by an id.
GUIDE_PAGE_P = "g:"
FEEDBACK_BLOCK_P = "feedback_block:"
DEVICE_P = "dev:"
DEVICE_RENAME_P = "devren:"
DEVICE_DELETE_ASK_P = "devdelq:"
DEVICE_DELETE_P = "devdel:"
CONN_NEW_P = "cnew:"
CONN_HYSTERIA_P = "chy:"
CONN_MAKE_P = "cmk:"
CONN_P = "conn:"
CONN_SHOW_P = "cshow:"
CONN_REISSUE_ASK_P = "creq:"
CONN_REISSUE_P = "cre:"
CONN_ADVANCED_P = "cadv:"
CONN_DELETE_ASK_P = "cdelq:"
CONN_DELETE_P = "cdel:"
SLOT_ACTIVATE_P = "sact:"
SLOT_REVOKE_ASK_P = "srevq:"
SLOT_REVOKE_P = "srev:"

# Choices for CONN_MAKE_P: cmk:<choice>:<device_id>
MAKE_ENTRY = "entry"
MAKE_REALITY = "reality"
MAKE_HYSTERIA_SALAMANDER = "hy-salamander"
MAKE_HYSTERIA_GECKO = "hy-gecko"
MAKE_CHOICES = frozenset({MAKE_ENTRY, MAKE_REALITY, MAKE_HYSTERIA_SALAMANDER, MAKE_HYSTERIA_GECKO})


def fits(data: str) -> bool:
    return len(str(data).encode("utf-8")) <= CALLBACK_DATA_LIMIT


def with_id(prefix: str, value: object) -> str:
    return f"{prefix}{value}"


def device(device_id: object) -> str:
    return with_id(DEVICE_P, device_id)


def connection(connection_id: object) -> str:
    return with_id(CONN_P, connection_id)


def make(choice: str, device_id: object) -> str:
    return f"{CONN_MAKE_P}{choice}:{device_id}"


def guide_page(path: str) -> str:
    return f"{GUIDE_PAGE_P}{path}"


def normalize_uuid(value: object) -> str | None:
    raw = str(value or "").strip()
    try:
        return str(UUID(raw))
    except (ValueError, AttributeError, TypeError):
        return None


def parse_id(data: str | None, prefix: str) -> str | None:
    """Return the UUID that follows ``prefix`` or None when it is malformed."""

    raw = str(data or "")
    if not raw.startswith(prefix):
        return None
    return normalize_uuid(raw[len(prefix) :])


def parse_make(data: str | None) -> tuple[str, str] | None:
    raw = str(data or "")
    if not raw.startswith(CONN_MAKE_P):
        return None
    choice, sep, device_id = raw[len(CONN_MAKE_P) :].partition(":")
    normalized = normalize_uuid(device_id)
    if not sep or choice not in MAKE_CHOICES or normalized is None:
        return None
    return choice, normalized


def parse_telegram_id(data: str | None, prefix: str) -> int | None:
    raw = str(data or "")
    if not raw.startswith(prefix):
        return None
    value = raw[len(prefix) :].strip()
    if not value.isdigit():
        return None
    parsed = int(value)
    return parsed if parsed > 0 else None
