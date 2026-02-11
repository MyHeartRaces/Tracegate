from __future__ import annotations

from datetime import datetime, timezone


def parse_api_datetime(raw: object) -> datetime | None:
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def bot_block_until(user: dict) -> datetime | None:
    return parse_api_datetime(user.get("bot_blocked_until"))


def is_bot_blocked(user: dict) -> bool:
    until = bot_block_until(user)
    return until is not None and until > datetime.now(timezone.utc)


def blocked_message(user: dict) -> str:
    until = bot_block_until(user)
    if until is None:
        return "Доступ временно ограничен."
    text = f"Доступ к боту временно ограничен до {until.isoformat()}."
    reason = (user.get("bot_block_reason") or "").strip()
    if reason:
        text += f"\nПричина: {reason}"
    return text


def is_admin(user: dict) -> bool:
    return (user.get("role") or "").strip().lower() in {"admin", "superadmin"}


def is_superadmin(user: dict) -> bool:
    return (user.get("role") or "").strip().lower() == "superadmin"


def user_label(user: dict) -> str:
    username = (user.get("telegram_username") or "").strip()
    telegram_id = int(user.get("telegram_id") or 0)
    if username:
        return f"@{username} ({telegram_id})"
    first = (user.get("telegram_first_name") or "").strip()
    last = (user.get("telegram_last_name") or "").strip()
    full = " ".join([part for part in [first, last] if part]).strip()
    if full:
        return f"{full} ({telegram_id})"
    return str(telegram_id)


def can_manage_block(actor: dict, target: dict) -> bool:
    actor_role = (actor.get("role") or "").strip().lower()
    target_role = (target.get("role") or "").strip().lower()
    if target_role == "superadmin":
        return False
    if actor_role == "superadmin":
        return True
    if actor_role == "admin":
        return target_role == "user"
    return False
