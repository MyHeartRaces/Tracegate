from __future__ import annotations

from datetime import datetime

from tracegate.bot.access import bot_block_until, user_label

_TELEGRAM_MESSAGE_LIMIT = 4096


def format_role_label(role: str | None) -> str:
    normalized = str(role or "").strip().lower()
    return {
        "user": "Пользователь",
        "admin": "Администратор",
        "superadmin": "Суперадмин",
    }.get(normalized, normalized or "Неизвестно")


def clip_text(value: str, *, max_len: int) -> str:
    text = str(value or "").strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3].rstrip() + "..."


def format_block_until_label(until: datetime | None) -> str:
    if until is None:
        return "не определено"
    if until.year >= 9999:
        return "перманентно"
    return until.isoformat()


def parse_user_block_request(text: str, *, default_target_id: int | None = None) -> tuple[int, int, str | None]:
    raw = str(text or "").strip()
    if not raw:
        raise ValueError("Пустая команда блокировки.")

    if default_target_id is None:
        parts = raw.split(maxsplit=2)
        if len(parts) < 2:
            raise ValueError("Формат: <telegram_id> <hours> [reason]")
        target_id = int(parts[0])
        hours = int(parts[1])
        reason = parts[2].strip() if len(parts) >= 3 else None
        return target_id, hours, reason or None

    parts = raw.split(maxsplit=1)
    hours = int(parts[0])
    reason = parts[1].strip() if len(parts) >= 2 else None
    return int(default_target_id), hours, reason or None


def build_feedback_admin_text(*, author: dict, feedback_text: str, sent_at: datetime) -> str:
    header = (
        "📨 Обратная связь\n"
        f"Автор: {user_label(author)}\n"
        f"ID: {int(author.get('telegram_id') or 0)}\n"
        f"Роль: {format_role_label(author.get('role'))}\n"
        f"Когда: {sent_at.isoformat()}\n\n"
        "Сообщение:\n"
    )
    available = max(64, _TELEGRAM_MESSAGE_LIMIT - len(header))
    body = clip_text(feedback_text, max_len=available)
    return header + body


def build_admin_users_report(
    *,
    all_users: list[dict],
    active_users: list[dict],
    blocked_users: list[dict],
    active_mtproto_grants: list[dict] | None = None,
    max_rows: int = 80,
) -> str:
    all_sorted = sorted(all_users, key=lambda row: (str(row.get("role") or ""), int(row.get("telegram_id") or 0)))
    active_sorted = sorted(active_users, key=lambda row: (str(row.get("role") or ""), int(row.get("telegram_id") or 0)))
    blocked_sorted = sorted(blocked_users, key=lambda row: int(row.get("telegram_id") or 0))
    mtproto_sorted = sorted(
        active_mtproto_grants or [],
        key=lambda row: (str(row.get("role") or ""), int(row.get("telegram_id") or 0)),
    )

    def _user_line(index: int, row: dict) -> str:
        return f"{index}. {user_label(row)} | {format_role_label(row.get('role'))}"

    def _mtproto_line(index: int, row: dict) -> str:
        telegram_id = int(row.get("telegram_id") or 0)
        display = str(row.get("display") or "").strip() or str(row.get("label") or "").strip() or str(telegram_id)
        parts = [f"{index}. {display}"]
        role = str(row.get("role") or "").strip()
        label = str(row.get("label") or "").strip()
        updated_at = str(row.get("updated_at") or row.get("last_sync_at") or "").strip()
        if role:
            parts.append(format_role_label(role))
        if label and label not in {display, str(telegram_id)}:
            parts.append(f"Метка: {label}")
        if updated_at:
            parts.append(f"Sync: {updated_at}")
        return " | ".join(parts)

    lines = [f"👥 Пользователи Tracegate: {len(all_sorted)}"]
    if not all_sorted:
        lines.append("Пользователи не найдены.")
    for index, row in enumerate(all_sorted[:max_rows], start=1):
        lines.append(_user_line(index, row))
    if len(all_sorted) > max_rows:
        lines.append(f"Показано {max_rows} из {len(all_sorted)}.")

    lines.extend(["", f"🔌 Активные подключения: {len(active_sorted)}"])
    if not active_sorted:
        lines.append("Нет пользователей с активными подключениями.")
    for index, row in enumerate(active_sorted[:max_rows], start=1):
        lines.append(_user_line(index, row))
    if len(active_sorted) > max_rows:
        lines.append(f"Показано {max_rows} из {len(active_sorted)}.")

    lines.extend(["", f"🔐 Активные Telegram Proxy: {len(mtproto_sorted)}"])
    if not mtproto_sorted:
        lines.append("Нет активных постоянных Telegram Proxy-доступов.")
    for index, row in enumerate(mtproto_sorted[:max_rows], start=1):
        lines.append(_mtproto_line(index, row))
    if len(mtproto_sorted) > max_rows:
        lines.append(f"Показано {max_rows} из {len(mtproto_sorted)}.")

    lines.extend(["", f"⛔ Активные блокировки: {len(blocked_sorted)}"])
    if not blocked_sorted:
        lines.append("Нет активных блокировок.")
    for index, row in enumerate(blocked_sorted[:max_rows], start=1):
        lines.append(
            f"{index}. {user_label(row)} | {format_role_label(row.get('role'))} | "
            f"Блок: {format_block_until_label(bot_block_until(row))}"
        )
    if len(blocked_sorted) > max_rows:
        lines.append(f"Показано {max_rows} из {len(blocked_sorted)}.")

    return "\n".join(lines)


def build_admin_mtproto_report(*, grants: list[dict], max_rows: int = 80) -> str:
    grants_sorted = sorted(grants, key=lambda row: (str(row.get("role") or ""), int(row.get("telegram_id") or 0)))

    def _mtproto_line(index: int, row: dict) -> str:
        telegram_id = int(row.get("telegram_id") or 0)
        display = str(row.get("display") or "").strip() or str(row.get("label") or "").strip() or str(telegram_id)
        parts = [f"{index}. {display}"]
        role = str(row.get("role") or "").strip()
        label = str(row.get("label") or "").strip()
        issued_by = str(row.get("issued_by") or "").strip()
        updated_at = str(row.get("updated_at") or row.get("last_sync_at") or "").strip()
        if role:
            parts.append(format_role_label(role))
        if label and label not in {display, str(telegram_id)}:
            parts.append(f"Метка: {label}")
        if issued_by:
            parts.append(f"Источник: {issued_by}")
        if updated_at:
            parts.append(f"Sync: {updated_at}")
        return " | ".join(parts)

    lines = [f"🔐 Постоянные Telegram Proxy-доступы: {len(grants_sorted)}"]
    if not grants_sorted:
        lines.append("Активных постоянных Telegram Proxy-доступов нет.")
        return "\n".join(lines)

    for index, row in enumerate(grants_sorted[:max_rows], start=1):
        lines.append(_mtproto_line(index, row))
    if len(grants_sorted) > max_rows:
        lines.append(f"Показано {max_rows} из {len(grants_sorted)}.")
    return "\n".join(lines)
