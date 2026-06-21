from __future__ import annotations


def user_display(
    *,
    telegram_id: int,
    telegram_username: str | None,
    telegram_first_name: str | None = None,
    telegram_last_name: str | None = None,
) -> str:
    username = (telegram_username or "").strip().lstrip("@")
    if username:
        return f"@{username} ({telegram_id})"

    full_name = " ".join([part.strip() for part in [telegram_first_name or "", telegram_last_name or ""] if part and part.strip()]).strip()
    if full_name:
        return f"{full_name} ({telegram_id})"
    return str(telegram_id)


def connection_alias(
    *,
    telegram_id: int,
    telegram_username: str | None,
    device_name: str,
    connection_id: str,
    telegram_first_name: str | None = None,
    telegram_last_name: str | None = None,
) -> str:
    owner = user_display(
        telegram_id=telegram_id,
        telegram_username=telegram_username,
        telegram_first_name=telegram_first_name,
        telegram_last_name=telegram_last_name,
    )
    return f"{owner} - {device_name} - {connection_id}"
