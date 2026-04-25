from __future__ import annotations

from tracegate.services.hysteria_markers import hysteria_ios_safe_username


class HysteriaAuthModeError(ValueError):
    pass


def normalize_hysteria_auth_mode(value: str | None) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return "userpass"
    if raw in {"userpass", "token"}:
        return raw
    raise HysteriaAuthModeError(f"unsupported hysteria auth mode: {raw}")


def build_hysteria_token_value(*, username: str, password: str) -> str:
    user_s = str(username or "").strip()
    pass_s = str(password or "").strip()
    if not user_s or not pass_s:
        raise HysteriaAuthModeError("username and password are required to derive a hysteria token")
    return f"{user_s}:{pass_s}"


def build_hysteria_opaque_token_value(*, username: str, password: str) -> str:
    user_s = str(username or "").strip()
    pass_s = str(password or "").strip()
    if not user_s or not pass_s:
        raise HysteriaAuthModeError("username and password are required to derive a hysteria token")

    # Keep token-mode auth fully opaque and URI-safe for broad client interop.
    token_suffix = "".join(ch.lower() for ch in pass_s if ch.isalnum())
    if not token_suffix:
        raise HysteriaAuthModeError("password must contain at least one alphanumeric character")
    return f"{user_s}-{token_suffix}"


def build_hysteria_auth_payload(
    *,
    auth_mode: str,
    variant: str,
    tg_id: int,
    connection_id: str,
    device_id: str,
) -> dict[str, str]:
    mode = normalize_hysteria_auth_mode(auth_mode)
    username = hysteria_ios_safe_username(
        variant=variant,
        tg_id=tg_id,
        connection_id=connection_id,
    )
    password = str(device_id or "").strip()
    token = build_hysteria_token_value(username=username, password=password)

    if mode == "userpass":
        return {
            "type": "userpass",
            "username": username,
            "password": password,
            "token": token,
            "client_id": username,
        }

    if mode == "token":
        return {
            "type": "token",
            "token": build_hysteria_opaque_token_value(username=username, password=password),
            "client_id": username,
        }

    raise HysteriaAuthModeError(f"unsupported hysteria auth mode: {mode}")
