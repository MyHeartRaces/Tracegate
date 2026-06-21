from __future__ import annotations

from typing import Any

from tracegate.services.hysteria_credentials import build_hysteria_token_value


def _artifact_connection_email(row: dict[str, Any]) -> str:
    variant = str(row.get("variant") or "").strip() or "V?"
    user_id = str(row.get("user_id") or "").strip() or "?"
    connection_id = str(row.get("connection_id") or "").strip() or "?"
    return f"{variant} - {user_id} - {connection_id}"


def _token_from_auth_payload(auth_cfg: dict[str, Any]) -> str:
    auth_type = str(auth_cfg.get("type") or "").strip().lower()
    if auth_type == "token":
        token = str(auth_cfg.get("token") or auth_cfg.get("value") or "").strip()
        if token:
            return token
        username = str(auth_cfg.get("client_id") or auth_cfg.get("username") or "").strip()
        password = str(auth_cfg.get("password") or "").strip()
        if username and password:
            return build_hysteria_token_value(username=username, password=password)
        return ""

    if auth_type == "userpass":
        username = str(auth_cfg.get("username") or auth_cfg.get("client_id") or "").strip()
        password = str(auth_cfg.get("password") or "").strip()
        token = str(auth_cfg.get("token") or "").strip()
        if token:
            return token
        if username and password:
            return build_hysteria_token_value(username=username, password=password)
    return ""


def build_hysteria_xray_clients(artifacts: list[dict[str, Any]]) -> list[dict[str, str]]:
    clients_by_email: dict[str, dict[str, str]] = {}
    for row in artifacts:
        if row.get("protocol") != "hysteria2":
            continue
        cfg = row.get("config") or {}
        auth_cfg = cfg.get("auth") or {}
        if not isinstance(auth_cfg, dict):
            continue
        token = _token_from_auth_payload(auth_cfg)
        if not token:
            continue
        email = _artifact_connection_email(row)
        clients_by_email[email] = {"auth": token, "email": email}
    return [clients_by_email[email] for email in sorted(clients_by_email, key=lambda value: str(value).lower())]
