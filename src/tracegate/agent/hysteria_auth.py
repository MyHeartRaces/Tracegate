from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tracegate.services.hysteria_markers import (
    hysteria_auth_username_aliases_for_artifact_row,
    normalize_hysteria_connection_marker,
)
from tracegate.settings import Settings

HYSTERIA_AUTH_DB_FILE_NAME = "auth.json"


def hysteria_auth_db_path(settings: Settings) -> Path:
    return Path(settings.agent_data_root) / "runtime" / "hysteria" / HYSTERIA_AUTH_DB_FILE_NAME


def build_hysteria_auth_db(*, static_userpass: dict[str, Any] | None, artifacts: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    entries: dict[str, dict[str, str]] = {}

    for raw_username, raw_password in (static_userpass or {}).items():
        username = str(raw_username or "").strip()
        password = str(raw_password or "").strip()
        if not username or not password:
            continue
        entries[username] = {
            "password": password,
            "id": normalize_hysteria_connection_marker(username) or username,
        }

    for row in artifacts:
        if row.get("protocol") != "hysteria2":
            continue
        cfg = row.get("config") or {}
        auth_cfg = cfg.get("auth") or {}
        if auth_cfg.get("type") != "userpass":
            continue
        username = str(auth_cfg.get("username") or "").strip()
        password = str(auth_cfg.get("password") or "").strip()
        if not username or not password:
            continue
        client_id = normalize_hysteria_connection_marker(username) or username
        aliases = hysteria_auth_username_aliases_for_artifact_row(row, username)
        if not aliases:
            aliases = {username}
        for alias in aliases:
            alias_s = str(alias or "").strip()
            if not alias_s:
                continue
            entries[alias_s] = {
                "password": password,
                "id": client_id,
            }

    return {key: entries[key] for key in sorted(entries, key=str)}


def load_hysteria_auth_db(settings: Settings) -> dict[str, dict[str, str]]:
    path = hysteria_auth_db_path(settings)
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(raw, dict):
        return {}

    out: dict[str, dict[str, str]] = {}
    for raw_username, raw_row in raw.items():
        username = str(raw_username or "").strip()
        if not username or not isinstance(raw_row, dict):
            continue
        password = str(raw_row.get("password") or "").strip()
        client_id = str(raw_row.get("id") or "").strip() or normalize_hysteria_connection_marker(username) or username
        if not password:
            continue
        out[username] = {
            "password": password,
            "id": client_id,
        }
    return out


def authenticate_hysteria_userpass(settings: Settings, raw_auth: str) -> tuple[bool, str | None]:
    auth = str(raw_auth or "")
    if ":" not in auth:
        return False, None
    username, password = auth.split(":", 1)
    username = username.strip()
    password = password.strip()
    if not username or not password:
        return False, None

    row = load_hysteria_auth_db(settings).get(username)
    if not row:
        return False, None
    if row.get("password") != password:
        return False, None
    client_id = str(row.get("id") or "").strip() or normalize_hysteria_connection_marker(username) or username
    return True, client_id
