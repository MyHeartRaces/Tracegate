from __future__ import annotations

import re
from uuid import UUID

_LEGACY_RE = re.compile(r"^[Bb]([0-9]+)\s*-\s*([0-9]+)\s*-\s*(.+)$")
_IOS_SAFE_RE = re.compile(r"^[Bb]([0-9]+)_([0-9]+)_([0-9a-fA-F]{32})$")


def _normalize_variant(variant: str) -> str:
    raw = str(variant or "").strip()
    if not raw:
        return "B?"
    if raw[0] in {"b", "B"} and raw[1:].isdigit():
        return f"B{raw[1:]}"
    return raw.upper()


def _canonicalize_connection_id(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return raw
    try:
        return str(UUID(raw))
    except Exception:
        pass
    compact = raw.replace("-", "")
    if len(compact) == 32:
        try:
            return str(UUID(compact))
        except Exception:
            return compact.lower()
    return raw


def hysteria_legacy_username(*, variant: str, tg_id: str | int, connection_id: str) -> str:
    return f"{_normalize_variant(str(variant))} - {str(tg_id).strip()} - {_canonicalize_connection_id(connection_id)}"


def hysteria_ios_safe_username(*, variant: str, tg_id: str | int, connection_id: str) -> str:
    variant_norm = _normalize_variant(str(variant))
    variant_token = variant_norm.lower() if variant_norm and variant_norm != "B?" else "b"
    conn = _canonicalize_connection_id(connection_id).replace("-", "").lower()
    return f"{variant_token}_{str(tg_id).strip()}_{conn}"


def parse_hysteria_username(username: str) -> tuple[str, str, str] | None:
    raw = str(username or "").strip()
    if not raw:
        return None

    m_ios = _IOS_SAFE_RE.match(raw)
    if m_ios is not None:
        variant = f"B{m_ios.group(1)}"
        tg_id = str(m_ios.group(2))
        conn_id = _canonicalize_connection_id(m_ios.group(3))
        if tg_id and conn_id:
            return variant, tg_id, conn_id

    m_legacy = _LEGACY_RE.match(raw)
    if m_legacy is not None:
        variant = f"B{m_legacy.group(1)}"
        tg_id = str(m_legacy.group(2)).strip()
        conn_id = _canonicalize_connection_id(m_legacy.group(3))
        if tg_id and conn_id:
            return variant, tg_id, conn_id

    return None


def normalize_hysteria_connection_marker(marker: str) -> str:
    parsed = parse_hysteria_username(marker)
    if parsed is None:
        return str(marker or "").strip()
    variant, tg_id, conn_id = parsed
    return hysteria_legacy_username(variant=variant, tg_id=tg_id, connection_id=conn_id)


def hysteria_auth_username_aliases(*, variant: str, tg_id: str | int, connection_id: str) -> set[str]:
    return {
        hysteria_legacy_username(variant=variant, tg_id=tg_id, connection_id=connection_id),
        hysteria_ios_safe_username(variant=variant, tg_id=tg_id, connection_id=connection_id),
    }


def hysteria_auth_username_aliases_for_artifact_row(row: dict, configured_username: str) -> set[str]:
    variant = str(row.get("variant") or "").strip()
    tg_id = str(row.get("user_id") or "").strip()
    connection_id = str(row.get("connection_id") or "").strip()
    if variant and tg_id and connection_id:
        return hysteria_auth_username_aliases(variant=variant, tg_id=tg_id, connection_id=connection_id)

    parsed = parse_hysteria_username(configured_username)
    if parsed is None:
        return {str(configured_username or "").strip()} if str(configured_username or "").strip() else set()
    p_variant, p_tg_id, p_conn_id = parsed
    return hysteria_auth_username_aliases(variant=p_variant, tg_id=p_tg_id, connection_id=p_conn_id)
