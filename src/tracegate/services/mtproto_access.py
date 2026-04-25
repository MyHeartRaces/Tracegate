from __future__ import annotations

import json
import secrets
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

import fcntl

from tracegate.services.decoy_auth import DecoyAuthConfigError, load_mtproto_public_profile
from tracegate.services.mtproto import MTPROTO_FAKE_TLS_PROFILE_NAME, MTProtoConfigError, build_mtproto_share_links
from tracegate.settings import Settings, effective_mtproto_issued_state_file


def _state_path(settings: Settings) -> Path:
    return Path(effective_mtproto_issued_state_file(settings))


def _lock_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".lock")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_iso(raw: str) -> datetime | None:
    value = str(raw or "").strip()
    if not value:
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _normalize_secret_hex(raw: str) -> str | None:
    value = "".join(ch for ch in str(raw or "").strip().lower() if ch in "0123456789abcdef")
    return value if len(value) == 32 else None


def _entry_sort_key(entry: dict[str, Any]) -> tuple[int, str, str]:
    return (
        int(entry.get("telegramId") or 0),
        str(entry.get("updatedAt") or ""),
        str(entry.get("issuedAt") or ""),
    )


def _normalize_entry(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None

    try:
        telegram_id = int(raw.get("telegramId") or 0)
    except (TypeError, ValueError):
        return None
    if telegram_id <= 0:
        return None

    secret_hex = _normalize_secret_hex(str(raw.get("secretHex") or ""))
    issued_at = _parse_iso(str(raw.get("issuedAt") or ""))
    updated_at = _parse_iso(str(raw.get("updatedAt") or "")) or issued_at
    if not secret_hex or issued_at is None or updated_at is None:
        return None

    entry = {
        "telegramId": telegram_id,
        "secretHex": secret_hex,
        "issuedAt": _iso(issued_at),
        "updatedAt": _iso(updated_at),
    }
    for key in ("label", "issuedBy"):
        value = str(raw.get(key) or "").strip()
        if value:
            entry[key] = value
    return entry


@contextmanager
def _locked_state(settings: Settings) -> Iterator[Path]:
    path = _state_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = _lock_path(path)
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield path
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _read_entries(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []

    payload = raw.get("entries") if isinstance(raw, dict) else raw
    if not isinstance(payload, list):
        return []

    by_telegram_id: dict[int, dict[str, Any]] = {}
    for item in payload:
        normalized = _normalize_entry(item)
        if normalized is None:
            continue
        by_telegram_id[int(normalized["telegramId"])] = normalized
    return sorted(by_telegram_id.values(), key=_entry_sort_key)


def _write_entries(path: Path, entries: list[dict[str, Any]]) -> None:
    payload = {"version": 1, "entries": sorted(entries, key=_entry_sort_key)}
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def load_mtproto_access_entries(settings: Settings) -> list[dict[str, Any]]:
    with _locked_state(settings) as path:
        return _read_entries(path)


def set_mtproto_access_entries(settings: Settings, entries: list[dict[str, Any]]) -> None:
    normalized: dict[int, dict[str, Any]] = {}
    for item in entries:
        entry = _normalize_entry(item)
        if entry is None:
            continue
        normalized[int(entry["telegramId"])] = entry
    with _locked_state(settings) as path:
        _write_entries(path, list(normalized.values()))


def issue_mtproto_access_profile(
    settings: Settings,
    *,
    telegram_id: int,
    label: str = "",
    issued_by: str = "",
    rotate: bool = False,
    now: datetime | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], bool]:
    if int(telegram_id or 0) <= 0:
        raise ValueError("telegram_id must be a positive integer")

    base_profile = load_mtproto_public_profile(settings)
    effective_now = now or _utc_now()
    normalized_label = str(label or "").strip()
    normalized_issued_by = str(issued_by or "").strip()

    changed = False
    with _locked_state(settings) as path:
        previous_entries = _read_entries(path)
        by_telegram_id = {int(entry["telegramId"]): dict(entry) for entry in previous_entries}
        current = by_telegram_id.get(int(telegram_id))

        if current is None or rotate:
            changed = True
            current = {
                "telegramId": int(telegram_id),
                "secretHex": secrets.token_hex(16),
                "issuedAt": _iso(effective_now),
                "updatedAt": _iso(effective_now),
            }
            if normalized_label:
                current["label"] = normalized_label
            if normalized_issued_by:
                current["issuedBy"] = normalized_issued_by
            by_telegram_id[int(telegram_id)] = current
            _write_entries(path, list(by_telegram_id.values()))

        next_entries = sorted(by_telegram_id.values(), key=_entry_sort_key)

    try:
        links = build_mtproto_share_links(
            server=str(base_profile["server"]),
            port=int(base_profile["port"]),
            secret_hex=str(current["secretHex"]),
            transport=str(base_profile.get("transport") or "tls"),
            domain=str(base_profile.get("domain") or base_profile["server"]),
        )
    except (KeyError, TypeError, ValueError, MTProtoConfigError) as exc:
        if changed:
            set_mtproto_access_entries(settings, previous_entries)
        raise DecoyAuthConfigError("unable to build MTProto access profile") from exc

    profile = {
        "protocol": "mtproto",
        "profile": str(base_profile.get("profile") or MTPROTO_FAKE_TLS_PROFILE_NAME),
        "server": str(base_profile["server"]),
        "port": int(base_profile["port"]),
        "transport": str(base_profile.get("transport") or "tls"),
        "domain": str(base_profile.get("domain") or base_profile["server"]),
        "clientSecretHex": links.client_secret_hex,
        "tgUri": links.tg_uri,
        "httpsUrl": links.https_url,
        "ephemeral": False,
        "telegramId": int(current["telegramId"]),
        "issuedAt": str(current["issuedAt"]),
        "updatedAt": str(current["updatedAt"]),
        "reused": not changed,
    }
    if current.get("label"):
        profile["label"] = str(current["label"])
    if current.get("issuedBy"):
        profile["issuedBy"] = str(current["issuedBy"])
    return profile, previous_entries, next_entries, changed


def revoke_mtproto_access(
    settings: Settings,
    *,
    telegram_id: int,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], list[dict[str, Any]]]:
    if int(telegram_id or 0) <= 0:
        raise ValueError("telegram_id must be a positive integer")

    with _locked_state(settings) as path:
        previous_entries = _read_entries(path)
        next_entries = [entry for entry in previous_entries if int(entry.get("telegramId") or 0) != int(telegram_id)]
        removed = next((entry for entry in previous_entries if int(entry.get("telegramId") or 0) == int(telegram_id)), None)
        if removed is not None:
            _write_entries(path, next_entries)
    return removed, previous_entries, next_entries
