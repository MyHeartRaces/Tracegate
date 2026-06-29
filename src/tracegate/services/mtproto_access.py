from __future__ import annotations

import json
import hashlib
import secrets
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

import fcntl

from tracegate.services.decoy_auth import DecoyAuthConfigError, load_mtproto_public_profile
from tracegate.services.mtproto import (
    MTPROTO_DIRECT_PROFILE_NAME,
    MTPROTO_FAKE_TLS_PROFILE_NAME,
    MTProtoConfigError,
    build_mtproto_share_links,
)
from tracegate.settings import Settings, effective_mtproto_issued_state_file


def _mtproto_secret_policy(base_profile: dict[str, Any]) -> str:
    raw = str(base_profile.get("secretPolicy") or "").strip().lower()
    if raw:
        return raw
    if base_profile.get("perUserSecrets") is False:
        return "shared"
    return "per-user"


def _mtproto_profile_ports(base_profile: dict[str, Any]) -> list[int]:
    candidates: list[object] = [base_profile.get("port")]
    raw_public_ports = base_profile.get("publicPorts")
    if isinstance(raw_public_ports, list):
        candidates.extend(raw_public_ports)

    ports: list[int] = []
    for candidate in candidates:
        try:
            port = int(candidate or 0)
        except (TypeError, ValueError):
            continue
        if port > 0 and port not in ports:
            ports.append(port)
    return ports


def _mtproto_profile_name(base_profile: dict[str, Any]) -> str:
    configured = str(base_profile.get("profile") or "").strip()
    if configured:
        return configured
    transport = str(base_profile.get("transport") or "tls").strip().lower()
    return MTPROTO_FAKE_TLS_PROFILE_NAME if transport == "tls" else MTPROTO_DIRECT_PROFILE_NAME


def _mtproto_profile_server(
    base_profile: dict[str, Any],
    *,
    telegram_id: int,
    ingress_generation: int,
    settings: Settings,
) -> str:
    configured = base_profile.get("servers")
    candidates = configured if isinstance(configured, list) else settings.mtproto_ingress_hosts
    hosts: list[str] = []
    for candidate in candidates:
        host = str(candidate or "").strip()
        if host and host not in hosts:
            hosts.append(host)
    if not hosts:
        return str(base_profile["server"])
    digest = hashlib.sha256(f"mtproto:{int(telegram_id)}".encode()).digest()
    base_index = int.from_bytes(digest[:8], "big") % len(hosts)
    return hosts[(base_index + max(0, int(ingress_generation))) % len(hosts)]


def _raw_secret_from_client_secret(base_profile: dict[str, Any]) -> str:
    client_secret = "".join(
        ch for ch in str(base_profile.get("clientSecretHex") or "").strip().lower() if ch in "0123456789abcdef"
    )
    if len(client_secret) == 32:
        return client_secret
    if client_secret.startswith("ee") and len(client_secret) > 34:
        return client_secret[2:34]
    if client_secret.startswith("dd") and len(client_secret) == 34:
        return client_secret[2:]
    raise DecoyAuthConfigError("base MTProto profile does not expose a usable server secret")


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
    try:
        ingress_generation = max(0, int(raw.get("ingressGeneration") or 0))
    except (TypeError, ValueError):
        ingress_generation = 0

    entry = {
        "telegramId": telegram_id,
        "secretHex": secret_hex,
        "issuedAt": _iso(issued_at),
        "updatedAt": _iso(updated_at),
        "ingressGeneration": ingress_generation,
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
        lock_path.chmod(0o600)
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
    tmp.chmod(0o600)
    tmp.replace(path)
    path.chmod(0o600)


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
    secret_policy = _mtproto_secret_policy(base_profile)
    if secret_policy not in {"per-user", "shared"}:
        raise DecoyAuthConfigError(f"unsupported MTProto secret policy: {secret_policy}")
    shared_secret_hex = _raw_secret_from_client_secret(base_profile) if secret_policy == "shared" else ""

    changed = False
    with _locked_state(settings) as path:
        previous_entries = _read_entries(path)
        by_telegram_id = {int(entry["telegramId"]): dict(entry) for entry in previous_entries}
        current = by_telegram_id.get(int(telegram_id))

        if current is None or rotate or (secret_policy == "shared" and current.get("secretHex") != shared_secret_hex):
            changed = True
            previous_generation = int(current.get("ingressGeneration") or 0) if current else -1
            current = {
                "telegramId": int(telegram_id),
                "secretHex": shared_secret_hex if secret_policy == "shared" else secrets.token_hex(16),
                "issuedAt": _iso(effective_now),
                "updatedAt": _iso(effective_now),
                "ingressGeneration": previous_generation + 1,
            }
            if normalized_label:
                current["label"] = normalized_label
            if normalized_issued_by:
                current["issuedBy"] = normalized_issued_by
            by_telegram_id[int(telegram_id)] = current
            _write_entries(path, list(by_telegram_id.values()))

        next_entries = sorted(by_telegram_id.values(), key=_entry_sort_key)

    try:
        base_transport = str(base_profile.get("transport") or "tls").strip().lower()
        base_domain = str(base_profile.get("domain") or "").strip()
        secret_hex = str(base_profile["clientSecretHex"]) if secret_policy == "shared" else str(current["secretHex"])
        ports = _mtproto_profile_ports(base_profile)
        selected_server = _mtproto_profile_server(
            base_profile,
            telegram_id=telegram_id,
            ingress_generation=int(current.get("ingressGeneration") or 0),
            settings=settings,
        )
        if not ports:
            raise ValueError("base MTProto profile does not expose a usable public port")
        link_domain = base_domain or str(base_profile.get("tlsDomain") or "")
        if base_transport != "tls":
            link_domain = ""
        link_rows = []
        for port in ports:
            links = build_mtproto_share_links(
                server=selected_server,
                port=port,
                secret_hex=secret_hex,
                transport=None if secret_policy == "shared" else base_transport,
                domain=link_domain or None,
            )
            link_rows.append(
                {
                    "port": port,
                    "clientSecretHex": links.client_secret_hex,
                    "tgUri": links.tg_uri,
                    "httpsUrl": links.https_url,
                }
            )
    except (KeyError, TypeError, ValueError, MTProtoConfigError) as exc:
        if changed:
            set_mtproto_access_entries(settings, previous_entries)
        raise DecoyAuthConfigError("unable to build MTProto access profile") from exc
    primary_link = link_rows[0]

    profile = {
        "protocol": "mtproto",
        "profile": _mtproto_profile_name(base_profile),
        "server": selected_server,
        "port": int(primary_link["port"]),
        "transport": str(base_profile.get("transport") or "tls"),
        "domain": str(base_profile.get("domain") or ""),
        "tlsDomain": str(base_profile.get("tlsDomain") or ""),
        "clientSecretHex": str(primary_link["clientSecretHex"]),
        "tgUri": str(primary_link["tgUri"]),
        "httpsUrl": str(primary_link["httpsUrl"]),
        "ephemeral": False,
        "telegramId": int(current["telegramId"]),
        "issuedAt": str(current["issuedAt"]),
        "updatedAt": str(current["updatedAt"]),
        "reused": not changed,
        "secretPolicy": secret_policy,
        "ingressGeneration": int(current.get("ingressGeneration") or 0),
    }
    if len(link_rows) > 1:
        profile["publicPorts"] = ports
        profile["links"] = link_rows
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
