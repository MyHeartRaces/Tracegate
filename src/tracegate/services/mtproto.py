from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlencode


class MTProtoConfigError(ValueError):
    pass


MTPROTO_FAKE_TLS_PROFILE_NAME = "MTProto-FakeTLS-Direct"


@dataclass(frozen=True)
class MTProtoShareLinks:
    client_secret_hex: str
    tg_uri: str
    https_url: str


@dataclass(frozen=True)
class MTProtoOfficialProxyCommand:
    argv: tuple[str, ...]
    accepted_secret_hexes: tuple[str, ...]


def _normalize_hex(value: str) -> str:
    normalized = "".join(ch for ch in str(value or "").strip().lower() if ch in "0123456789abcdef")
    if not normalized:
        raise MTProtoConfigError("MTProto secret is empty")
    if len(normalized) % 2 != 0:
        raise MTProtoConfigError("MTProto secret must contain an even number of hex characters")
    return normalized


def normalize_mtproto_domain(domain: str) -> str:
    normalized = str(domain or "").strip().rstrip(".").lower()
    if not normalized:
        raise MTProtoConfigError("MTProto domain is required for TLS transport")
    try:
        return normalized.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise MTProtoConfigError("MTProto domain is not valid IDNA") from exc


def build_mtproto_client_secret(
    secret_hex: str,
    *,
    transport: str = "raw",
    domain: str | None = None,
) -> str:
    normalized_secret = _normalize_hex(secret_hex)
    normalized_transport = str(transport or "raw").strip().lower()

    if normalized_transport == "tls":
        if len(normalized_secret) != 32:
            raise MTProtoConfigError("MTProto TLS transport requires a raw 16-byte secret in hex")
        normalized_domain = normalize_mtproto_domain(domain or "")
        return "ee" + normalized_secret + normalized_domain.encode("ascii").hex()

    if normalized_transport in {"random_padding", "dd"}:
        if len(normalized_secret) != 32:
            raise MTProtoConfigError("MTProto random padding transport requires a raw 16-byte secret in hex")
        return "dd" + normalized_secret

    if normalized_transport in {"raw", "plain"}:
        if len(normalized_secret) != 32:
            raise MTProtoConfigError("MTProto raw transport requires a raw 16-byte secret in hex")
        return normalized_secret

    raise MTProtoConfigError(f"Unsupported MTProto transport: {transport!r}")


def resolve_mtproto_client_secret(
    secret_hex: str,
    *,
    transport: str | None = None,
    domain: str | None = None,
) -> str:
    normalized_secret = _normalize_hex(secret_hex)
    normalized_transport = str(transport or "").strip().lower()

    if normalized_transport:
        return build_mtproto_client_secret(normalized_secret, transport=normalized_transport, domain=domain)

    if normalized_secret.startswith("ee") and len(normalized_secret) > 34:
        return normalized_secret
    if normalized_secret.startswith("dd") and len(normalized_secret) == 34:
        return normalized_secret
    if len(normalized_secret) == 32:
        return normalized_secret
    raise MTProtoConfigError("Unable to resolve MTProto client secret")


def build_mtproto_share_links(
    *,
    server: str,
    port: int,
    secret_hex: str,
    transport: str | None = None,
    domain: str | None = None,
) -> MTProtoShareLinks:
    normalized_server = normalize_mtproto_domain(server)
    normalized_port = int(port or 0)
    if normalized_port <= 0:
        raise MTProtoConfigError("MTProto port must be a positive integer")

    client_secret = resolve_mtproto_client_secret(secret_hex, transport=transport, domain=domain)
    query = urlencode({"server": normalized_server, "port": normalized_port, "secret": client_secret})
    return MTProtoShareLinks(
        client_secret_hex=client_secret,
        tg_uri=f"tg://proxy?{query}",
        https_url=f"https://t.me/proxy?{query}",
    )


def load_mtproto_server_secret(secret_file: str | Path) -> str:
    path = Path(secret_file)
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise MTProtoConfigError(f"MTProto secret file not found: {path}") from exc

    normalized = _normalize_hex(raw)
    if len(normalized) != 32:
        raise MTProtoConfigError("MTProto server secret must contain exactly 16 bytes in hex")
    return normalized


def _parse_state_timestamp(raw: object) -> datetime | None:
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


def load_mtproto_issued_secret_hexes(issued_state_file: str | Path) -> tuple[str, ...]:
    path = Path(issued_state_file)
    if not path.is_file():
        return ()

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return ()

    payload = raw.get("entries") if isinstance(raw, dict) else raw
    if not isinstance(payload, list):
        return ()

    active: list[tuple[datetime, int, str]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        try:
            telegram_id = int(item.get("telegramId") or 0)
        except (TypeError, ValueError):
            continue
        if telegram_id <= 0:
            continue
        try:
            secret_hex = _normalize_hex(str(item.get("secretHex") or ""))
        except MTProtoConfigError:
            continue
        if len(secret_hex) != 32:
            continue
        issued_at = _parse_state_timestamp(item.get("updatedAt")) or _parse_state_timestamp(item.get("issuedAt"))
        if issued_at is None:
            issued_at = datetime.fromtimestamp(0, UTC)
        active.append((issued_at, telegram_id, secret_hex))

    seen: set[str] = set()
    ordered: list[str] = []
    for _issued_at, _telegram_id, secret_hex in sorted(active, key=lambda item: (item[0], item[1])):
        if secret_hex in seen:
            continue
        seen.add(secret_hex)
        ordered.append(secret_hex)
    return tuple(ordered)


def build_mtproto_official_proxy_command(
    *,
    binary: str,
    run_as_user: str,
    stats_port: int,
    listen_port: int,
    bind_address: str = "",
    nat_info: str = "",
    primary_secret_hex: str,
    issued_secret_hexes: tuple[str, ...] | list[str] = (),
    proxy_secret_file: str,
    proxy_config_file: str,
    workers: int,
    proxy_tag: str = "",
    tls_mode: str = "raw",
    domain: str = "",
) -> MTProtoOfficialProxyCommand:
    binary_value = str(binary or "").strip()
    if not binary_value:
        raise MTProtoConfigError("MTProto binary path is required")

    user_value = str(run_as_user or "").strip()
    if not user_value:
        raise MTProtoConfigError("MTProto run-as user is required")

    if int(stats_port or 0) <= 0:
        raise MTProtoConfigError("MTProto stats port must be a positive integer")
    if int(listen_port or 0) <= 0:
        raise MTProtoConfigError("MTProto listen port must be a positive integer")
    workers_value = int(workers or 0)
    if workers_value < 0:
        raise MTProtoConfigError("MTProto workers must be a non-negative integer")

    primary_secret = _normalize_hex(primary_secret_hex)
    if len(primary_secret) != 32:
        raise MTProtoConfigError("MTProto primary server secret must contain exactly 16 bytes in hex")

    accepted_secret_hexes: list[str] = [primary_secret]
    seen = {primary_secret}
    for raw_secret in issued_secret_hexes:
        normalized = _normalize_hex(str(raw_secret or ""))
        if len(normalized) != 32 or normalized in seen:
            continue
        seen.add(normalized)
        accepted_secret_hexes.append(normalized)

    tls_mode_value = str(tls_mode or "").strip().lower()
    argv = [
        binary_value,
        "-u",
        user_value,
        "-p",
        str(int(stats_port)),
        "-H",
        str(int(listen_port)),
    ]
    for secret_hex in accepted_secret_hexes:
        argv.extend(["-S", secret_hex])

    proxy_tag_value = str(proxy_tag or "").strip()
    if proxy_tag_value:
        argv.extend(["-P", proxy_tag_value])

    if tls_mode_value == "private-fronting":
        normalized_domain = normalize_mtproto_domain(domain)
        argv.extend(["--domain", normalized_domain])

    bind_address_value = str(bind_address or "").strip()
    if bind_address_value:
        argv.extend(["--address", bind_address_value])

    nat_info_value = str(nat_info or "").strip()
    if nat_info_value:
        if ":" not in nat_info_value:
            raise MTProtoConfigError("MTProto nat_info must use <local-addr>:<global-addr>")
        argv.extend(["--nat-info", nat_info_value])

    argv.extend(["--aes-pwd", str(proxy_secret_file), str(proxy_config_file)])
    if workers_value > 0:
        argv.extend(["-M", str(workers_value)])
    return MTProtoOfficialProxyCommand(argv=tuple(argv), accepted_secret_hexes=tuple(accepted_secret_hexes))
