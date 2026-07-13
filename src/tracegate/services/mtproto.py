from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlencode, urlparse


class MTProtoConfigError(ValueError):
    pass


MTPROTO_FAKE_TLS_PROFILE_NAME = "MTProto-FakeTLS-Direct"
MTPROTO_DIRECT_PROFILE_NAME = "MTProto-Direct"


@dataclass(frozen=True)
class MTProtoShareLinks:
    client_secret_hex: str
    tg_uri: str
    https_url: str


@dataclass(frozen=True)
class MTProtoOfficialProxyCommand:
    argv: tuple[str, ...]
    accepted_secret_hexes: tuple[str, ...]


@dataclass(frozen=True)
class MTProtoIssuedSecret:
    telegram_id: int
    secret_hex: str


@dataclass(frozen=True)
class MTProtoMtgConfig:
    config_text: str
    client_secret_hex: str


@dataclass(frozen=True)
class MTProtoTelemtConfig:
    config_text: str
    client_secret_hex: str


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
    return tuple(entry.secret_hex for entry in load_mtproto_issued_secret_entries(issued_state_file))


def load_mtproto_issued_secret_entries(issued_state_file: str | Path) -> tuple[MTProtoIssuedSecret, ...]:
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
    ordered: list[MTProtoIssuedSecret] = []
    for _issued_at, telegram_id, secret_hex in sorted(active, key=lambda item: (item[0], item[1])):
        if secret_hex in seen:
            continue
        seen.add(secret_hex)
        ordered.append(MTProtoIssuedSecret(telegram_id=telegram_id, secret_hex=secret_hex))
    return tuple(ordered)


def _toml_string(value: object) -> str:
    return json.dumps(str(value), ensure_ascii=True)


def build_mtproto_mtg_config(
    *,
    listen_port: int,
    tls_domain: str,
    primary_secret_hex: str,
    socks5_proxy: str = "",
    domain_fronting_host: str = "",
    domain_fronting_port: int = 443,
    listen_ip: str = "127.0.0.1",
    concurrency: int = 8192,
    tolerate_time_skewness: str = "5m",
    transport: str = "tls",
) -> MTProtoMtgConfig:
    if int(listen_port or 0) <= 0:
        raise MTProtoConfigError("MTG listen port must be a positive integer")
    if int(domain_fronting_port or 0) <= 0:
        raise MTProtoConfigError("MTG domain-fronting port must be a positive integer")
    if int(concurrency or 0) <= 0:
        raise MTProtoConfigError("MTG concurrency must be a positive integer")

    normalized_transport = str(transport or "tls").strip().lower()
    if normalized_transport in {"plain"}:
        normalized_transport = "raw"
    if normalized_transport == "dd":
        normalized_transport = "random_padding"
    if normalized_transport not in {"tls", "raw", "random_padding"}:
        raise MTProtoConfigError(f"Unsupported MTG MTProto transport: {transport!r}")
    if normalized_transport != "tls":
        raise MTProtoConfigError("MTG runtime requires TLS/FakeTLS MTProto transport")

    normalized_tls_domain = normalize_mtproto_domain(tls_domain) if normalized_transport == "tls" else ""
    normalized_fronting_host = normalize_mtproto_domain(domain_fronting_host) if normalized_transport == "tls" else ""
    if normalized_fronting_host:
        try:
            legacy_fronting_ip = str(ipaddress.ip_address(normalized_fronting_host))
        except ValueError:
            legacy_fronting_ip = ""
    else:
        legacy_fronting_ip = ""
    primary_secret = _normalize_hex(primary_secret_hex)
    if len(primary_secret) != 32:
        raise MTProtoConfigError("MTG primary secret must contain exactly 16 bytes in hex")

    proxy = str(socks5_proxy or "").strip()
    if proxy and (not proxy.startswith("socks5://") or proxy == "socks5://"):
        raise MTProtoConfigError("MTG egress proxy must be a non-empty socks5:// URL when configured")

    bind_ip = str(listen_ip or "").strip() or "127.0.0.1"
    if bind_ip not in {"127.0.0.1", "::1"}:
        raise MTProtoConfigError("MTG must bind to loopback behind the Tracegate TLS demux")

    client_secret = build_mtproto_client_secret(
        primary_secret,
        transport=normalized_transport,
        domain=normalized_tls_domain or None,
    )
    lines = [
        "# Generated by Tracegate. Do not edit by hand.",
        f"secret = {_toml_string(client_secret)}",
        f"bind-to = {_toml_string(f'{bind_ip}:{int(listen_port)}')}",
        "proxy-protocol-listener = true",
        f"concurrency = {int(concurrency)}",
        'prefer-ip = "only-ipv4"',
        "auto-update = false",
        f"tolerate-time-skewness = {_toml_string(tolerate_time_skewness)}",
        "allow-fallback-on-unknown-dc = true",
    ]
    if normalized_transport == "tls":
        if legacy_fronting_ip:
            # MTG 2.2.x uses the legacy top-level IP while newer builds use
            # [domain-fronting].host. Emit both so a pinned fronting IP is honored.
            lines.append(f"domain-fronting-ip = {_toml_string(legacy_fronting_ip)}")
        lines.extend(["", "[domain-fronting]", f"host = {_toml_string(normalized_fronting_host)}", f"port = {int(domain_fronting_port)}"])
    lines.extend(
        [
            "",
            "[network.timeout]",
            'tcp = "10s"',
            'http = "15s"',
            'idle = "10m"',
            'handshake = "15s"',
            "",
            "[network.keep-alive]",
            "disabled = false",
            'idle = "15s"',
            'interval = "15s"',
            "count = 9",
            "",
            "[defense.anti-replay]",
            "enabled = true",
            'max-size = "1mib"',
            "error-rate = 0.001",
            "",
        ]
    )
    if proxy:
        network_index = lines.index("[network.timeout]")
        lines[network_index:network_index] = [
            "[network]",
            f"proxies = [{_toml_string(proxy)}]",
            "",
        ]
    return MTProtoMtgConfig(config_text="\n".join(lines), client_secret_hex=client_secret)


def build_mtproto_telemt_config(
    *,
    listen_port: int,
    tls_domain: str,
    primary_secret_hex: str,
    socks5_proxy: str = "",
    issued_secrets: tuple[MTProtoIssuedSecret, ...] | list[MTProtoIssuedSecret] = (),
    mask_host: str = "",
    mask_port: int = 443,
    public_host: str = "",
    public_port: int = 443,
    listen_ip: str = "127.0.0.1",
    metrics_port: int = 9090,
    tls_front_dir: str = "/var/lib/tracegate/private/mtproto/tlsfront",
) -> MTProtoTelemtConfig:
    """Build a strict Telemt FakeTLS configuration for the shared L4 demux.

    Telemt watches this file and hot-reloads ``access.users``. The primary
    secret is retained as a bootstrap/recovery credential, while issued
    per-user secrets can be added and revoked without restarting the process.
    """

    if int(listen_port or 0) <= 0:
        raise MTProtoConfigError("Telemt listen port must be a positive integer")
    if int(mask_port or 0) <= 0:
        raise MTProtoConfigError("Telemt mask port must be a positive integer")
    if int(public_port or 0) <= 0:
        raise MTProtoConfigError("Telemt public port must be a positive integer")
    if int(metrics_port or 0) <= 0:
        raise MTProtoConfigError("Telemt metrics port must be a positive integer")

    bind_ip = str(listen_ip or "").strip() or "127.0.0.1"
    if bind_ip not in {"127.0.0.1", "::1"}:
        raise MTProtoConfigError("Telemt must bind to loopback behind the Tracegate TLS demux")

    normalized_tls_domain = normalize_mtproto_domain(tls_domain)
    normalized_mask_host = normalize_mtproto_domain(mask_host or normalized_tls_domain)
    normalized_public_host = normalize_mtproto_domain(public_host or normalized_tls_domain)
    tls_dns_override_ip = ""
    try:
        mask_ip = ipaddress.ip_address(normalized_mask_host)
    except ValueError:
        mask_ip = None
    if mask_ip is not None and mask_ip.is_loopback:
        tls_dns_override_ip = str(mask_ip)
    primary_secret = _normalize_hex(primary_secret_hex)
    if len(primary_secret) != 32:
        raise MTProtoConfigError("Telemt primary secret must contain exactly 16 bytes in hex")

    proxy = str(socks5_proxy or "").strip()
    proxy_address = ""
    proxy_username = ""
    proxy_password = ""
    if proxy:
        parsed_proxy = urlparse(proxy)
        if parsed_proxy.scheme != "socks5" or not parsed_proxy.hostname or not parsed_proxy.port:
            raise MTProtoConfigError("Telemt egress proxy must be a non-empty socks5://host:port URL when configured")
        proxy_address = f"{parsed_proxy.hostname}:{parsed_proxy.port}"
        proxy_username = parsed_proxy.username or ""
        proxy_password = parsed_proxy.password or ""

    users: list[tuple[str, str]] = [("bootstrap", primary_secret)]
    seen = {primary_secret}
    for entry in issued_secrets:
        try:
            telegram_id = int(entry.telegram_id)
            secret_hex = _normalize_hex(entry.secret_hex)
        except (AttributeError, TypeError, ValueError, MTProtoConfigError):
            continue
        if telegram_id <= 0 or len(secret_hex) != 32 or secret_hex in seen:
            continue
        seen.add(secret_hex)
        users.append((f"tg_{telegram_id}", secret_hex))

    client_secret = build_mtproto_client_secret(
        primary_secret,
        transport="tls",
        domain=normalized_tls_domain,
    )
    lines = [
        "# Generated by Tracegate. Do not edit by hand.",
        "[general]",
        "config_strict = true",
        "prefer_ipv6 = false",
        "fast_mode = true",
        f"use_middle_proxy = {'false' if proxy_address else 'true'}",
        "me2dc_fallback = true",
        'log_level = "normal"',
        "",
        "[general.modes]",
        "classic = false",
        "secure = false",
        "tls = true",
        "",
        "[general.links]",
        "show = []",
        f"public_host = {_toml_string(normalized_public_host)}",
        f"public_port = {int(public_port)}",
        "",
    ]
    if tls_dns_override_ip:
        lines.extend(
            [
                "[network]",
                "ipv6 = false",
                "prefer = 4",
                f"dns_overrides = [{_toml_string(f'{normalized_tls_domain}:443:{tls_dns_override_ip}')}]",
                "",
            ]
        )
    lines.extend(
        [
            "[server]",
            f"port = {int(listen_port)}",
            f"listen_addr_ipv4 = {_toml_string(bind_ip)}",
            "proxy_protocol = true",
            "proxy_protocol_header_timeout_ms = 1000",
            'proxy_protocol_trusted_cidrs = ["127.0.0.1/32", "::1/128"]',
            f"metrics_listen = {_toml_string(f'127.0.0.1:{int(metrics_port)}')}",
            "",
            "[server.api]",
            "enabled = true",
            'listen = "127.0.0.1:9091"',
            'whitelist = ["127.0.0.1/32", "::1/128"]',
            "read_only = true",
            "",
            "[censorship]",
            f"tls_domain = {_toml_string(normalized_tls_domain)}",
            "mask = true",
            f"mask_host = {_toml_string(normalized_mask_host)}",
            f"mask_port = {int(mask_port)}",
            "tls_emulation = true",
            f"tls_front_dir = {_toml_string(str(tls_front_dir or '').strip())}",
            "",
            "[access.users]",
        ]
    )
    lines.extend(f"{_toml_string(username)} = {_toml_string(secret_hex)}" for username, secret_hex in users)
    lines.append("")
    if proxy_address:
        lines.extend(
            [
                "[[upstreams]]",
                'type = "socks5"',
                f"address = {_toml_string(proxy_address)}",
            ]
        )
        if proxy_username:
            lines.append(f"username = {_toml_string(proxy_username)}")
        if proxy_password:
            lines.append(f"password = {_toml_string(proxy_password)}")
        lines.extend(
            [
                "weight = 1",
                "enabled = true",
                "",
            ]
        )
    return MTProtoTelemtConfig(config_text="\n".join(lines), client_secret_hex=client_secret)


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
