from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any
from urllib.parse import quote, urlencode, urlparse

import yaml

from tracegate.constants import TRACEGATE_PUBLIC_UDP_PORT
from tracegate.services.mtproto import (
    MTPROTO_FAKE_TLS_PROFILE_NAME,
    MTProtoConfigError,
    build_mtproto_share_links,
)

_LOCAL_SOCKS_PORT_BASE = 20000
_LOCAL_SOCKS_PORT_SPAN = 40000
_HYSTERIA_CHAIN_CLIENT_RATE_LIMIT_MBIT = 10
_HYSTERIA_DIRECT_DEFAULT_MBIT = 100


class ClientConfigExportError(ValueError):
    pass


@dataclass(frozen=True)
class ExportResult:
    kind: str
    title: str
    content: str
    alternate_title: str | None = None
    alternate_content: str | None = None
    extra_messages: tuple[tuple[str, str], ...] = ()
    filename: str | None = None
    attachment_content: bytes | None = None
    attachment_filename: str | None = None
    attachment_mime: str | None = None


def _q(s: str) -> str:
    # Share links typically expect URL-encoded fragments/params.
    return quote(s, safe="")


def _encode_query(params: dict[str, Any], *, safe: str = "") -> str:
    # `path=/ws` is more interoperable than `%2Fws` for some clients.
    return urlencode(params, safe=safe)


def _vless_encryption(effective: dict[str, Any]) -> str:
    block = effective.get("vless_encryption")
    if isinstance(block, dict) and bool(block.get("enabled", False)):
        raise ClientConfigExportError("Encrypted VLESS was removed from Tracegate 3")
    return "none"


def _normalize_alpn(value: object, *, default: tuple[str, ...]) -> list[str]:
    if isinstance(value, str):
        items = [value]
    elif isinstance(value, (list, tuple)):
        items = [str(item) for item in value]
    else:
        items = list(default)
    normalized = [item.strip() for item in items if item.strip()]
    return normalized or list(default)


def _safe_filename_fragment(value: str) -> str:
    normalized = "".join(
        ch.lower() if ch.isalnum() else "-" for ch in str(value or "").strip()
    )
    compact = "-".join(part for part in normalized.split("-") if part)
    return compact or "tracegate"


def _artifact_filename_fragment(profile_name: str) -> str:
    """Keep client-facing artifact filenames aligned with the menu taxonomy."""
    return {
        "Tracegate-Reality": "direct-vless",
        "Tracegate-Hysteria(Salamander)": "direct-hysteria",
        "Tracegate-Hysteria(Gecko)": "direct-hysteria",
        "Tracegate-Chain": "chain",
        "Tracegate-Backup(gRPC)": "backup-vless-grpc",
        "Tracegate-Backup(WebSocket)": "backup-vless-websocket",
    }.get(profile_name, _safe_filename_fragment(profile_name))


def client_profile_name(effective: dict[str, Any]) -> str:
    protocol = str(effective.get("protocol") or "").strip().lower()
    transport = str(effective.get("transport") or "").strip().lower()
    is_chain = isinstance(effective.get("chain"), dict)
    if is_chain:
        return "Tracegate-Chain"
    if protocol == "vless" and (
        transport
        in {"reality", "reality_raw", "reality-raw", "raw_reality", "raw-tcp-reality"}
        or isinstance(effective.get("reality"), dict)
    ):
        return "Tracegate-Reality"
    if protocol == "hysteria2":
        obfs = effective.get("obfs") if isinstance(effective.get("obfs"), dict) else {}
        obfs_type = (
            str(obfs.get("type") or effective.get("hysteria_obfs") or "salamander")
            .strip()
            .lower()
        )
        label = "Gecko" if obfs_type == "gecko" else "Salamander"
        return f"Tracegate-Hysteria({label})"
    if protocol == "vless" and transport in {"ws_tls", "ws+tls", "ws-tls"}:
        return "Tracegate-Backup(WebSocket)"
    if protocol == "vless" and transport in {"grpc_tls", "grpc+tls", "grpc-tls"}:
        return "Tracegate-Backup(gRPC)"
    return str(effective.get("profile") or "Tracegate").strip() or "Tracegate"


def _is_loopback_host(host: str) -> bool:
    normalized = str(host or "").strip().lower()
    if normalized == "localhost":
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


def _is_ip_literal(host: str) -> bool:
    normalized = str(host or "").strip().strip("[]")
    if not normalized:
        return False
    try:
        ip_address(normalized)
        return True
    except ValueError:
        return False


def _normalize_route_host(value: object) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.hostname or ""
    else:
        raw = raw.split("/", 1)[0].split("?", 1)[0].strip()
        if raw.startswith("["):
            raw = raw[1:].split("]", 1)[0]
        elif raw.count(":") == 1:
            host, sep, port = raw.rpartition(":")
            if sep and port.isdigit():
                raw = host
    return raw.strip().strip("[]").rstrip(".").lower()


def _singbox_direct_route_rules_for_outbounds(
    outbounds: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Route proxy bearer addresses outside the proxy to avoid TUN/FakeIP loops."""

    domains: set[str] = set()
    cidrs: set[str] = set()
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            continue
        host = _normalize_route_host(outbound.get("server"))
        if not host or host == "localhost":
            continue
        try:
            parsed_ip = ip_address(host)
        except ValueError:
            domains.add(host)
            continue
        if parsed_ip.is_loopback or parsed_ip.is_unspecified:
            continue
        cidrs.add(f"{parsed_ip}/{32 if parsed_ip.version == 4 else 128}")

    rules: list[dict[str, Any]] = []
    if domains:
        rules.append({"domain": sorted(domains), "outbound": "direct"})
    if cidrs:
        rules.append({"ip_cidr": sorted(cidrs), "outbound": "direct"})
    return rules


def _client_connect_server(effective: dict[str, Any]) -> str:
    return str(effective.get("connect_host") or effective.get("server") or "").strip()


def _default_local_socks_port(effective: dict[str, Any]) -> int:
    seed = "|".join(
        str(effective.get(key) or "")
        for key in (
            "protocol",
            "transport",
            "profile",
            "server",
            "uuid",
            "device_id",
            "sni",
        )
    ).encode("utf-8")
    digest = hashlib.sha256(seed).digest()
    return _LOCAL_SOCKS_PORT_BASE + (
        int.from_bytes(digest[:4], "big") % _LOCAL_SOCKS_PORT_SPAN
    )


def _parse_local_socks_listen(effective: dict[str, Any]) -> tuple[str, int]:
    local_socks = effective.get("local_socks") or {}
    listen = str(
        local_socks.get("listen") or f"127.0.0.1:{_default_local_socks_port(effective)}"
    ).strip()
    if listen.startswith("["):
        host_end = listen.find("]")
        if host_end < 0 or host_end + 1 >= len(listen) or listen[host_end + 1] != ":":
            raise ClientConfigExportError(
                f"Invalid local SOCKS5 listen endpoint: {listen}"
            )
        host = listen[1:host_end]
        port_raw = listen[host_end + 2 :]
    else:
        host, sep, port_raw = listen.rpartition(":")
        if not sep:
            host = "127.0.0.1"
            port_raw = listen
    host = host.strip() or "127.0.0.1"
    if not _is_loopback_host(host):
        raise ClientConfigExportError(
            f"Local SOCKS5 listen must stay on loopback, got {listen}"
        )
    try:
        port = int(str(port_raw).strip())
    except (TypeError, ValueError):
        raise ClientConfigExportError(
            f"Invalid local SOCKS5 listen port: {listen}"
        ) from None
    if port < 1 or port > 65535:
        raise ClientConfigExportError(f"Invalid local SOCKS5 listen port: {listen}")
    return "127.0.0.1", port


def _local_socks_endpoint(effective: dict[str, Any]) -> tuple[str, int]:
    return _parse_local_socks_listen(effective)


def _local_socks_auth(effective: dict[str, Any]) -> tuple[str, str]:
    raw_local_socks = effective.get("local_socks")
    local_socks = raw_local_socks if isinstance(raw_local_socks, dict) else {}
    raw_auth = local_socks.get("auth")
    auth = raw_auth if isinstance(raw_auth, dict) else {}
    if local_socks and not auth:
        raise ClientConfigExportError("Local SOCKS5 auth is required")
    if auth.get("required") is False:
        raise ClientConfigExportError("Local SOCKS5 auth is explicitly disabled")
    mode = str(auth.get("mode") or "").strip()
    if mode and mode not in {"username_password", "generated"}:
        raise ClientConfigExportError(f"Unsupported local SOCKS5 auth mode: {mode}")
    username = str(auth.get("username") or "").strip()
    password = str(auth.get("password") or "").strip()
    if username and password:
        return username, password
    if auth:
        raise ClientConfigExportError(
            "Local SOCKS5 auth requires username and password"
        )

    seed = "|".join(
        str(effective.get(key) or "")
        for key in (
            "protocol",
            "transport",
            "profile",
            "server",
            "uuid",
            "device_id",
            "sni",
        )
    ).encode("utf-8")
    digest = hashlib.sha256(seed).digest()
    username = f"tg_{digest[:5].hex()}"
    password = (
        base64.urlsafe_b64encode(
            hashlib.sha256(digest + b":attachment-local-socks").digest()
        )
        .decode("ascii")
        .rstrip("=")
    )
    return username, password[:32]


def _local_socks_extra_message(effective: dict[str, Any]) -> tuple[str, str]:
    host, port = _local_socks_endpoint(effective)
    username, password = _local_socks_auth(effective)
    uri = f"socks5://{_q(username)}:{_q(password)}@{host}:{port}"
    return (
        "Local SOCKS5 credentials",
        "\n".join(
            [
                f"Host: {host}",
                f"Port: {port}",
                f"Username: {username}",
                f"Password: {password}",
                f"URI: {uri}",
            ]
        ),
    )


def _reject_client_management_api(effective: dict[str, Any]) -> None:
    for key in ("client_api", "xray_api"):
        block = effective.get(key)
        if not isinstance(block, dict):
            continue
        services_raw = block.get("services") or []
        services = (
            {str(item).strip().lower() for item in services_raw if str(item).strip()}
            if isinstance(services_raw, list)
            else set()
        )
        handler_enabled = bool(
            block.get("handler_service", False) or block.get("handlerService", False)
        )
        if handler_enabled or "handlerservice" in services:
            raise ClientConfigExportError(
                "Client-side Xray HandlerService is forbidden"
            )
        if (
            bool(
                block.get("reflection_service", False)
                or block.get("reflectionService", False)
            )
            or "reflectionservice" in services
        ):
            raise ClientConfigExportError(
                "Client-side Xray ReflectionService is forbidden"
            )
        if bool(block.get("enabled", False)):
            raise ClientConfigExportError(
                "Client-side Xray API is forbidden for exported profiles"
            )


def _build_xray_client_attachment(
    effective: dict[str, Any], outbound: dict[str, Any]
) -> tuple[bytes, str]:
    profile_name = client_profile_name(effective)
    local_host, local_port = _local_socks_endpoint(effective)
    socks_username, socks_password = _local_socks_auth(effective)
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "local-socks",
                "listen": local_host,
                "port": local_port,
                "protocol": "socks",
                "settings": {
                    "auth": "password",
                    "accounts": [{"user": socks_username, "pass": socks_password}],
                    "udp": True,
                },
            }
        ],
        "outbounds": [outbound],
    }
    filename = f"{_artifact_filename_fragment(profile_name)}.xray.json"
    return json.dumps(config, ensure_ascii=True, indent=2).encode("utf-8"), filename


def _build_singbox_client_attachment(
    effective: dict[str, Any],
    outbound: dict[str, Any] | list[dict[str, Any]],
    *,
    inbound_type: str = "mixed",
) -> tuple[bytes, str]:
    profile_name = client_profile_name(effective)
    local_host, local_port = _local_socks_endpoint(effective)
    socks_username, socks_password = _local_socks_auth(effective)
    outbounds = outbound if isinstance(outbound, list) else [outbound]
    route: dict[str, Any] = {
        "auto_detect_interface": True,
        "default_domain_resolver": "cloudflare",
        "final": "proxy",
    }
    direct_route_rules = _singbox_direct_route_rules_for_outbounds(outbounds)
    if direct_route_rules:
        route["rules"] = direct_route_rules

    config = {
        "log": {"level": "warn"},
        "dns": {
            "servers": [
                {
                    "type": "udp",
                    "tag": "cloudflare",
                    "server": "1.1.1.1",
                    "server_port": 53,
                }
            ],
            "final": "cloudflare",
            "strategy": "ipv4_only",
        },
        "inbounds": [
            {
                "type": inbound_type,
                "tag": "local-in",
                "listen": local_host,
                "listen_port": local_port,
                "users": [{"username": socks_username, "password": socks_password}],
            }
        ],
        "outbounds": outbounds,
        "route": route,
    }
    filename = f"{_artifact_filename_fragment(profile_name)}.singbox.json"
    return json.dumps(config, ensure_ascii=True, indent=2).encode("utf-8"), filename


def _hysteria_port_hopping(effective: dict[str, Any]) -> dict[str, Any] | None:
    """Return the stored port-hopping block of a Hysteria revision, if any.

    Only revisions issued with a configured hop range carry ``port_hopping``;
    every other stored config exports exactly as before.
    """

    block = effective.get("port_hopping")
    if not isinstance(block, dict):
        return None
    raw_ports = str(block.get("ports") or "").strip()
    lower_raw, sep, upper_raw = raw_ports.partition("-")
    try:
        lower = int(lower_raw)
        upper = int(upper_raw)
        min_interval = int(block.get("min_interval_s") or 0)
        max_interval = int(block.get("max_interval_s") or 0)
    except (TypeError, ValueError):
        raise ClientConfigExportError("Invalid Hysteria2 port hopping block") from None
    if not sep or not 1 <= lower < upper <= 65535 or min_interval <= 0 or max_interval <= min_interval:
        raise ClientConfigExportError("Invalid Hysteria2 port hopping block")
    return {
        "lower": lower,
        "upper": upper,
        "min_interval_s": min_interval,
        "max_interval_s": max_interval,
    }


def _build_hysteria_client_attachment(
    effective: dict[str, Any],
    *,
    server: str,
    port: int,
    auth: str,
    sni: str,
    insecure: bool,
    obfs_password: str,
    min_packet_size: int,
    max_packet_size: int,
    port_hopping: dict[str, Any] | None = None,
) -> tuple[bytes, str]:
    """Build an official Hysteria client config for Gecko.

    sing-box supports Hysteria2 Salamander but does not implement Gecko.  A
    Gecko profile must therefore be exported for the official Hysteria client
    instead of being mislabeled as a usable sing-box attachment.
    """

    profile_name = client_profile_name(effective)
    local_host, local_port = _local_socks_endpoint(effective)
    socks_username, socks_password = _local_socks_auth(effective)
    server_address = f"{server}:{port}"
    if port_hopping is not None:
        # Official multi-port syntax: the listener port plus the hop range.
        server_address = f"{server}:{port},{port_hopping['lower']}-{port_hopping['upper']}"
    config: dict[str, Any] = {
        "server": server_address,
        "auth": auth,
        "tls": {"sni": sni or server, "insecure": insecure},
        "obfs": {
            "type": "gecko",
            "gecko": {
                "password": obfs_password,
                "minPacketSize": min_packet_size,
                "maxPacketSize": max_packet_size,
            },
        },
        "bandwidth": {
            "up": f'{_hysteria_export_mbps(effective, "up_mbps")} mbps',
            "down": f'{_hysteria_export_mbps(effective, "down_mbps")} mbps',
        },
        "socks5": {
            "listen": f"{local_host}:{local_port}",
            "username": socks_username,
            "password": socks_password,
            "disableUDP": False,
        },
    }
    if port_hopping is not None:
        config["transport"] = {
            "type": "udp",
            "udp": {
                "minHopInterval": f"{port_hopping['min_interval_s']}s",
                "maxHopInterval": f"{port_hopping['max_interval_s']}s",
            },
        }
    filename = f"{_artifact_filename_fragment(profile_name)}.hysteria.yaml"
    rendered = yaml.safe_dump(config, sort_keys=False, allow_unicode=False)
    return rendered.encode("utf-8"), filename


def _is_hysteria_chain_profile(effective: dict[str, Any]) -> bool:
    mode = str(effective.get("mode") or "").strip().lower()
    if mode == "chain":
        return True
    chain = effective.get("chain")
    if isinstance(chain, dict) and chain:
        return True
    profile = str(effective.get("profile") or "").strip().lower()
    return "chain" in profile


def _hysteria_chain_limit_mbit(effective: dict[str, Any]) -> int:
    rate_limit = effective.get("rate_limit")
    if isinstance(rate_limit, dict):
        try:
            max_mbit = int(rate_limit.get("max_mbit") or 0)
        except (TypeError, ValueError):
            max_mbit = 0
        if max_mbit > 0:
            return max_mbit

    constraints = effective.get("design_constraints")
    if isinstance(constraints, dict):
        try:
            max_mbit = int(constraints.get("chain_client_rate_limit_mbit") or 0)
        except (TypeError, ValueError):
            max_mbit = 0
        if max_mbit > 0:
            return max_mbit

    return _HYSTERIA_CHAIN_CLIENT_RATE_LIMIT_MBIT


def _hysteria_export_mbps(effective: dict[str, Any], field: str) -> int:
    is_chain = _is_hysteria_chain_profile(effective)
    fallback = (
        _hysteria_chain_limit_mbit(effective)
        if is_chain
        else _HYSTERIA_DIRECT_DEFAULT_MBIT
    )
    try:
        value = int(effective.get(field) or fallback)
    except (TypeError, ValueError):
        value = fallback
    if is_chain:
        return max(1, min(value, fallback))
    return max(1, value)


def export_client_config(effective: dict[str, Any]) -> ExportResult:
    """
    Build a client-importable payload from Tracegate effective_config_json.

    - VLESS+REALITY: returns a `vless://...` URI
    - Hysteria2: returns a `hysteria2://...` URI (with insecure=1 by default)
    - MTProto: returns a Telegram proxy deep link
    """

    _reject_client_management_api(effective)

    proto = (effective.get("protocol") or "").strip().lower()
    if proto == "vless":
        transport = (effective.get("transport") or "").strip().lower()
        if not transport:
            # Backward-compatible heuristics (older payloads / tests may omit transport).
            if effective.get("reality"):
                transport = "reality"
            elif effective.get("grpc"):
                transport = "grpc_tls"
            elif effective.get("ws"):
                transport = "ws_tls"
        if transport in {
            "reality",
            "reality_raw",
            "reality-raw",
            "raw_reality",
            "raw-tcp-reality",
        }:
            return _export_vless_reality(effective)
        if transport in {"ws_tls", "ws+tls", "ws-tls"}:
            return _export_vless_ws_tls(effective)
        if transport in {"grpc_tls", "grpc+tls", "grpc-tls"}:
            return _export_vless_grpc_tls(effective)
        raise ClientConfigExportError(
            f"Unsupported VLESS transport for export: {transport!r}"
        )
    if proto == "hysteria2":
        return _export_hysteria2(effective)
    if proto == "mtproto":
        return _export_mtproto(effective)
    raise ClientConfigExportError(f"Unsupported protocol for export: {proto!r}")


def export_v2rayn(effective: dict[str, Any]) -> ExportResult:
    # Backward-compatible alias.
    return export_client_config(effective)


V2RayNExportError = ClientConfigExportError


def _export_vless_reality(effective: dict[str, Any]) -> ExportResult:
    server = effective.get("server")
    port = int(effective.get("port") or 443)
    uuid = effective.get("uuid")
    sni = effective.get("sni")
    reality = effective.get("reality") or {}
    pbk = reality.get("public_key")
    sid = reality.get("short_id")
    flow = str(effective.get("flow") or "xtls-rprx-vision").strip()
    encryption = _vless_encryption(effective)

    if not server or not uuid or not sni or not pbk or not sid:
        raise ClientConfigExportError("Missing fields for VLESS/REALITY export")

    # Xray share-link parameters.
    params: dict[str, str] = {
        "encryption": encryption,
        "security": "reality",
        "sni": sni,
        "fp": "chrome",
        "pbk": pbk,
        "sid": sid,
        # Many clients default to spiderX="/". Export explicitly to reduce interop issues.
        "spx": "/",
        "type": "tcp",
        "flow": flow,
    }

    name = client_profile_name(effective)
    uri = f"vless://{uuid}@{server}:{port}?{_encode_query(params, safe='/,')}#{_q(str(name))}"
    attachment_content, attachment_filename = _build_xray_client_attachment(
        effective,
        {
            "protocol": "vless",
            "tag": "proxy",
            "settings": {
                "vnext": [
                    {
                        "address": server,
                        "port": port,
                        "users": [{"id": uuid, "encryption": encryption, "flow": flow}],
                    }
                ]
            },
            "streamSettings": {
                "network": "raw",
                "security": "reality",
                "realitySettings": {
                    "serverName": sni,
                    "fingerprint": "chrome",
                    "password": pbk,
                    "shortId": sid,
                    "spiderX": "/",
                },
            },
        },
    )
    return ExportResult(
        kind="uri",
        title="VLESS REALITY link",
        content=uri,
        extra_messages=(_local_socks_extra_message(effective),),
        attachment_content=attachment_content,
        attachment_filename=attachment_filename,
        attachment_mime="application/json",
    )


def _export_vless_ws_tls(effective: dict[str, Any]) -> ExportResult:
    logical_server = str(effective.get("server") or "").strip()
    server = _client_connect_server(effective)
    port = int(effective.get("port") or 443)
    uuid = effective.get("uuid")
    sni = (effective.get("sni") or "").strip()
    ws = effective.get("ws") or {}
    ws_path = (ws.get("path") or "/ws").strip()
    ws_host = (ws.get("host") or "").strip()
    tls = effective.get("tls") or {}
    insecure = bool(tls.get("insecure", False))
    alpn = _normalize_alpn(tls.get("alpn"), default=("http/1.1",))
    encryption = _vless_encryption(effective)

    if not server or not uuid:
        raise ClientConfigExportError("Missing fields for VLESS+WS+TLS export")
    if not sni:
        # Some clients allow empty SNI (use server host), but make it explicit to avoid interop issues.
        sni = logical_server or str(server)
    if not ws_host:
        ws_host = sni

    params = {
        "encryption": encryption,
        "security": "tls",
        "type": "ws",
        "sni": sni,
        "host": ws_host,
        "path": ws_path,
    }
    if insecure:
        params["allowInsecure"] = "1"

    name = client_profile_name(effective)
    uri = f"vless://{uuid}@{server}:{port}?{_encode_query(params, safe='/,')}#{_q(str(name))}"
    tls_settings: dict[str, Any] = {
        "serverName": sni,
        "fingerprint": "chrome",
        "alpn": alpn,
    }

    attachment_content, attachment_filename = _build_xray_client_attachment(
        effective,
        {
            "protocol": "vless",
            "tag": "proxy",
            "settings": {
                "vnext": [
                    {
                        "address": server,
                        "port": port,
                        "users": [{"id": uuid, "encryption": encryption}],
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": tls_settings,
                "wsSettings": {
                    "path": ws_path,
                    "headers": {"Host": ws_host},
                },
            },
        },
    )
    return ExportResult(
        kind="uri",
        title="VLESS WS+TLS link",
        content=uri,
        extra_messages=(_local_socks_extra_message(effective),),
        attachment_content=attachment_content,
        attachment_filename=attachment_filename,
        attachment_mime="application/json",
    )


def _export_vless_grpc_tls(effective: dict[str, Any]) -> ExportResult:
    logical_server = str(effective.get("server") or "").strip()
    server = _client_connect_server(effective)
    port = int(effective.get("port") or 443)
    uuid = effective.get("uuid")
    sni = str(effective.get("sni") or logical_server or server or "").strip()
    grpc = effective.get("grpc") or {}
    service_name = (
        str(grpc.get("service_name") or "tracegate.v1.Edge").strip()
        or "tracegate.v1.Edge"
    )
    authority = str(grpc.get("authority") or sni or server or "").strip()
    tls = effective.get("tls") or {}
    insecure = bool(tls.get("insecure", False))
    alpn = _normalize_alpn(tls.get("alpn"), default=("h2",))
    encryption = _vless_encryption(effective)

    if not server or not uuid:
        raise ClientConfigExportError("Missing fields for VLESS+gRPC+TLS export")
    if not sni:
        sni = str(server)

    params = {
        "encryption": encryption,
        "security": "tls",
        "type": "grpc",
        "sni": sni,
        "serviceName": service_name,
        "mode": "gun",
    }
    if insecure:
        params["allowInsecure"] = "1"

    name = client_profile_name(effective)
    uri = f"vless://{uuid}@{server}:{port}?{_encode_query(params, safe='/,')}#{_q(str(name))}"
    tls_settings: dict[str, Any] = {
        "serverName": sni,
        "fingerprint": "chrome",
        "alpn": alpn,
    }

    grpc_settings: dict[str, Any] = {"serviceName": service_name}
    if authority:
        grpc_settings["authority"] = authority
    attachment_content, attachment_filename = _build_xray_client_attachment(
        effective,
        {
            "protocol": "vless",
            "tag": "proxy",
            "settings": {
                "vnext": [
                    {
                        "address": server,
                        "port": port,
                        "users": [{"id": uuid, "encryption": encryption}],
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "security": "tls",
                "tlsSettings": tls_settings,
                "grpcSettings": grpc_settings,
            },
        },
    )
    return ExportResult(
        kind="uri",
        title="VLESS gRPC+TLS link",
        content=uri,
        extra_messages=(_local_socks_extra_message(effective),),
        attachment_content=attachment_content,
        attachment_filename=attachment_filename,
        attachment_mime="application/json",
    )


def _export_hysteria2(effective: dict[str, Any]) -> ExportResult:
    server = effective.get("server")
    port = int(effective.get("port") or TRACEGATE_PUBLIC_UDP_PORT)
    auth = effective.get("auth") or {}
    auth_type = str(auth.get("type") or "").strip().lower()
    username = (auth.get("username") or auth.get("client_id") or "").strip()
    password = (auth.get("password") or "").strip()
    token = (auth.get("token") or auth.get("value") or "").strip()
    sni = str(effective.get("sni") or server or "").strip()
    tls = effective.get("tls") or {}
    insecure = bool(tls.get("insecure", False)) or _is_ip_literal(sni)
    alpn = tls.get("alpn") or ["h3"]
    if isinstance(alpn, str):
        alpn_values = [alpn]
    else:
        alpn_values = [str(item).strip() for item in alpn if str(item).strip()]
    if not alpn_values:
        alpn_values = ["h3"]
    obfs = effective.get("obfs") or {}
    if not isinstance(obfs, dict):
        obfs = {}
    obfs_type = str(obfs.get("type") or "").strip().lower()
    obfs_password = str(obfs.get("password") or obfs.get("obfs_password") or "").strip()

    if not server:
        raise ClientConfigExportError("Missing fields for Hysteria2 export")
    port_hopping = _hysteria_port_hopping(effective)
    if obfs_type not in {"gecko", "salamander"} or not obfs_password:
        raise ClientConfigExportError(
            "Hysteria2 export requires Gecko or Salamander obfs with a password"
        )

    # Keep the URI aligned with the official Hysteria 2 scheme:
    # token auth is a single opaque auth component, percent-encoded as needed.
    params = {
        "obfs": obfs_type,
        "obfs-password": obfs_password,
    }
    if insecure:
        params["insecure"] = "1"
    if sni:
        params["sni"] = sni
    if alpn_values and alpn_values != ["h3"]:
        params["alpn"] = ",".join(alpn_values)

    name = client_profile_name(effective)
    if auth_type == "userpass":
        if not username or not password:
            raise ClientConfigExportError(
                "Missing userpass fields for Hysteria2 export"
            )
        share_auth = f"{username}:{password}"
        authority = _q(share_auth)
    else:
        if not token:
            raise ClientConfigExportError("Missing token field for Hysteria2 export")
        share_auth = token
        authority = _q(token)

    uri_ports = str(port)
    if port_hopping is not None:
        # Official multi-port URI syntax; the hop interval is client-side only.
        uri_ports = f"{port},{port_hopping['lower']}-{port_hopping['upper']}"
    uri = f"hysteria2://{authority}@{server}:{uri_ports}/?{_encode_query(params)}#{_q(str(name))}"
    singbox_tls: dict[str, Any] = {
        "enabled": True,
        "server_name": sni or str(server),
        "alpn": alpn_values,
    }
    if insecure:
        singbox_tls["insecure"] = True
    if obfs_type == "gecko":
        attachment_content, attachment_filename = _build_hysteria_client_attachment(
            effective,
            server=str(server),
            port=port,
            auth=share_auth,
            sni=sni,
            insecure=insecure,
            obfs_password=obfs_password,
            min_packet_size=int(obfs.get("min_packet_size") or 512),
            max_packet_size=int(obfs.get("max_packet_size") or 1200),
            port_hopping=port_hopping,
        )
        attachment_mime = "application/yaml"
    else:
        singbox_outbound: dict[str, Any] = {
            "type": "hysteria2",
            "tag": "proxy",
            "server": server,
            "server_port": port,
            "up_mbps": _hysteria_export_mbps(effective, "up_mbps"),
            "down_mbps": _hysteria_export_mbps(effective, "down_mbps"),
            "password": share_auth,
            "obfs": {"type": obfs_type, "password": obfs_password},
            "tls": singbox_tls,
        }
        if port_hopping is not None:
            # sing-box multi-port form. Only the fixed hop_interval is emitted:
            # older sing-box builds in mainstream clients reject unknown fields
            # such as hop_interval_max.
            singbox_outbound.pop("server_port")
            singbox_outbound = {
                **{key: value for key, value in singbox_outbound.items() if key in {"type", "tag", "server"}},
                "server_ports": [f"{port_hopping['lower']}:{port_hopping['upper']}"],
                "hop_interval": f"{port_hopping['min_interval_s']}s",
                **{key: value for key, value in singbox_outbound.items() if key not in {"type", "tag", "server"}},
            }
        attachment_content, attachment_filename = _build_singbox_client_attachment(
            effective,
            singbox_outbound,
        )
        attachment_mime = "application/json"
    return ExportResult(
        kind="uri",
        title="Hysteria2 link",
        content=uri,
        extra_messages=(
            _local_socks_extra_message(effective),
            (
                "Client compatibility",
                (
                    "Gecko requires the official Hysteria client with Gecko support; sing-box does not support Gecko."
                    if obfs_type == "gecko"
                    else "Salamander is the broadly compatible Hysteria2 obfs mode."
                ),
            ),
        ),
        attachment_content=attachment_content,
        attachment_filename=attachment_filename,
        attachment_mime=attachment_mime,
    )


def _export_mtproto(effective: dict[str, Any]) -> ExportResult:
    server = str(effective.get("server") or "").strip()
    port = int(effective.get("port") or 443)
    profile = (
        str(effective.get("profile") or MTPROTO_FAKE_TLS_PROFILE_NAME).strip()
        or MTPROTO_FAKE_TLS_PROFILE_NAME
    )
    transport = (
        str(effective.get("transport") or effective.get("mtproto_transport") or "")
        .strip()
        .lower()
        or None
    )
    domain = str(
        effective.get("domain") or effective.get("mtproto_domain") or server
    ).strip()
    secret = str(
        effective.get("secret")
        or effective.get("secret_hex")
        or effective.get("mtproto_secret")
        or effective.get("mtproto_secret_hex")
        or ""
    ).strip()

    if not server or not secret:
        raise ClientConfigExportError("Missing fields for MTProto export")

    try:
        links = build_mtproto_share_links(
            server=server,
            port=port,
            secret_hex=secret,
            transport=transport,
            domain=domain,
        )
    except MTProtoConfigError as exc:
        raise ClientConfigExportError(str(exc)) from exc

    return ExportResult(
        kind="uri", title=f"Telegram Proxy link · {profile}", content=links.https_url
    )
