from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any
from urllib.parse import quote, urlencode, urlparse

from tracegate.constants import TRACEGATE_PUBLIC_UDP_PORT
from tracegate.services.mtproto import MTPROTO_FAKE_TLS_PROFILE_NAME, MTProtoConfigError, build_mtproto_share_links

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


def _b64url_no_padding(raw: str) -> str:
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")


def _encode_query(params: dict[str, Any], *, safe: str = "") -> str:
    # `path=/ws` is more interoperable than `%2Fws` for some clients.
    return urlencode(params, safe=safe)


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
    normalized = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(value or "").strip())
    compact = "-".join(part for part in normalized.split("-") if part)
    return compact or "tracegate"


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


def _client_connect_server(effective: dict[str, Any]) -> str:
    return str(effective.get("connect_host") or effective.get("server") or "").strip()


def _default_local_socks_port(effective: dict[str, Any]) -> int:
    seed = "|".join(
        str(effective.get(key) or "")
        for key in ("protocol", "transport", "profile", "server", "uuid", "device_id", "sni")
    ).encode("utf-8")
    digest = hashlib.sha256(seed).digest()
    return _LOCAL_SOCKS_PORT_BASE + (int.from_bytes(digest[:4], "big") % _LOCAL_SOCKS_PORT_SPAN)


def _parse_local_socks_listen(effective: dict[str, Any]) -> tuple[str, int]:
    local_socks = effective.get("local_socks") or {}
    listen = str(local_socks.get("listen") or f"127.0.0.1:{_default_local_socks_port(effective)}").strip()
    if listen.startswith("["):
        host_end = listen.find("]")
        if host_end < 0 or host_end + 1 >= len(listen) or listen[host_end + 1] != ":":
            raise ClientConfigExportError(f"Invalid local SOCKS5 listen endpoint: {listen}")
        host = listen[1:host_end]
        port_raw = listen[host_end + 2 :]
    else:
        host, sep, port_raw = listen.rpartition(":")
        if not sep:
            host = "127.0.0.1"
            port_raw = listen
    host = host.strip() or "127.0.0.1"
    if not _is_loopback_host(host):
        raise ClientConfigExportError(f"Local SOCKS5 listen must stay on loopback, got {listen}")
    try:
        port = int(str(port_raw).strip())
    except (TypeError, ValueError):
        raise ClientConfigExportError(f"Invalid local SOCKS5 listen port: {listen}") from None
    if port < 1 or port > 65535:
        raise ClientConfigExportError(f"Invalid local SOCKS5 listen port: {listen}")
    return "127.0.0.1", port


def _parse_loopback_listen_endpoint(raw_value: object, *, label: str, default: str) -> tuple[str, int]:
    listen = str(raw_value or default).strip()
    if listen.startswith("["):
        host_end = listen.find("]")
        if host_end < 0 or host_end + 1 >= len(listen) or listen[host_end + 1] != ":":
            raise ClientConfigExportError(f"Invalid {label} endpoint: {listen}")
        host = listen[1:host_end]
        port_raw = listen[host_end + 2 :]
    else:
        host, sep, port_raw = listen.rpartition(":")
        if not sep:
            host = "127.0.0.1"
            port_raw = listen
    host = host.strip() or "127.0.0.1"
    if not _is_loopback_host(host):
        raise ClientConfigExportError(f"{label} must stay on loopback, got {listen}")
    try:
        port = int(str(port_raw).strip())
    except (TypeError, ValueError):
        raise ClientConfigExportError(f"Invalid {label} port: {listen}") from None
    if port < 1 or port > 65535:
        raise ClientConfigExportError(f"Invalid {label} port: {listen}")
    return "127.0.0.1", port


def _validated_wstunnel_url(wstunnel: dict[str, Any]) -> str:
    url = str(wstunnel.get("url") or "").strip()
    parsed = urlparse(url)
    try:
        port = int(parsed.port or 0)
    except ValueError:
        port = 0
    path = str(parsed.path or "")
    if (
        parsed.scheme != "wss"
        or not parsed.hostname
        or port != 443
        or not path.startswith("/")
        or "://" in path
        or any(ch.isspace() for ch in path)
        or bool(parsed.query)
        or bool(parsed.fragment)
    ):
        raise ClientConfigExportError("WSTunnel target must be wss://host:443/path")
    return url


def _validated_wireguard_mtu(wireguard: dict[str, Any]) -> int:
    try:
        mtu = int(wireguard.get("mtu") or 1280)
    except (TypeError, ValueError) as exc:
        raise ClientConfigExportError("WireGuard MTU must be an integer") from exc
    if mtu < 1200 or mtu > 1420:
        raise ClientConfigExportError("WireGuard MTU must stay within 1200..1420")
    return mtu


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
        raise ClientConfigExportError("Local SOCKS5 auth requires username and password")

    seed = "|".join(
        str(effective.get(key) or "")
        for key in ("protocol", "transport", "profile", "server", "uuid", "device_id", "sni")
    ).encode("utf-8")
    digest = hashlib.sha256(seed).digest()
    username = f"tg_{digest[:5].hex()}"
    password = base64.urlsafe_b64encode(hashlib.sha256(digest + b":attachment-local-socks").digest()).decode("ascii").rstrip("=")
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
        services = {str(item).strip().lower() for item in services_raw if str(item).strip()} if isinstance(services_raw, list) else set()
        handler_enabled = bool(block.get("handler_service", False) or block.get("handlerService", False))
        if handler_enabled or "handlerservice" in services:
            raise ClientConfigExportError("Client-side Xray HandlerService is forbidden")
        if bool(block.get("reflection_service", False) or block.get("reflectionService", False)) or "reflectionservice" in services:
            raise ClientConfigExportError("Client-side Xray ReflectionService is forbidden")
        if bool(block.get("enabled", False)):
            raise ClientConfigExportError("Client-side Xray API is forbidden for exported profiles")


def _build_xray_client_attachment(effective: dict[str, Any], outbound: dict[str, Any]) -> tuple[bytes, str]:
    profile_name = str(effective.get("profile") or "tracegate-client").strip() or "tracegate-client"
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
    filename = f"{_safe_filename_fragment(profile_name)}.xray.json"
    return json.dumps(config, ensure_ascii=True, indent=2).encode("utf-8"), filename


def _build_singbox_client_attachment(
    effective: dict[str, Any],
    outbound: dict[str, Any] | list[dict[str, Any]],
    *,
    inbound_type: str = "mixed",
) -> tuple[bytes, str]:
    profile_name = str(effective.get("profile") or "tracegate-client").strip() or "tracegate-client"
    local_host, local_port = _local_socks_endpoint(effective)
    socks_username, socks_password = _local_socks_auth(effective)
    outbounds = outbound if isinstance(outbound, list) else [outbound]
    config = {
        "log": {"level": "warn"},
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
        "route": {
            "auto_detect_interface": True,
            "final": "proxy",
        },
    }
    filename = f"{_safe_filename_fragment(profile_name)}.singbox.json"
    return json.dumps(config, ensure_ascii=True, indent=2).encode("utf-8"), filename


def _build_wgws_client_attachment(
    effective: dict[str, Any],
    *,
    wstunnel_url: str,
    local_udp_host: str,
    local_udp_port: int,
    local_addresses: list[str],
    private_key: str,
    peer_public_key: str,
    preshared_key: str,
    mtu: int,
) -> tuple[bytes, str]:
    profile_name = str(effective.get("profile") or "v0-wgws-wireguard").strip() or "v0-wgws-wireguard"
    parsed = urlparse(wstunnel_url)
    ws_server = str(parsed.hostname or "").strip()
    ws_port = int(parsed.port or 443)
    ws_path = parsed.path or "/wgws"
    wstunnel = effective.get("wstunnel") if isinstance(effective.get("wstunnel"), dict) else {}
    wireguard = effective.get("wireguard") if isinstance(effective.get("wireguard"), dict) else {}
    allowed_ips = wireguard.get("allowed_ips")
    if isinstance(allowed_ips, str):
        allowed_ip_values = [allowed_ips] if allowed_ips else []
    elif isinstance(allowed_ips, (list, tuple)):
        allowed_ip_values = [str(item).strip() for item in allowed_ips if str(item).strip()]
    else:
        allowed_ip_values = []
    if not allowed_ip_values:
        allowed_ip_values = ["0.0.0.0/0", "::/0"]

    local_socks_host, local_socks_port = _local_socks_endpoint(effective)
    socks_username, socks_password = _local_socks_auth(effective)
    persistent_keepalive = int(wireguard.get("persistent_keepalive") or 25)
    endpoint_peer: dict[str, Any] = {
        "address": local_udp_host,
        "port": local_udp_port,
        "public_key": peer_public_key,
        "allowed_ips": allowed_ip_values,
        "persistent_keepalive_interval": persistent_keepalive,
    }
    if preshared_key:
        endpoint_peer["pre_shared_key"] = preshared_key
    endpoint: dict[str, Any] = {
        "type": "wireguard",
        "tag": "proxy",
        "system": False,
        "address": local_addresses,
        "private_key": private_key,
        "peers": [endpoint_peer],
        "mtu": mtu,
        "workers": 4,
    }
    singbox = {
        "log": {"level": "warn"},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "local-in",
                "listen": local_socks_host,
                "listen_port": local_socks_port,
                "users": [{"username": socks_username, "password": socks_password}],
            }
        ],
        "endpoints": [endpoint],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"auto_detect_interface": True, "final": "proxy"},
    }

    host_header = str(wstunnel.get("host") or ws_server).strip()
    headers = {str(key): str(value) for key, value in (wstunnel.get("headers") or {}).items()} if isinstance(wstunnel.get("headers"), dict) else {}
    if host_header and host_header != ws_server:
        headers.setdefault("Host", host_header)
    local_udp_listen = f"{local_udp_host}:{local_udp_port}"
    websocket = {
        "server": ws_server,
        "server_port": ws_port,
        "tls": parsed.scheme == "wss",
        "sni": str(wstunnel.get("tls_server_name") or effective.get("sni") or ws_server).strip(),
        "host": host_header or ws_server,
        "path": ws_path,
        "headers": headers,
    }
    attachment = {
        "type": "wgws",
        "schema": "tracegate.wgws-client.v1",
        "name": profile_name,
        "wireguard": {
            "local_address": local_addresses,
            "private_key": private_key,
            "peer_public_key": peer_public_key,
            "allowed_ips": allowed_ip_values,
            "dns": wireguard.get("dns") or "1.1.1.1",
            "mtu": mtu,
            "persistent_keepalive": persistent_keepalive,
        },
        "websocket": websocket,
        "wstunnel": {
            "mode": "wireguard-over-websocket",
            "url": wstunnel_url,
            "local_udp_listen": local_udp_listen,
            "remote_udp_endpoint": f"127.0.0.1:{local_udp_port}",
            "http_upgrade_path_prefix": ws_path.lstrip("/"),
            "client_command": (
                f"wstunnel client --http-upgrade-path-prefix {ws_path.lstrip('/')} "
                f"-L udp://{local_udp_listen}:127.0.0.1:{local_udp_port} "
                f"wss://{ws_server}:{ws_port}"
            ),
        },
        "singbox": singbox,
        "local_socks": {
            "listen": f"{local_socks_host}:{local_socks_port}",
            "auth": {"username": socks_username, "password": socks_password},
        },
    }
    if preshared_key:
        attachment["wireguard"]["pre_shared_key"] = preshared_key
    filename = f"{_safe_filename_fragment(profile_name)}.wgws.json"
    return json.dumps(attachment, ensure_ascii=True, indent=2).encode("utf-8"), filename


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
    fallback = _hysteria_chain_limit_mbit(effective) if is_chain else _HYSTERIA_DIRECT_DEFAULT_MBIT
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
    - NaiveProxy: returns a Shadowrocket-friendly URI plus official `naive` JSON attachment
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
        if transport in {"reality"}:
            return _export_vless_reality(effective)
        if transport in {"ws_tls", "ws+tls", "ws-tls"}:
            return _export_vless_ws_tls(effective)
        if transport in {"grpc_tls", "grpc+tls", "grpc-tls"}:
            return _export_vless_grpc_tls(effective)
        raise ClientConfigExportError(f"Unsupported VLESS transport for export: {transport!r}")
    if proto == "hysteria2":
        return _export_hysteria2(effective)
    if proto == "naiveproxy":
        return _export_naiveproxy(effective)
    if proto in {"shadowsocks2022", "shadowsocks"}:
        return _export_shadowsocks2022_shadowtls(effective)
    if proto == "wireguard":
        return _export_wireguard_wstunnel(effective)
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
    xhttp = effective.get("xhttp") or {}
    xhttp_mode = str((xhttp.get("mode") or "")).strip()
    xhttp_path = str((xhttp.get("path") or "")).strip()

    if not server or not uuid or not sni or not pbk or not sid:
        raise ClientConfigExportError("Missing fields for VLESS/REALITY export")

    # Xray share-link parameters.
    params: dict[str, str] = {
        "encryption": "none",
        "security": "reality",
        "sni": sni,
        "fp": "chrome",
        "pbk": pbk,
        "sid": sid,
        # Many clients default to spiderX="/". Export explicitly to reduce interop issues.
        "spx": "/",
        # Tracegate VLESS/REALITY is xhttp-only.
        "type": "xhttp",
        "mode": xhttp_mode or "auto",
    }
    params["path"] = xhttp_path or "/api/v1/update"

    name = effective.get("profile") or "tracegate-vless"
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
                        "users": [{"id": uuid, "encryption": "none"}],
                    }
                ]
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "reality",
                "realitySettings": {
                    "serverName": sni,
                    "fingerprint": "chrome",
                    "publicKey": pbk,
                    "shortId": sid,
                    "spiderX": "/",
                },
                "xhttpSettings": {
                    "mode": xhttp_mode or "auto",
                    "path": xhttp_path or "/api/v1/update",
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

    if not server or not uuid:
        raise ClientConfigExportError("Missing fields for VLESS+WS+TLS export")
    if not sni:
        # Some clients allow empty SNI (use server host), but make it explicit to avoid interop issues.
        sni = logical_server or str(server)
    if not ws_host:
        ws_host = sni

    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "sni": sni,
        "host": ws_host,
        "path": ws_path,
    }
    if insecure:
        params["allowInsecure"] = "1"

    name = effective.get("profile") or "tracegate-vless-ws"
    uri = f"vless://{uuid}@{server}:{port}?{_encode_query(params, safe='/,')}#{_q(str(name))}"
    tls_settings: dict[str, Any] = {
        "serverName": sni,
        "fingerprint": "chrome",
        "alpn": alpn,
    }
    if insecure:
        tls_settings["allowInsecure"] = True

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
                        "users": [{"id": uuid, "encryption": "none"}],
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
    service_name = str(grpc.get("service_name") or "tracegate.v1.Edge").strip() or "tracegate.v1.Edge"
    authority = str(grpc.get("authority") or sni or server or "").strip()
    tls = effective.get("tls") or {}
    insecure = bool(tls.get("insecure", False))
    alpn = _normalize_alpn(tls.get("alpn"), default=("h2",))

    if not server or not uuid:
        raise ClientConfigExportError("Missing fields for VLESS+gRPC+TLS export")
    if not sni:
        sni = str(server)

    params = {
        "encryption": "none",
        "security": "tls",
        "type": "grpc",
        "sni": sni,
        "serviceName": service_name,
        "mode": "gun",
    }
    if insecure:
        params["allowInsecure"] = "1"

    name = effective.get("profile") or "v0-grpc-vless"
    uri = f"vless://{uuid}@{server}:{port}?{_encode_query(params, safe='/,')}#{_q(str(name))}"
    tls_settings: dict[str, Any] = {
        "serverName": sni,
        "fingerprint": "chrome",
        "alpn": alpn,
    }
    if insecure:
        tls_settings["allowInsecure"] = True

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
                        "users": [{"id": uuid, "encryption": "none"}],
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
    if obfs_type != "salamander" or not obfs_password:
        raise ClientConfigExportError("Hysteria2 export requires Salamander obfs with a password")

    # Keep the URI aligned with the official Hysteria 2 scheme:
    # token auth is a single opaque auth component, percent-encoded as needed.
    params = {
        "obfs": "salamander",
        "obfs-password": obfs_password,
    }
    if insecure:
        params["insecure"] = "1"
    if sni:
        params["sni"] = sni
    if alpn_values and alpn_values != ["h3"]:
        params["alpn"] = ",".join(alpn_values)

    name = effective.get("profile") or "tracegate-hysteria2"
    alternate_uri: str | None = None
    alternate_title: str | None = None
    if auth_type == "userpass":
        if not username or not password:
            raise ClientConfigExportError("Missing userpass fields for Hysteria2 export")
        share_auth = f"{username}:{password}"
        authority = f"{_q(username)}:{_q(password)}"
        fallback_authority = _q(password)
        fallback_name = f"{name} Shadowrocket"
        alternate_uri = f"hy2://{fallback_authority}@{server}:{port}/?{_encode_query(params)}#{_q(str(fallback_name))}"
        alternate_title = "Hysteria2 Shadowrocket fallback URI"
    else:
        if not token:
            raise ClientConfigExportError("Missing token field for Hysteria2 export")
        share_auth = token
        authority = _q(token)

    uri = f"hysteria2://{authority}@{server}:{port}/?{_encode_query(params)}#{_q(str(name))}"
    singbox_tls: dict[str, Any] = {
        "enabled": True,
        "server_name": sni or str(server),
        "alpn": alpn_values,
    }
    if insecure:
        singbox_tls["insecure"] = True
    attachment_content, attachment_filename = _build_singbox_client_attachment(
        effective,
        {
            "type": "hysteria2",
            "tag": "proxy",
            "server": server,
            "server_port": port,
            "up_mbps": _hysteria_export_mbps(effective, "up_mbps"),
            "down_mbps": _hysteria_export_mbps(effective, "down_mbps"),
            "password": share_auth,
            "obfs": {
                "type": "salamander",
                "password": obfs_password,
            },
            "tls": singbox_tls,
        },
    )
    return ExportResult(
        kind="uri",
        title="Hysteria2 link",
        content=uri,
        alternate_title=alternate_title,
        alternate_content=alternate_uri,
        extra_messages=(_local_socks_extra_message(effective),),
        attachment_content=attachment_content,
        attachment_filename=attachment_filename,
        attachment_mime="application/json",
    )


def _export_naiveproxy(effective: dict[str, Any]) -> ExportResult:
    server = str(effective.get("server") or "").strip()
    port = int(effective.get("port") or 443)
    profile = str(effective.get("profile") or "v4-direct-naiveproxy").strip()
    auth = effective.get("auth") or {}
    username = str(auth.get("username") or "").strip()
    password = str(auth.get("password") or "").strip()
    if not server or not username or not password:
        raise ClientConfigExportError("Missing fields for NaiveProxy export")

    local_host, local_port = _local_socks_endpoint(effective)
    local_user, local_pass = _local_socks_auth(effective)
    listen = f"socks://{_q(local_user)}:{_q(local_pass)}@{local_host}:{local_port}"
    authority = f"{_q(username)}:{_q(password)}@{server}"
    if port != 443:
        authority = f"{authority}:{port}"
    h2_proxy = f"https://{authority}"
    h3_proxy = f"quic://{authority}"
    label = profile or "Tracegate NaiveProxy"
    shadowrocket_uri = f"naive+{h2_proxy}?padding=true#{_q(label)}"
    h3_uri = f"naive+{h3_proxy}?padding=true#{_q(label)}"

    config = {
        "listen": listen,
        "proxy": h3_proxy,
        "log": "",
    }
    attachment_content = json.dumps(config, ensure_ascii=True, indent=2).encode("utf-8")
    filename = f"{_safe_filename_fragment(profile)}.naive.json"
    return ExportResult(
        kind="uri",
        title="NaiveProxy link · Shadowrocket",
        content=shadowrocket_uri,
        alternate_title="NaiveProxy HTTP/3 URI",
        alternate_content=h3_uri,
        extra_messages=(
            (
                "Shadowrocket import",
                "Use the QR code below with Shadowrocket's built-in scanner, or import the single-line "
                "`naive+https://...` URI from the previous message. The attached `.naive.json` file is "
                "for native NaiveProxy clients, not for Shadowrocket.",
            ),
        ),
        attachment_content=attachment_content,
        attachment_filename=filename,
        attachment_mime="application/json",
    )


def _export_mtproto(effective: dict[str, Any]) -> ExportResult:
    server = str(effective.get("server") or "").strip()
    port = int(effective.get("port") or 443)
    profile = str(effective.get("profile") or MTPROTO_FAKE_TLS_PROFILE_NAME).strip() or MTPROTO_FAKE_TLS_PROFILE_NAME
    transport = str(effective.get("transport") or effective.get("mtproto_transport") or "").strip().lower() or None
    domain = str(effective.get("domain") or effective.get("mtproto_domain") or server).strip()
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

    return ExportResult(kind="uri", title=f"Telegram Proxy link · {profile}", content=links.https_url)


def _export_shadowsocks2022_shadowtls(effective: dict[str, Any]) -> ExportResult:
    server = str(effective.get("server") or "").strip()
    port = int(effective.get("port") or 443)
    method = str(effective.get("method") or "2022-blake3-aes-128-gcm").strip()
    password = str(effective.get("password") or "").strip()
    shadowtls = effective.get("shadowtls") or {}
    shadowtls_password = str(shadowtls.get("password") or "").strip()
    shadowtls_server_name = str(shadowtls.get("server_name") or effective.get("sni") or server).strip()
    profile = str(effective.get("profile") or "v3-direct-shadowtls-shadowsocks").strip()

    if not server or not password or not shadowtls_password:
        raise ClientConfigExportError("Missing fields for Shadowsocks-2022 + ShadowTLS export")

    userinfo = _b64url_no_padding(f"{method}:{password}")
    plugin_opts = _encode_query(
        {
            "plugin": ";".join(
                [
                    "shadow-tls",
                    f"host={shadowtls_server_name}",
                    f"password={shadowtls_password}",
                    "version=3",
                ]
            )
        }
    )
    uri = f"ss://{userinfo}@{server}:{port}?{plugin_opts}#{_q(profile)}"
    attachment_content, attachment_filename = _build_singbox_client_attachment(
        effective,
        [
            {
                "type": "shadowsocks",
                "tag": "proxy",
                "server": server,
                "server_port": port,
                "method": method,
                "password": password,
                "detour": "shadowtls-out",
            },
            {
                "type": "shadowtls",
                "tag": "shadowtls-out",
                "server": server,
                "server_port": port,
                "version": 3,
                "password": shadowtls_password,
                "tls": {
                    "enabled": True,
                    "server_name": shadowtls_server_name,
                },
            },
        ],
    )

    return ExportResult(
        kind="uri",
        title="Shadowsocks-2022 + ShadowTLS",
        content=uri,
        attachment_content=attachment_content,
        attachment_filename=attachment_filename,
        attachment_mime="application/json",
    )


def _export_wireguard_wstunnel(effective: dict[str, Any]) -> ExportResult:
    server = str(effective.get("server") or "").strip()
    wstunnel = effective.get("wstunnel") or {}
    wireguard = effective.get("wireguard") or {}
    profile = str(effective.get("profile") or "v0-wgws-wireguard").strip()
    private_key = str(wireguard.get("private_key") or "").strip()
    peer_public_key = str(wireguard.get("server_public_key") or "").strip()
    address = wireguard.get("address") or ""
    if isinstance(address, str):
        local_addresses = [address] if address else []
    else:
        local_addresses = [str(item).strip() for item in address if str(item).strip()]

    if not server or not private_key or not peer_public_key or not local_addresses:
        raise ClientConfigExportError("Missing fields for WireGuard over WSTunnel export")

    wstunnel_url = _validated_wstunnel_url(wstunnel)
    local_udp_host, local_udp_port = _parse_loopback_listen_endpoint(
        wstunnel.get("local_udp_listen"),
        label="WSTunnel local UDP listen",
        default="127.0.0.1:51820",
    )

    mtu = _validated_wireguard_mtu(wireguard)
    preshared_key = str(wireguard.get("preshared_key") or "").strip()
    attachment_content, attachment_filename = _build_wgws_client_attachment(
        effective,
        wstunnel_url=wstunnel_url,
        local_udp_host=local_udp_host,
        local_udp_port=local_udp_port,
        local_addresses=local_addresses,
        private_key=private_key,
        peer_public_key=peer_public_key,
        preshared_key=preshared_key,
        mtu=mtu,
    )
    extra_messages = (_local_socks_extra_message(effective),)
    extra_messages = (("WGWS transport", wstunnel_url), ("WG local UDP", f"{local_udp_host}:{local_udp_port}"), *extra_messages)
    return ExportResult(
        kind="attachment",
        title="WGWS config",
        content=(
            f"Use the attached WGWS config for {profile}. It includes WireGuard keys, "
            "the WebSocket transport, and the inner sing-box endpoint config."
        ),
        extra_messages=extra_messages,
        attachment_content=attachment_content,
        attachment_filename=attachment_filename,
        attachment_mime="application/json",
    )
