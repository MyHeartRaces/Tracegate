from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any
from urllib.parse import quote, urlencode, urlparse

from tracegate.services.mtproto import MTPROTO_FAKE_TLS_PROFILE_NAME, MTProtoConfigError, build_mtproto_share_links

_LOCAL_SOCKS_PORT_BASE = 20000
_LOCAL_SOCKS_PORT_SPAN = 40000


class V2RayNExportError(ValueError):
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
            raise V2RayNExportError(f"Invalid local SOCKS5 listen endpoint: {listen}")
        host = listen[1:host_end]
        port_raw = listen[host_end + 2 :]
    else:
        host, sep, port_raw = listen.rpartition(":")
        if not sep:
            host = "127.0.0.1"
            port_raw = listen
    host = host.strip() or "127.0.0.1"
    if not _is_loopback_host(host):
        raise V2RayNExportError(f"Local SOCKS5 listen must stay on loopback, got {listen}")
    try:
        port = int(str(port_raw).strip())
    except (TypeError, ValueError):
        raise V2RayNExportError(f"Invalid local SOCKS5 listen port: {listen}") from None
    if port < 1 or port > 65535:
        raise V2RayNExportError(f"Invalid local SOCKS5 listen port: {listen}")
    return "127.0.0.1", port


def _parse_loopback_listen_endpoint(raw_value: object, *, label: str, default: str) -> tuple[str, int]:
    listen = str(raw_value or default).strip()
    if listen.startswith("["):
        host_end = listen.find("]")
        if host_end < 0 or host_end + 1 >= len(listen) or listen[host_end + 1] != ":":
            raise V2RayNExportError(f"Invalid {label} endpoint: {listen}")
        host = listen[1:host_end]
        port_raw = listen[host_end + 2 :]
    else:
        host, sep, port_raw = listen.rpartition(":")
        if not sep:
            host = "127.0.0.1"
            port_raw = listen
    host = host.strip() or "127.0.0.1"
    if not _is_loopback_host(host):
        raise V2RayNExportError(f"{label} must stay on loopback, got {listen}")
    try:
        port = int(str(port_raw).strip())
    except (TypeError, ValueError):
        raise V2RayNExportError(f"Invalid {label} port: {listen}") from None
    if port < 1 or port > 65535:
        raise V2RayNExportError(f"Invalid {label} port: {listen}")
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
        raise V2RayNExportError("WSTunnel target must be wss://host:443/path")
    return url


def _validated_wireguard_mtu(wireguard: dict[str, Any]) -> int:
    try:
        mtu = int(wireguard.get("mtu") or 1280)
    except (TypeError, ValueError) as exc:
        raise V2RayNExportError("WireGuard MTU must be an integer") from exc
    if mtu < 1200 or mtu > 1420:
        raise V2RayNExportError("WireGuard MTU must stay within 1200..1420")
    return mtu


def _local_socks_endpoint(effective: dict[str, Any]) -> tuple[str, int]:
    return _parse_local_socks_listen(effective)


def _local_socks_auth(effective: dict[str, Any]) -> tuple[str, str]:
    raw_local_socks = effective.get("local_socks")
    local_socks = raw_local_socks if isinstance(raw_local_socks, dict) else {}
    raw_auth = local_socks.get("auth")
    auth = raw_auth if isinstance(raw_auth, dict) else {}
    if local_socks and not auth:
        raise V2RayNExportError("Local SOCKS5 auth is required")
    if auth.get("required") is False:
        raise V2RayNExportError("Local SOCKS5 auth is explicitly disabled")
    mode = str(auth.get("mode") or "").strip()
    if mode and mode not in {"username_password", "generated"}:
        raise V2RayNExportError(f"Unsupported local SOCKS5 auth mode: {mode}")
    username = str(auth.get("username") or "").strip()
    password = str(auth.get("password") or "").strip()
    if username and password:
        return username, password
    if auth:
        raise V2RayNExportError("Local SOCKS5 auth requires username and password")

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
            raise V2RayNExportError("Client-side Xray HandlerService is forbidden")
        if bool(block.get("reflection_service", False) or block.get("reflectionService", False)) or "reflectionservice" in services:
            raise V2RayNExportError("Client-side Xray ReflectionService is forbidden")
        if bool(block.get("enabled", False)):
            raise V2RayNExportError("Client-side Xray API is forbidden for exported profiles")


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
    outbound: dict[str, Any],
    *,
    inbound_type: str = "mixed",
) -> tuple[bytes, str]:
    profile_name = str(effective.get("profile") or "tracegate-client").strip() or "tracegate-client"
    local_host, local_port = _local_socks_endpoint(effective)
    socks_username, socks_password = _local_socks_auth(effective)
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
        "outbounds": [outbound],
        "route": {
            "auto_detect_interface": True,
            "final": "proxy",
        },
    }
    filename = f"{_safe_filename_fragment(profile_name)}.singbox.json"
    return json.dumps(config, ensure_ascii=True, indent=2).encode("utf-8"), filename


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
        if transport in {"reality"}:
            return _export_vless_reality(effective)
        if transport in {"ws_tls", "ws+tls", "ws-tls"}:
            return _export_vless_ws_tls(effective)
        if transport in {"grpc_tls", "grpc+tls", "grpc-tls"}:
            return _export_vless_grpc_tls(effective)
        raise V2RayNExportError(f"Unsupported VLESS transport for export: {transport!r}")
    if proto == "hysteria2":
        return _export_hysteria2(effective)
    if proto in {"shadowsocks2022", "shadowsocks"}:
        return _export_shadowsocks2022_shadowtls(effective)
    if proto == "wireguard":
        return _export_wireguard_wstunnel(effective)
    if proto == "mtproto":
        return _export_mtproto(effective)
    raise V2RayNExportError(f"Unsupported protocol for export: {proto!r}")


def export_v2rayn(effective: dict[str, Any]) -> ExportResult:
    # Backward-compatible alias.
    return export_client_config(effective)


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
        raise V2RayNExportError("Missing fields for VLESS/REALITY export")

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
        "mode": xhttp_mode or "packet-up",
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
                    "mode": xhttp_mode or "packet-up",
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
    server = effective.get("server")
    port = int(effective.get("port") or 443)
    uuid = effective.get("uuid")
    sni = (effective.get("sni") or "").strip()
    ws = effective.get("ws") or {}
    ws_path = (ws.get("path") or "/ws").strip()
    ws_host = (ws.get("host") or "").strip()
    tls = effective.get("tls") or {}
    insecure = bool(tls.get("insecure", False))

    if not server or not uuid:
        raise V2RayNExportError("Missing fields for VLESS+WS+TLS export")
    if not sni:
        # Some clients allow empty SNI (use server host), but make it explicit to avoid interop issues.
        sni = str(server)
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
    server = effective.get("server")
    port = int(effective.get("port") or 443)
    uuid = effective.get("uuid")
    sni = str(effective.get("sni") or server or "").strip()
    grpc = effective.get("grpc") or {}
    service_name = str(grpc.get("service_name") or "tracegate.v1.Edge").strip() or "tracegate.v1.Edge"
    authority = str(grpc.get("authority") or sni or server or "").strip()
    tls = effective.get("tls") or {}
    insecure = bool(tls.get("insecure", False))

    if not server or not uuid:
        raise V2RayNExportError("Missing fields for VLESS+gRPC+TLS export")
    if not sni:
        sni = str(server)

    params = {
        "encryption": "none",
        "security": "tls",
        "type": "grpc",
        "sni": sni,
        "serviceName": service_name,
    }
    if authority:
        params["authority"] = authority
    if insecure:
        params["allowInsecure"] = "1"

    name = effective.get("profile") or "V1-VLESS-gRPC-TLS-Direct"
    uri = f"vless://{uuid}@{server}:{port}?{_encode_query(params, safe='/,')}#{_q(str(name))}"
    tls_settings: dict[str, Any] = {
        "serverName": sni,
        "fingerprint": "chrome",
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
    port = int(effective.get("port") or 443)
    auth = effective.get("auth") or {}
    auth_type = str(auth.get("type") or "").strip().lower()
    username = (auth.get("username") or auth.get("client_id") or "").strip()
    password = (auth.get("password") or "").strip()
    token = (auth.get("token") or auth.get("value") or "").strip()
    sni = str(effective.get("sni") or server or "").strip()
    tls = effective.get("tls") or {}
    insecure = bool(tls.get("insecure", False))
    alpn = tls.get("alpn") or ["h3"]
    if isinstance(alpn, str):
        alpn_values = [alpn]
    else:
        alpn_values = [str(item).strip() for item in alpn if str(item).strip()]
    if not alpn_values:
        alpn_values = ["h3"]

    if not server:
        raise V2RayNExportError("Missing fields for Hysteria2 export")

    # Keep the URI aligned with the official Hysteria 2 scheme:
    # token auth is a single opaque auth component, percent-encoded as needed.
    params = {"insecure": "1" if insecure else "0"}
    if sni:
        params["sni"] = sni
        params["peer"] = sni
    if alpn_values and alpn_values != ["h3"]:
        params["alpn"] = ",".join(alpn_values)

    name = effective.get("profile") or "tracegate-hysteria2"
    if auth_type == "userpass":
        if not username or not password:
            raise V2RayNExportError("Missing userpass fields for Hysteria2 export")
        authority = f"{_q(username)}:{_q(password)}"
        share_auth = f"{username}:{password}"
    else:
        if not token:
            raise V2RayNExportError("Missing token field for Hysteria2 export")
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
            "password": share_auth,
            "tls": singbox_tls,
        },
    )
    return ExportResult(
        kind="uri",
        title="Hysteria2 link",
        content=uri,
        extra_messages=(_local_socks_extra_message(effective),),
        attachment_content=attachment_content,
        attachment_filename=attachment_filename,
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
        raise V2RayNExportError("Missing fields for MTProto export")

    try:
        links = build_mtproto_share_links(
            server=server,
            port=port,
            secret_hex=secret,
            transport=transport,
            domain=domain,
        )
    except MTProtoConfigError as exc:
        raise V2RayNExportError(str(exc)) from exc

    return ExportResult(kind="uri", title=f"Telegram Proxy link · {profile}", content=links.https_url)


def _export_shadowsocks2022_shadowtls(effective: dict[str, Any]) -> ExportResult:
    server = str(effective.get("server") or "").strip()
    port = int(effective.get("port") or 443)
    method = str(effective.get("method") or "2022-blake3-aes-128-gcm").strip()
    password = str(effective.get("password") or "").strip()
    shadowtls = effective.get("shadowtls") or {}
    shadowtls_password = str(shadowtls.get("password") or "").strip()
    shadowtls_server_name = str(shadowtls.get("server_name") or effective.get("sni") or server).strip()
    profile = str(effective.get("profile") or "V5-Shadowsocks2022-ShadowTLS-Direct").strip()

    if not server or not password or not shadowtls_password:
        raise V2RayNExportError("Missing fields for Shadowsocks-2022 + ShadowTLS export")

    attachment_content, attachment_filename = _build_singbox_client_attachment(
        effective,
        {
            "type": "shadowsocks",
            "tag": "proxy",
            "method": method,
            "password": password,
            "detour": "shadowtls-out",
        },
    )
    attachment = json.loads(attachment_content.decode("utf-8"))
    attachment["outbounds"].append(
        {
            "type": "shadowtls",
            "tag": "shadowtls-out",
            "server": server,
            "server_port": port,
            "version": int(shadowtls.get("version") or 3),
            "password": shadowtls_password,
            "tls": {
                "enabled": True,
                "server_name": shadowtls_server_name,
            },
        }
    )
    attachment_content = json.dumps(attachment, ensure_ascii=True, indent=2).encode("utf-8")

    return ExportResult(
        kind="attachment",
        title="Shadowsocks-2022 + ShadowTLS config",
        content=f"Use the attached sing-box config for {profile}. Local SOCKS5 authentication is required.",
        extra_messages=(_local_socks_extra_message(effective),),
        attachment_content=attachment_content,
        attachment_filename=attachment_filename,
        attachment_mime="application/json",
    )


def _export_wireguard_wstunnel(effective: dict[str, Any]) -> ExportResult:
    server = str(effective.get("server") or "").strip()
    wstunnel = effective.get("wstunnel") or {}
    wireguard = effective.get("wireguard") or {}
    profile = str(effective.get("profile") or "V7-WireGuard-WSTunnel-Direct").strip()
    private_key = str(wireguard.get("private_key") or "").strip()
    peer_public_key = str(wireguard.get("server_public_key") or "").strip()
    address = wireguard.get("address") or ""
    if isinstance(address, str):
        local_addresses = [address] if address else []
    else:
        local_addresses = [str(item).strip() for item in address if str(item).strip()]

    if not server or not private_key or not peer_public_key or not local_addresses:
        raise V2RayNExportError("Missing fields for WireGuard over WSTunnel export")

    wstunnel_url = _validated_wstunnel_url(wstunnel)
    local_udp_host, local_udp_port = _parse_loopback_listen_endpoint(
        wstunnel.get("local_udp_listen"),
        label="WSTunnel local UDP listen",
        default="127.0.0.1:51820",
    )

    outbound = {
        "type": "wireguard",
        "tag": "proxy",
        "server": local_udp_host,
        "server_port": local_udp_port,
        "local_address": local_addresses,
        "private_key": private_key,
        "peer_public_key": peer_public_key,
        "mtu": _validated_wireguard_mtu(wireguard),
        "workers": 4,
    }
    preshared_key = str(wireguard.get("preshared_key") or "").strip()
    if preshared_key:
        outbound["pre_shared_key"] = preshared_key
    attachment_content, attachment_filename = _build_singbox_client_attachment(effective, outbound)
    extra_messages = (_local_socks_extra_message(effective),)
    extra_messages = (("WSTunnel target", wstunnel_url), *extra_messages)
    return ExportResult(
        kind="attachment",
        title="WireGuard over WSTunnel config",
        content=(
            f"Use the attached sing-box config for {profile}. Start WSTunnel toward {wstunnel_url}; "
            "local SOCKS5 authentication is required."
        ),
        extra_messages=extra_messages,
        attachment_content=attachment_content,
        attachment_filename=attachment_filename,
        attachment_mime="application/json",
    )
