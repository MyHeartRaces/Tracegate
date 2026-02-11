from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode


class V2RayNExportError(ValueError):
    pass


@dataclass(frozen=True)
class ExportResult:
    kind: str  # "uri" | "wg_conf"
    title: str
    content: str
    filename: str | None = None


def _q(s: str) -> str:
    # Share links typically expect URL-encoded fragments/params.
    return quote(s, safe="")


def _encode_query(params: dict[str, Any], *, safe: str = "") -> str:
    # `path=/ws` is more interoperable than `%2Fws` for some clients.
    return urlencode(params, safe=safe)


def export_client_config(effective: dict[str, Any]) -> ExportResult:
    """
    Build a client-importable payload from Tracegate effective_config_json.

    - VLESS+REALITY: returns a `vless://...` URI
    - Hysteria2: returns a `hysteria2://...` URI (with insecure=1 by default)
    - WireGuard: returns a wg `.conf` payload (as text)
    """

    proto = (effective.get("protocol") or "").strip().lower()
    if proto == "vless":
        transport = (effective.get("transport") or "").strip().lower()
        if not transport:
            # Backward-compatible heuristics (older payloads / tests may omit transport).
            if effective.get("reality"):
                transport = "reality"
            elif effective.get("ws"):
                transport = "ws_tls"
        if transport in {"reality"}:
            return _export_vless_reality(effective)
        if transport in {"ws_tls", "ws+tls", "ws-tls"}:
            return _export_vless_ws_tls(effective)
        raise V2RayNExportError(f"Unsupported VLESS transport for export: {transport!r}")
    if proto == "hysteria2":
        return _export_hysteria2(effective)
    if proto == "wireguard":
        return _export_wireguard(effective)
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

    if not server or not uuid or not sni or not pbk or not sid:
        raise V2RayNExportError("Missing fields for VLESS/REALITY export")

    # Xray share-link parameters.
    params = {
        "encryption": "none",
        "security": "reality",
        "type": "tcp",
        "sni": sni,
        "fp": "chrome",
        "pbk": pbk,
        "sid": sid,
        # Many clients default to spiderX="/". Export explicitly to reduce interop issues.
        "spx": "/",
    }

    name = effective.get("profile") or "tracegate-vless"
    uri = f"vless://{uuid}@{server}:{port}?{_encode_query(params)}#{_q(str(name))}"
    return ExportResult(kind="uri", title="VLESS REALITY link", content=uri)


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
        # Some clients default to h2 and fail WS over Cloudflare; pin ALPN to HTTP/1.1.
        "alpn": "http/1.1",
        "sni": sni,
        "host": ws_host,
        "path": ws_path,
    }
    if insecure:
        params["allowInsecure"] = "1"

    name = effective.get("profile") or "tracegate-vless-ws"
    uri = f"vless://{uuid}@{server}:{port}?{_encode_query(params, safe='/,')}#{_q(str(name))}"
    return ExportResult(kind="uri", title="VLESS WS+TLS link", content=uri)


def _export_hysteria2(effective: dict[str, Any]) -> ExportResult:
    server = effective.get("server")
    port = int(effective.get("port") or 443)
    auth = effective.get("auth") or {}
    username = (auth.get("username") or "").strip()
    password = (auth.get("password") or "").strip()

    if not server or not username or not password:
        raise V2RayNExportError("Missing fields for Hysteria2 export")

    # Export with insecure=1 for compatibility with self-signed/non-public cert deployments.
    params = {
        "alpn": "h3",
        "insecure": "1",
    }

    name = effective.get("profile") or "tracegate-hysteria2"
    uri = f"hysteria2://{_q(username)}:{_q(password)}@{server}:{port}/?{_encode_query(params)}#{_q(str(name))}"
    return ExportResult(kind="uri", title="Hysteria2 link", content=uri)


def _export_wireguard(effective: dict[str, Any]) -> ExportResult:
    endpoint = effective.get("endpoint")
    interface = effective.get("interface") or {}
    peer = effective.get("peer") or {}

    addresses = interface.get("addresses") or []
    private_key = interface.get("private_key") or ""
    dns = interface.get("dns") or []
    mtu = interface.get("mtu")

    public_key = peer.get("public_key") or ""
    allowed_ips = peer.get("allowed_ips") or []
    keepalive = peer.get("persistent_keepalive")

    if not endpoint or not addresses or not private_key or not public_key or not allowed_ips:
        raise V2RayNExportError("Missing fields for WireGuard export")

    lines: list[str] = ["[Interface]"]
    for addr in addresses:
        lines.append(f"Address = {addr}")
    if dns:
        lines.append(f"DNS = {', '.join(dns)}")
    if mtu:
        lines.append(f"MTU = {mtu}")
    lines.append(f"PrivateKey = {private_key}")
    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {public_key}")
    lines.append(f"Endpoint = {endpoint}")
    lines.append(f"AllowedIPs = {', '.join(allowed_ips)}")
    if keepalive:
        lines.append(f"PersistentKeepalive = {keepalive}")
    lines.append("")

    name = effective.get("profile") or "tracegate-wg"
    filename = f"{name}.conf"
    return ExportResult(kind="wg_conf", title="WireGuard config", content="\n".join(lines), filename=filename)
