from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tracegate.enums import ConnectionMode, ConnectionProtocol, ConnectionVariant
from tracegate.models import Connection, Device, User
from tracegate.services.sni_catalog import SniCatalogEntry


@dataclass
class EndpointSet:
    vps_t_host: str
    vps_e_host: str
    # Optional per-role proxy hostname (e.g. Cloudflare orange cloud) used for HTTPS-based transports.
    vps_t_proxy_host: str | None = None
    vps_e_proxy_host: str | None = None
    # Legacy/compat: if per-role keys are not set, fall back to these.
    reality_public_key: str = ""
    reality_short_id: str = ""
    # Per-role REALITY material. Needed when B1 (direct to VPS-T) and B2 (chain via VPS-E)
    # terminate REALITY on different nodes with different keys/shortIds.
    reality_public_key_vps_t: str = ""
    reality_short_id_vps_t: str = ""
    reality_public_key_vps_e: str = ""
    reality_short_id_vps_e: str = ""
    wireguard_server_public_key: str = ""
    vless_ws_path: str = "/ws"
    vless_ws_tls_port: int = 443


def build_effective_config(
    *,
    user: User,
    device: Device,
    connection: Connection,
    selected_sni: SniCatalogEntry | None,
    endpoints: EndpointSet,
) -> dict[str, Any]:
    overrides = connection.custom_overrides_json or {}

    if connection.protocol == ConnectionProtocol.VLESS_REALITY:
        if connection.variant not in {ConnectionVariant.B1, ConnectionVariant.B2}:
            raise ValueError("VLESS/REALITY supports only B1/B2 variants")
        if selected_sni is None:
            raise ValueError("camouflage SNI is required for VLESS/REALITY")

        # REALITY terminates on different nodes depending on mode.
        # - DIRECT (B1): client connects to VPS-T -> use VPS-T REALITY public key + shortId.
        # - CHAIN (B2): client connects to VPS-E -> use VPS-E REALITY public key + shortId.
        if connection.mode == ConnectionMode.DIRECT:
            pbk = endpoints.reality_public_key_vps_t or endpoints.reality_public_key
            sid = endpoints.reality_short_id_vps_t or endpoints.reality_short_id
        else:
            pbk = endpoints.reality_public_key_vps_e or endpoints.reality_public_key
            sid = endpoints.reality_short_id_vps_e or endpoints.reality_short_id

        common = {
            "protocol": "vless",
            "transport": "reality",
            "xhttp": {
                "mode": "packet-up",
                "path": "/api/v1/update",
            },
            "port": 443,
            # Use connection-scoped UUID so one user can have multiple VLESS connections safely.
            "uuid": str(connection.id),
            "device_id": str(device.id),
            "sni": selected_sni.fqdn,
            "reality": {
                "public_key": pbk or "REPLACE_REALITY_PUBLIC_KEY",
                "short_id": sid or "REPLACE_REALITY_SHORT_ID",
            },
            "local_socks": {
                "enabled": True,
                "listen": f"127.0.0.1:{overrides.get('local_socks_port', 1080)}",
            },
            "client_options": {
                "connect_timeout_ms": overrides.get("connect_timeout_ms", 8000),
                "dial_timeout_ms": overrides.get("dial_timeout_ms", 8000),
                "tcp_fast_open": bool(overrides.get("tcp_fast_open", True)),
            },
        }

        if connection.mode == ConnectionMode.DIRECT and connection.variant == ConnectionVariant.B1:
            return {
                **common,
                "profile": "B1-stealth-direct",
                "server": endpoints.vps_t_host,
                "chain": None,
                "design_constraints": {
                    "fixed_port_tcp": 443,
                    "single_sni_for_all_legs": True,
                },
            }

        if connection.mode == ConnectionMode.CHAIN and connection.variant == ConnectionVariant.B2:
            # Chain profile always enters via VPS-E.
            # The E->T leg can be implemented either as plain L4 forward (legacy) or as
            # a splitter transit hop managed on VPS-E.
            return {
                **common,
                "profile": "B2-stealth-chain",
                "server": endpoints.vps_e_host,
                "chain": {"type": "tcp_forward", "upstream": endpoints.vps_t_host, "port": 443},
                "design_constraints": {
                    "fixed_port_tcp": 443,
                    "entry_via_vps_e": True,
                    "transit_via_vps_t": True,
                },
            }

        raise ValueError("Inconsistent VLESS/REALITY mode and variant")

    if connection.protocol == ConnectionProtocol.VLESS_WS_TLS:
        if connection.variant != ConnectionVariant.B1 or connection.mode != ConnectionMode.DIRECT:
            raise ValueError("VLESS+WS+TLS supports only B1 direct")

        # For WS+TLS in Tracegate architecture, direct mode is always terminated on VPS-T.
        # Operators can override SNI/Host via custom_overrides_json.
        tls_server_name = str(overrides.get("tls_server_name") or "").strip()
        if not tls_server_name and selected_sni is not None:
            tls_server_name = selected_sni.fqdn

        # Direct WS+TLS must terminate on VPS-T endpoint, not on VPS-E entry host.
        entry_host = str(endpoints.vps_t_host or "").strip()
        tls_termination_host = entry_host
        if not tls_server_name:
            tls_server_name = tls_termination_host

        ws_path = str(overrides.get("ws_path") or endpoints.vless_ws_path or "/ws").strip() or "/ws"
        ws_host = str(overrides.get("ws_host") or tls_server_name or "").strip()

        common = {
            "protocol": "vless",
            "transport": "ws_tls",
            "port": int(endpoints.vless_ws_tls_port or 443),
            "uuid": str(connection.id),
            "device_id": str(device.id),
            "sni": tls_server_name,
            "tls": {
                "server_name": tls_server_name,
                "insecure": bool(overrides.get("tls_insecure", False)),
            },
            "ws": {
                "path": ws_path,
                "host": ws_host,
            },
            "local_socks": {
                "enabled": True,
                "listen": f"127.0.0.1:{overrides.get('local_socks_port', 1080)}",
            },
            "client_options": {
                "connect_timeout_ms": overrides.get("connect_timeout_ms", 8000),
                "dial_timeout_ms": overrides.get("dial_timeout_ms", 8000),
                "tcp_fast_open": bool(overrides.get("tcp_fast_open", True)),
            },
        }

        return {
            **common,
            "profile": "B1-https-ws-direct",
            "server": entry_host,
            "chain": None,
            "design_constraints": {
                "fixed_port_tcp": int(endpoints.vless_ws_tls_port or 443),
            },
        }

    if connection.protocol == ConnectionProtocol.HYSTERIA2:
        if connection.variant != ConnectionVariant.B3 or connection.mode != ConnectionMode.DIRECT:
            raise ValueError("Hysteria2 supports B3 direct in v0.1")

        mode = overrides.get("client_mode", "socks")
        if mode not in {"socks", "http", "tun"}:
            raise ValueError("Unsupported Hysteria client_mode")

        # Keep it stable across bot, node configs, and metrics.
        # Format: "B* - TG_ID - CONNECTION_ID"
        marker = f"{connection.variant.value} - {user.telegram_id} - {connection.id}"

        return {
            "protocol": "hysteria2",
            "profile": "B3-h3-mimic-direct",
            "server": endpoints.vps_t_host,
            "port": 443,
            "transport": "udp-quic",
            "auth": {
                "type": "userpass",
                "username": marker,
                "password": str(device.id),
            },
            "client_mode": mode,
            "up_mbps": overrides.get("up_mbps", 100),
            "down_mbps": overrides.get("down_mbps", 100),
            "local_socks": {
                "enabled": mode == "socks",
                "listen": overrides.get("socks_listen", "127.0.0.1:1080"),
            },
            "design_constraints": {
                "fixed_port_udp": 443,
                "masquerade_mode": "file",
                "stats_api_secret_required": True,
            },
        }

    if connection.protocol == ConnectionProtocol.WIREGUARD:
        if connection.variant != ConnectionVariant.B5 or connection.mode != ConnectionMode.DIRECT:
            raise ValueError("WireGuard supports B5 direct in v0.1")

        return {
            "protocol": "wireguard",
            "profile": "B5-gaming-direct",
            "endpoint": f"{endpoints.vps_t_host}:51820",
            "interface": {
                "addresses": ["10.70.0.2/32"],
                "dns": overrides.get("dns", ["1.1.1.1", "8.8.8.8"]),
                "mtu": overrides.get("mtu", 1420),
            },
            "peer": {
                "public_key": endpoints.wireguard_server_public_key or "REPLACE_WG_SERVER_PUBLIC_KEY",
                "allowed_ips": overrides.get("allowed_ips", ["0.0.0.0/0"]),
                "persistent_keepalive": overrides.get("persistent_keepalive", 25),
            },
            "design_constraints": {
                "fixed_port_udp": 51820,
                "ipv4_only": True,
            },
        }

    raise ValueError(f"Unsupported protocol: {connection.protocol}")
