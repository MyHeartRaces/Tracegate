from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any

from tracegate.constants import (
    TRACEGATE_FORBIDDEN_PUBLIC_TCP_PORT,
    TRACEGATE_FORBIDDEN_PUBLIC_UDP_PORT,
    TRACEGATE_PUBLIC_UDP_PORT,
)
from tracegate.enums import ConnectionMode, ConnectionProtocol, ConnectionVariant
from tracegate.models import Connection, Device, User
from tracegate.services.connection_profiles import (
    connection_profile_label,
    tcp_chain_selected_profiles,
    udp_chain_selected_profiles,
)
from tracegate.services.hysteria_credentials import build_hysteria_auth_payload
from tracegate.services.sni_catalog import SniCatalogEntry
from tracegate.services.wireguard_keys import (
    derive_wireguard_client_address,
    derive_wireguard_public_key,
    generate_wireguard_keypair,
    generate_wireguard_preshared_key,
)

_LOCAL_SOCKS_PORT_BASE = 20000
_LOCAL_SOCKS_PORT_SPAN = 40000
_LOCAL_SOCKS_CREDENTIAL_RE = re.compile(r"^[A-Za-z0-9._~!$&'()*+,;=:@%-]{1,128}$")


@dataclass
class EndpointSet:
    transit_host: str
    entry_host: str
    hysteria_auth_mode: str = "userpass"
    hysteria_udp_port: int = TRACEGATE_PUBLIC_UDP_PORT
    hysteria_salamander_password_entry: str = ""
    hysteria_salamander_password_transit: str = ""
    # Optional per-role proxy hostname (e.g. Cloudflare orange cloud) used for HTTPS-based transports.
    transit_proxy_host: str | None = None
    entry_proxy_host: str | None = None
    # Legacy/compat: if per-role keys are not set, fall back to these.
    reality_public_key: str = ""
    reality_short_id: str = ""
    # Per-role REALITY material. Needed when V1 (direct to Transit) and V2 (chain via Entry)
    # terminate REALITY on different nodes with different keys/shortIds.
    reality_public_key_transit: str = ""
    reality_short_id_transit: str = ""
    reality_public_key_entry: str = ""
    reality_short_id_entry: str = ""
    vless_ws_path: str = "/ws"
    vless_ws_tls_port: int = 443
    vless_grpc_service_name: str = "tracegate.v1.Edge"
    vless_grpc_tls_port: int = 443
    hysteria_ech_config_list_entry: str = ""
    hysteria_ech_config_list_transit: str = ""
    hysteria_ech_force_query_entry: str = ""
    hysteria_ech_force_query_transit: str = ""
    shadowtls_server_name_entry: str = ""
    shadowtls_server_name_transit: str = ""
    shadowtls_password_entry: str = ""
    shadowtls_password_transit: str = ""
    shadowsocks2022_method: str = "2022-blake3-aes-128-gcm"
    shadowsocks2022_password_entry: str = ""
    shadowsocks2022_password_transit: str = ""
    wireguard_server_public_key: str = ""
    wireguard_client_address: str = ""
    wireguard_dns: str = "1.1.1.1"
    wireguard_allowed_ips: tuple[str, ...] = ("0.0.0.0/0", "::/0")
    wireguard_mtu: int = 1280
    wstunnel_path: str = "/cdn-cgi/tracegate"


def _build_local_socks_auth(
    *,
    user: User,
    device: Device,
    connection: Connection,
    overrides: dict[str, Any],
) -> dict[str, Any]:
    has_username = "local_socks_username" in overrides and overrides.get("local_socks_username") is not None
    has_password = "local_socks_password" in overrides and overrides.get("local_socks_password") is not None
    if has_username or has_password:
        username = str(overrides.get("local_socks_username") or "").strip()
        password = str(overrides.get("local_socks_password") or "").strip()
        if not username or not password:
            raise ValueError("local SOCKS5 username and password overrides must be provided together")
        if _LOCAL_SOCKS_CREDENTIAL_RE.fullmatch(username) is None:
            raise ValueError("local_socks_username contains unsupported characters or is too long")
        if _LOCAL_SOCKS_CREDENTIAL_RE.fullmatch(password) is None:
            raise ValueError("local_socks_password contains unsupported characters or is too long")
        return {
            "mode": "username_password",
            "required": True,
            "username": username,
            "password": password,
        }

    seed = "|".join(
        [
            str(user.telegram_id),
            str(device.id),
            str(connection.id),
            str(connection.protocol.value),
            str(connection.variant.value),
        ]
    ).encode("utf-8")
    digest = hashlib.sha256(seed).digest()
    username = f"tg_{connection.variant.value.lower()}_{digest[:5].hex()}"
    password = base64.urlsafe_b64encode(hashlib.sha256(digest + b":local-socks").digest()).decode("ascii").rstrip("=")
    return {
        "mode": "username_password",
        "required": True,
        "username": username,
        "password": password[:32],
    }


def _is_loopback_host(host: str) -> bool:
    normalized = str(host or "").strip().lower()
    if normalized == "localhost":
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


def _is_placeholder(value: object) -> bool:
    return str(value or "").strip().upper().startswith("REPLACE_")


def _is_ip_literal(host: str) -> bool:
    normalized = str(host or "").strip().strip("[]")
    if not normalized:
        return False
    try:
        ip_address(normalized)
        return True
    except ValueError:
        return False


def _normalize_loopback_listen(value: object, *, field_name: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError(f"{field_name} must not be empty")

    host: str
    port_raw: str
    if raw.startswith("["):
        host_end = raw.find("]")
        if host_end < 0 or host_end + 1 >= len(raw) or raw[host_end + 1] != ":":
            raise ValueError(f"{field_name} must use loopback host:port")
        host = raw[1:host_end]
        port_raw = raw[host_end + 2 :]
    else:
        host, sep, port_raw = raw.rpartition(":")
        if not sep:
            host = "127.0.0.1"
            port_raw = raw

    host = host.strip() or "127.0.0.1"
    if not _is_loopback_host(host):
        raise ValueError(f"{field_name} must be bound to loopback, got {raw}")

    try:
        port = int(str(port_raw).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must use a valid TCP port, got {raw}") from exc
    if port < 1 or port > 65535:
        raise ValueError(f"{field_name} must use a TCP port in 1..65535, got {raw}")

    return f"127.0.0.1:{port}"


def _normalize_http_path(value: object, *, field_name: str) -> str:
    raw = str(value or "").strip()
    if not raw.startswith("/"):
        raise ValueError(f"{field_name} must be an absolute HTTP path")
    if "://" in raw or any(ch.isspace() for ch in raw):
        raise ValueError(f"{field_name} must be a clean HTTP path")
    return raw


def _normalize_int_range(value: object, *, field_name: str, min_value: int, max_value: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be an integer") from exc
    if parsed < min_value or parsed > max_value:
        raise ValueError(f"{field_name} must be in {min_value}..{max_value}")
    return parsed


def _default_local_socks_port(*, user: User, device: Device, connection: Connection) -> int:
    seed = "|".join(
        [
            str(user.telegram_id),
            str(device.id),
            str(connection.id),
            str(connection.protocol.value),
            str(connection.variant.value),
            "local-socks-port",
        ]
    ).encode("utf-8")
    digest = hashlib.sha256(seed).digest()
    return _LOCAL_SOCKS_PORT_BASE + (int.from_bytes(digest[:4], "big") % _LOCAL_SOCKS_PORT_SPAN)


def _local_socks_listen(
    *,
    overrides: dict[str, Any],
    user: User,
    device: Device,
    connection: Connection,
) -> str:
    raw_override = overrides.get("local_socks_port")
    if raw_override is not None and str(raw_override).strip():
        return str(raw_override).strip()
    return f"127.0.0.1:{_default_local_socks_port(user=user, device=device, connection=connection)}"


def _local_socks_payload(
    *,
    listen: str,
    user: User,
    device: Device,
    connection: Connection,
    overrides: dict[str, Any],
) -> dict[str, Any]:
    return {
        "enabled": True,
        "listen": _normalize_loopback_listen(listen, field_name="local_socks.listen"),
        "auth": _build_local_socks_auth(user=user, device=device, connection=connection, overrides=overrides),
    }


def _derive_urlsafe_secret(*, user: User, device: Device, connection: Connection, purpose: str, length: int = 32) -> str:
    seed = "|".join(
        [
            str(user.telegram_id),
            str(device.id),
            str(connection.id),
            str(connection.protocol.value),
            str(connection.variant.value),
            purpose,
        ]
    ).encode("utf-8")
    digest = hashlib.sha256(seed).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")[:length]


def _shadowsocks2022_password(
    *,
    user: User,
    device: Device,
    connection: Connection,
    method: str,
) -> str:
    key_len = 32 if "256" in method else 16
    seed = "|".join(
        [
            str(user.telegram_id),
            str(device.id),
            str(connection.id),
            str(connection.protocol.value),
            str(connection.variant.value),
            method,
            "shadowsocks2022",
        ]
    ).encode("utf-8")
    return base64.b64encode(hashlib.sha256(seed).digest()[:key_len]).decode("ascii")


def _hysteria_salamander_password(*, endpoints: EndpointSet, is_chain: bool) -> str:
    password = (
        endpoints.hysteria_salamander_password_entry
        if is_chain
        else endpoints.hysteria_salamander_password_transit
    )
    password = str(password or "").strip()
    return password or "REPLACE_HYSTERIA2_SALAMANDER_PASSWORD"


def _hysteria_masquerade_payload() -> dict[str, Any]:
    return {
        "type": "file",
        "mode": "server_file_decoy",
        "required": True,
        "serves_decoy": True,
    }


def _hysteria_hygiene_payload(*, is_chain: bool, public_udp_port: int) -> dict[str, Any]:
    return {
        "required": True,
        "required_layers": [
            "hysteria2",
            "salamander",
            "file-masquerade",
            "dns-san-sni-guard",
            "http-auth-loopback",
            "reject-anonymous",
            "traffic-stats-loopback",
            "udp-enabled",
            "quic-pmtu",
            "udp-idle-timeout",
            "sniff",
        ],
        "server": {
            "auth_backend": "http-loopback",
            "anonymous": "reject",
            "sni_guard": "dns-san",
            "traffic_stats": "loopback-secret",
            "masquerade": "file-decoy",
            "sniff": True,
            "congestion": "bbr",
        },
        "udp": {
            "public_port": public_udp_port,
            "enabled": True,
            "idle_timeout": "60s",
            "path_mtu_discovery": True,
            "anti_replay": True,
            "anti_amplification": True,
            "rate_limit": {
                "handshake_per_minute": 120,
                "new_session_per_minute": 60,
            },
            "mtu": {
                "mode": "clamp",
                "max_packet_size": 1252,
            },
            "source_validation": "profile-bound-remote" if is_chain else "auth-bound-client",
        },
        "client": {
            "local_socks_auth": "required",
            "anonymous_local_proxy": "forbidden",
        },
        "forbidden_public_ports": [
            {"protocol": "udp", "port": TRACEGATE_FORBIDDEN_PUBLIC_UDP_PORT, "action": "drop"},
            {"protocol": "tcp", "port": TRACEGATE_FORBIDDEN_PUBLIC_TCP_PORT, "action": "drop"},
        ],
        "entry_transit_relay": bool(is_chain),
    }


def _entry_transit_private_relay(
    *,
    endpoints: EndpointSet,
    inner_transport: str,
) -> dict[str, Any]:
    is_udp = inner_transport == "hysteria2-quic"
    relay = {
        "type": "entry_transit_private_relay",
        "entry": endpoints.entry_host,
        "transit": endpoints.transit_host,
        "link_class": "entry-transit-udp" if is_udp else "entry-transit",
        "carrier": "hysteria2-salamander" if is_udp else "xray-vless-reality",
        "preferred_outer": "udp-quic-salamander" if is_udp else "reality-xhttp",
        "outer_carrier": "udp-quic" if is_udp else "tcp-reality-xhttp",
        "optional_packet_shaping": "paired-udp-obfs" if is_udp else None,
        "managed_by": "link-crypto" if is_udp else "xray-chain",
        "selected_profiles": udp_chain_selected_profiles() if is_udp else tcp_chain_selected_profiles(),
        "inner_transport": inner_transport,
        "xray_backhaul": False,
        "udp_capable": is_udp,
        "salamander_required": is_udp,
        "paired_obfs_supported": is_udp,
        "dpi_resistance": {
            "required": is_udp,
            "mode": "salamander-plus-scoped-paired-obfs" if is_udp else "reality-xhttp",
            "forbid_udp_443": False,
            "forbid_tcp_8443": is_udp,
        },
    }
    if is_udp:
        relay["hygiene"] = {
            "required": True,
            "carrier": "hysteria2",
            "obfs": "salamander",
            "anti_replay": True,
            "anti_amplification": True,
            "source_validation": "profile-bound-remote",
            "mtu": {"mode": "clamp", "max_packet_size": 1252},
        }
    return relay



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
        if connection.variant != ConnectionVariant.V1:
            raise ValueError("VLESS/REALITY supports only V1")
        if selected_sni is None:
            raise ValueError("camouflage SNI is required for VLESS/REALITY")

        # REALITY terminates on different nodes depending on mode.
        # - DIRECT: client connects to Transit -> use Transit REALITY public key + shortId.
        # - CHAIN: client connects to Entry -> use Entry REALITY public key + shortId.
        if connection.mode == ConnectionMode.DIRECT:
            pbk = endpoints.reality_public_key_transit or endpoints.reality_public_key
            sid = endpoints.reality_short_id_transit or endpoints.reality_short_id
        else:
            pbk = endpoints.reality_public_key_entry or endpoints.reality_public_key
            sid = endpoints.reality_short_id_entry or endpoints.reality_short_id

        common = {
            "protocol": "vless",
            "transport": "reality",
            "xhttp": {
                "mode": "auto",
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
            "local_socks": _local_socks_payload(
                listen=_local_socks_listen(overrides=overrides, user=user, device=device, connection=connection),
                user=user,
                device=device,
                connection=connection,
                overrides=overrides,
            ),
            "client_options": {
                "connect_timeout_ms": overrides.get("connect_timeout_ms", 8000),
                "dial_timeout_ms": overrides.get("dial_timeout_ms", 8000),
                "tcp_fast_open": bool(overrides.get("tcp_fast_open", True)),
            },
        }

        if connection.mode == ConnectionMode.DIRECT and connection.variant == ConnectionVariant.V1:
            return {
                **common,
                "profile": connection_profile_label(connection.protocol, connection.mode, connection.variant),
                "server": endpoints.transit_host,
                "chain": None,
                "design_constraints": {
                    "fixed_port_tcp": 443,
                    "single_sni_for_all_legs": True,
                },
            }

        if connection.mode == ConnectionMode.CHAIN and connection.variant == ConnectionVariant.V1:
            return {
                **common,
                "profile": connection_profile_label(connection.protocol, connection.mode, connection.variant),
                "server": endpoints.entry_host,
                "chain": _entry_transit_private_relay(endpoints=endpoints, inner_transport="vless-reality-xhttp"),
                "design_constraints": {
                    "fixed_port_tcp": 443,
                    "entry_role_required": True,
                    "transit_role_required": True,
                    "private_interconnect": "xray-vless-reality",
                    "backhaul_outside_xray": False,
                },
            }

        raise ValueError("Inconsistent VLESS/REALITY mode and variant")

    if connection.protocol in {ConnectionProtocol.VLESS_WS_TLS, ConnectionProtocol.VLESS_GRPC_TLS}:
        is_grpc = connection.protocol == ConnectionProtocol.VLESS_GRPC_TLS
        if connection.variant != ConnectionVariant.V0 or connection.mode != ConnectionMode.DIRECT:
            raise ValueError("VLESS TLS compatibility profiles support only V0 direct")

        # TLS compatibility surfaces in Tracegate architecture are always terminated on Transit.
        # Operators can override SNI/Host via custom_overrides_json.
        tls_server_name = str(overrides.get("tls_server_name") or "").strip()
        if not tls_server_name and selected_sni is not None:
            tls_server_name = selected_sni.fqdn

        # Client configs must use the direct Transit connection hostname, not the
        # public/proxied site hostname. Operators can still override per connection.
        transit_host = str(overrides.get("server") or endpoints.transit_host).strip()
        connect_host = str(overrides.get("connect_host") or "").strip()
        tls_termination_host = transit_host
        if not tls_server_name:
            tls_server_name = tls_termination_host

        ws_path = str(overrides.get("ws_path") or endpoints.vless_ws_path or "/ws").strip() or "/ws"
        ws_host = str(overrides.get("ws_host") or tls_server_name or "").strip()
        default_alpn = ["h2"] if is_grpc else ["http/1.1"]
        alpn_raw = overrides.get("alpn", default_alpn)
        tls_alpn = (
            [str(alpn_raw).strip()]
            if isinstance(alpn_raw, str)
            else [str(item).strip() for item in alpn_raw if str(item).strip()]
        )
        if not tls_alpn:
            tls_alpn = default_alpn
        grpc_service_name = (
            str(overrides.get("grpc_service_name") or endpoints.vless_grpc_service_name or "tracegate.v1.Edge").strip()
            or "tracegate.v1.Edge"
        )
        grpc_authority = str(overrides.get("grpc_authority") or tls_server_name or "").strip()

        common = {
            "protocol": "vless",
            "transport": "grpc_tls" if is_grpc else "ws_tls",
            "connect_host": connect_host,
            "port": int((endpoints.vless_grpc_tls_port if is_grpc else endpoints.vless_ws_tls_port) or 443),
            "uuid": str(connection.id),
            "device_id": str(device.id),
            "sni": tls_server_name,
            "tls": {
                "server_name": tls_server_name,
                "insecure": bool(overrides.get("tls_insecure", False)),
                "alpn": tls_alpn,
            },
            "ws": {
                "path": ws_path,
                "host": ws_host,
            },
            "grpc": {
                "service_name": grpc_service_name,
                "authority": grpc_authority,
            },
            "local_socks": _local_socks_payload(
                listen=_local_socks_listen(overrides=overrides, user=user, device=device, connection=connection),
                user=user,
                device=device,
                connection=connection,
                overrides=overrides,
            ),
            "client_options": {
                "connect_timeout_ms": overrides.get("connect_timeout_ms", 8000),
                "dial_timeout_ms": overrides.get("dial_timeout_ms", 8000),
                "tcp_fast_open": bool(overrides.get("tcp_fast_open", True)),
            },
        }

        return {
            **common,
            "profile": connection_profile_label(connection.protocol, connection.mode, connection.variant),
            "server": transit_host,
            "chain": None,
            "design_constraints": {
                "fixed_port_tcp": int((endpoints.vless_grpc_tls_port if is_grpc else endpoints.vless_ws_tls_port) or 443),
                "preferred_compat_transport": "grpc" if is_grpc else "ws",
            },
        }

    if connection.protocol == ConnectionProtocol.HYSTERIA2:
        if (connection.mode, connection.variant) not in {
            (ConnectionMode.DIRECT, ConnectionVariant.V2),
            (ConnectionMode.CHAIN, ConnectionVariant.V2),
        }:
            raise ValueError("Hysteria2 supports V2 direct or V2 chain")

        mode = str(overrides.get("client_mode") or "socks").strip().lower()
        if mode != "socks":
            raise ValueError("Hysteria client_mode must stay socks because local SOCKS5 auth is required")

        is_chain = connection.mode == ConnectionMode.CHAIN
        entry_host = endpoints.entry_host if is_chain else endpoints.transit_host
        profile_name = connection_profile_label(connection.protocol, connection.mode, connection.variant)
        ech_config_list = (
            endpoints.hysteria_ech_config_list_entry if is_chain else endpoints.hysteria_ech_config_list_transit
        )
        ech_force_query = (
            endpoints.hysteria_ech_force_query_entry if is_chain else endpoints.hysteria_ech_force_query_transit
        )
        auth_payload = build_hysteria_auth_payload(
            auth_mode=endpoints.hysteria_auth_mode,
            variant=connection.variant.value,
            tg_id=user.telegram_id,
            connection_id=str(connection.id),
            device_id=str(device.id),
        )
        tls_payload: dict[str, Any] = {
            "server_name": entry_host,
            "insecure": bool(overrides.get("tls_insecure", False)) or _is_ip_literal(entry_host),
            "alpn": ["h3"],
        }
        if ech_config_list:
            tls_payload["ech_config_list"] = ech_config_list
        if ech_force_query:
            tls_payload["ech_force_query"] = ech_force_query
        salamander_password = _hysteria_salamander_password(endpoints=endpoints, is_chain=is_chain)
        hysteria_port = _normalize_int_range(
            endpoints.hysteria_udp_port,
            field_name="hysteria_udp_port",
            min_value=1,
            max_value=65535,
        )

        return {
            "protocol": "hysteria2",
            "profile": profile_name,
            "server": entry_host,
            "port": hysteria_port,
            "sni": entry_host,
            "transport": "udp-quic",
            "tls": tls_payload,
            "auth": auth_payload,
            "obfs": {
                "type": "salamander",
                "password": salamander_password,
                "required": True,
            },
            "masquerade": _hysteria_masquerade_payload(),
            "hygiene": _hysteria_hygiene_payload(is_chain=is_chain, public_udp_port=hysteria_port),
            "client_mode": mode,
            "up_mbps": overrides.get("up_mbps", 100),
            "down_mbps": overrides.get("down_mbps", 100),
            "local_socks": {
                **_local_socks_payload(
                    listen=str(overrides.get("socks_listen") or "").strip()
                    or _local_socks_listen(overrides=overrides, user=user, device=device, connection=connection),
                    user=user,
                    device=device,
                    connection=connection,
                    overrides=overrides,
                ),
                "enabled": True,
            },
            "design_constraints": {
                "fixed_port_udp": hysteria_port,
                "masquerade_mode": "file",
                "masquerade_required": True,
                "salamander_required": True,
                "hygiene_required": True,
                "server_sni_guard": "dns-san",
                "auth_backend": "http-loopback",
                "anonymous_rejected": True,
                "traffic_stats": "loopback-secret",
                "udp_hygiene": "anti-replay+anti-amplification+rate-limit+mtu-clamp+source-validation",
                "entry_role_required": is_chain,
                "private_interconnect": "hysteria2-salamander-udp-link" if is_chain else None,
                "backhaul_outside_xray": is_chain,
                "udp_over_private_relay": is_chain,
            },
            "chain": _entry_transit_private_relay(endpoints=endpoints, inner_transport="hysteria2-quic")
            if is_chain
            else None,
        }

    if connection.protocol == ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS:
        if (connection.mode, connection.variant) not in {
            (ConnectionMode.DIRECT, ConnectionVariant.V3),
            (ConnectionMode.CHAIN, ConnectionVariant.V3),
        }:
            raise ValueError("Shadowsocks-2022 + ShadowTLS supports V3 direct or V3 chain")

        is_chain = connection.mode == ConnectionMode.CHAIN
        server = endpoints.entry_host if is_chain else endpoints.transit_host
        selected_sni_fqdn = selected_sni.fqdn if selected_sni is not None else ""
        shadowtls_server_name = str(
            overrides.get("shadowtls_server_name")
            or (endpoints.shadowtls_server_name_entry if is_chain else endpoints.shadowtls_server_name_transit)
            or selected_sni_fqdn
        ).strip()
        if not shadowtls_server_name:
            shadowtls_server_name = server
        method = str(overrides.get("method") or endpoints.shadowsocks2022_method).strip()
        if not method:
            method = "2022-blake3-aes-128-gcm"
        shadowtls_password = str(
            overrides.get("shadowtls_password")
            or (endpoints.shadowtls_password_entry if is_chain else endpoints.shadowtls_password_transit)
            or _derive_urlsafe_secret(
                user=user,
                device=device,
                connection=connection,
                purpose="shadowtls-v3",
                length=32,
            )
        ).strip()
        shadowsocks2022_server_password = str(
            endpoints.shadowsocks2022_password_entry if is_chain else endpoints.shadowsocks2022_password_transit
        ).strip()
        shadowsocks2022_user_password = str(
            overrides.get("password")
            or _shadowsocks2022_password(
                user=user,
                device=device,
                connection=connection,
                method=method,
            )
        ).strip()
        shadowsocks2022_client_password = shadowsocks2022_user_password
        if shadowsocks2022_server_password and ":" not in shadowsocks2022_user_password:
            shadowsocks2022_client_password = f"{shadowsocks2022_server_password}:{shadowsocks2022_user_password}"

        return {
            "protocol": "shadowsocks2022",
            "transport": "shadowtls_v3",
            "profile": connection_profile_label(connection.protocol, connection.mode, connection.variant),
            "server": server,
            "port": 443,
            "sni": shadowtls_server_name,
            "method": method,
            "password": shadowsocks2022_client_password,
            "shadowtls": {
                "version": 3,
                "server_name": shadowtls_server_name,
                "password": shadowtls_password,
                "alpn": overrides.get("alpn", ["h2", "http/1.1"]),
            },
            "local_socks": _local_socks_payload(
                listen=_local_socks_listen(overrides=overrides, user=user, device=device, connection=connection),
                user=user,
                device=device,
                connection=connection,
                overrides=overrides,
            ),
            "design_constraints": {
                "fixed_port_tcp": 443,
                "shadowtls_version": 3,
                "entry_role_required": is_chain,
                "private_interconnect": "xray-vless-reality" if is_chain else None,
            },
            "chain": (
                _entry_transit_private_relay(endpoints=endpoints, inner_transport="shadowsocks2022-shadowtls-v3")
                if is_chain
                else None
            ),
        }

    if connection.protocol == ConnectionProtocol.WIREGUARD_WSTUNNEL:
        if (connection.mode, connection.variant) != (ConnectionMode.DIRECT, ConnectionVariant.V0):
            raise ValueError("WireGuard over WSTunnel supports only V0 direct")

        server = str(overrides.get("server") or endpoints.transit_host).strip()
        tls_server_name = str(overrides.get("tls_server_name") or server).strip()
        allowed_ips_raw = overrides.get("allowed_ips", endpoints.wireguard_allowed_ips)
        allowed_ips = (
            [str(item).strip() for item in allowed_ips_raw if str(item).strip()]
            if isinstance(allowed_ips_raw, (list, tuple))
            else [str(allowed_ips_raw).strip()]
        )
        if not allowed_ips or allowed_ips == [""]:
            allowed_ips = ["0.0.0.0/0", "::/0"]
        wstunnel_path = _normalize_http_path(
            overrides.get("wstunnel_path") or endpoints.wstunnel_path,
            field_name="wstunnel.path",
        )
        mtu = _normalize_int_range(
            overrides.get("mtu", endpoints.wireguard_mtu),
            field_name="wireguard.mtu",
            min_value=1200,
            max_value=1420,
        )
        persistent_keepalive = _normalize_int_range(
            overrides.get("persistent_keepalive", 25),
            field_name="wireguard.persistent_keepalive",
            min_value=0,
            max_value=60,
        )
        private_key = str(overrides.get("wireguard_private_key") or "").strip()
        public_key = str(overrides.get("wireguard_public_key") or "").strip()
        if not private_key or _is_placeholder(private_key):
            generated_keypair = generate_wireguard_keypair()
            private_key = generated_keypair.private_key
            public_key = generated_keypair.public_key
        elif not public_key or _is_placeholder(public_key):
            public_key = derive_wireguard_public_key(private_key)

        preshared_key = str(overrides.get("wireguard_preshared_key") or "").strip()
        if not preshared_key or _is_placeholder(preshared_key):
            preshared_key = generate_wireguard_preshared_key()

        server_public_key = str(
            overrides.get("wireguard_server_public_key") or endpoints.wireguard_server_public_key or ""
        ).strip()
        if not server_public_key or _is_placeholder(server_public_key):
            raise ValueError("wireguard_server_public_key is required for WireGuard over WSTunnel")

        wireguard_address = str(
            overrides.get("wireguard_address")
            or endpoints.wireguard_client_address
            or derive_wireguard_client_address(connection.id)
        ).strip()

        return {
            "protocol": "wireguard",
            "transport": "wstunnel",
            "profile": connection_profile_label(connection.protocol, connection.mode, connection.variant),
            "server": server,
            "port": 443,
            "sni": tls_server_name,
            "wstunnel": {
                "mode": "wireguard-over-websocket",
                "url": f"wss://{server}:443{wstunnel_path}",
                "path": wstunnel_path,
                "tls_server_name": tls_server_name,
                "local_udp_listen": _normalize_loopback_listen(
                    overrides.get("local_udp_listen") or "127.0.0.1:51820",
                    field_name="wstunnel.local_udp_listen",
                ),
            },
            "wireguard": {
                "private_key": private_key,
                "public_key": public_key,
                "preshared_key": preshared_key,
                "server_public_key": server_public_key,
                "address": wireguard_address,
                "allowed_ips": allowed_ips,
                "dns": overrides.get("dns", endpoints.wireguard_dns),
                "mtu": mtu,
                "persistent_keepalive": persistent_keepalive,
            },
            "local_socks": _local_socks_payload(
                listen=_local_socks_listen(overrides=overrides, user=user, device=device, connection=connection),
                user=user,
                device=device,
                connection=connection,
                overrides=overrides,
            ),
            "design_constraints": {
                "fixed_port_tcp": 443,
                "l3_overlay": True,
                "route_wstunnel_server_outside_tunnel": True,
                "live_peer_sync_required": True,
            },
            "chain": None,
        }

    raise ValueError(f"Unsupported protocol: {connection.protocol}")
