from __future__ import annotations

from tracegate.enums import ConnectionMode, ConnectionProtocol, ConnectionVariant

MAX_DEVICES_PER_USER = 5
MAX_CONNECTIONS_PER_DEVICE = 4
MAX_ACTIVE_REVISIONS_PER_CONNECTION = 2
RESERVE_REVISION_SLOT = MAX_ACTIVE_REVISIONS_PER_CONNECTION - 1


def connection_profile_label(
    protocol: ConnectionProtocol | str,
    mode: ConnectionMode | str,
    variant: ConnectionVariant | str,
) -> str:
    proto = ConnectionProtocol(protocol)
    conn_mode = ConnectionMode(mode)
    conn_variant = ConnectionVariant(variant)
    version = conn_variant.value.lower()

    if proto == ConnectionProtocol.VLESS_REALITY:
        return f"{version}-{conn_mode.value}-reality-vless"
    if proto == ConnectionProtocol.HYSTERIA2:
        return f"{version}-{conn_mode.value}-quic-hysteria"
    if proto == ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS:
        return f"{version}-{conn_mode.value}-shadowtls-shadowsocks"
    if proto == ConnectionProtocol.VLESS_WS_TLS:
        return "v0-ws-vless"
    if proto == ConnectionProtocol.VLESS_GRPC_TLS:
        return "v0-grpc-vless"
    if proto == ConnectionProtocol.WIREGUARD_WSTUNNEL:
        return "v0-wgws-wireguard"
    return f"{version}-{conn_mode.value}-{proto.value}"


def supported_profile_specs() -> dict[str, tuple[ConnectionProtocol, ConnectionMode, ConnectionVariant]]:
    return {
        "v1direct": (ConnectionProtocol.VLESS_REALITY, ConnectionMode.DIRECT, ConnectionVariant.V1),
        "v1chain": (ConnectionProtocol.VLESS_REALITY, ConnectionMode.CHAIN, ConnectionVariant.V1),
        "v2direct": (ConnectionProtocol.HYSTERIA2, ConnectionMode.DIRECT, ConnectionVariant.V2),
        "v2chain": (ConnectionProtocol.HYSTERIA2, ConnectionMode.CHAIN, ConnectionVariant.V2),
        "v3direct": (ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS, ConnectionMode.DIRECT, ConnectionVariant.V3),
        "v3chain": (ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS, ConnectionMode.CHAIN, ConnectionVariant.V3),
        "v0ws": (ConnectionProtocol.VLESS_WS_TLS, ConnectionMode.DIRECT, ConnectionVariant.V0),
        "v0grpc": (ConnectionProtocol.VLESS_GRPC_TLS, ConnectionMode.DIRECT, ConnectionVariant.V0),
        "v0wgws": (ConnectionProtocol.WIREGUARD_WSTUNNEL, ConnectionMode.DIRECT, ConnectionVariant.V0),
    }


def is_supported_profile(
    protocol: ConnectionProtocol,
    mode: ConnectionMode,
    variant: ConnectionVariant,
) -> bool:
    return (protocol, mode, variant) in set(supported_profile_specs().values())


def tcp_chain_selected_profiles() -> list[str]:
    return ["V1", "V3"]


def udp_chain_selected_profiles() -> list[str]:
    return ["V2"]


def router_transit_tcp_selected_profiles() -> list[str]:
    return ["V0", "V1", "V3"]


def router_transit_udp_selected_profiles() -> list[str]:
    return ["V2"]
