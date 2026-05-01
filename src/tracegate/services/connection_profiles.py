from __future__ import annotations

from collections.abc import Iterable

from tracegate.enums import ConnectionMode, ConnectionProtocol, ConnectionVariant

MAX_DEVICES_PER_USER = 5
MAX_CONNECTIONS_PER_DEVICE = 4
MAX_ACTIVE_REVISIONS_PER_CONNECTION = 2
RESERVE_REVISION_SLOT = MAX_ACTIVE_REVISIONS_PER_CONNECTION - 1

_PROFILE_LIST_ORDER = {
    "v1direct": 10,
    "v2direct": 20,
    "v3direct": 30,
    "v1chain": 110,
    "v2chain": 120,
    "v3chain": 130,
    "v0ws": 210,
    "v0grpc": 220,
    "v0wgws": 230,
}


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


def connection_profile_display_label(
    protocol: ConnectionProtocol | str,
    mode: ConnectionMode | str,
    variant: ConnectionVariant | str,
) -> str:
    proto = ConnectionProtocol(protocol)
    conn_mode = ConnectionMode(mode)
    conn_variant = ConnectionVariant(variant)
    version = conn_variant.value
    mode_label = conn_mode.value.capitalize()

    if proto == ConnectionProtocol.VLESS_REALITY:
        return f"{version}-{mode_label}-Reality-VLESS"
    if proto == ConnectionProtocol.HYSTERIA2:
        return f"{version}-{mode_label}-QUIC-Hysteria"
    if proto == ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS:
        return f"{version}-{mode_label}-ShadowTLS-Shadowsocks"
    if proto == ConnectionProtocol.VLESS_WS_TLS:
        return "V0-WS-VLESS"
    if proto == ConnectionProtocol.VLESS_GRPC_TLS:
        return "V0-gRPC-VLESS"
    if proto == ConnectionProtocol.WIREGUARD_WSTUNNEL:
        return "V0-WGWS-WireGuard"
    return f"{version}-{mode_label}-{proto.value}"


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


def profile_key_for(
    protocol: ConnectionProtocol | str,
    mode: ConnectionMode | str,
    variant: ConnectionVariant | str,
) -> str | None:
    spec = (ConnectionProtocol(protocol), ConnectionMode(mode), ConnectionVariant(variant))
    for key, candidate in supported_profile_specs().items():
        if candidate == spec:
            return key
    return None


def connection_profile_sort_key(
    protocol: ConnectionProtocol | str,
    mode: ConnectionMode | str,
    variant: ConnectionVariant | str,
) -> tuple[int, str]:
    key = profile_key_for(protocol, mode, variant)
    if key is None:
        return 999, connection_profile_label(protocol, mode, variant)
    return _PROFILE_LIST_ORDER.get(key, 999), key


def enabled_profile_keys(enabled_profile_names: Iterable[str] | None) -> set[str]:
    specs = supported_profile_specs()
    if enabled_profile_names is None:
        return set(specs)

    normalized = {str(name or "").strip().lower() for name in enabled_profile_names if str(name or "").strip()}
    if not normalized:
        return set()

    enabled: set[str] = set()
    for key, (protocol, mode, variant) in specs.items():
        names = {
            key.lower(),
            connection_profile_label(protocol, mode, variant).lower(),
            connection_profile_display_label(protocol, mode, variant).lower(),
        }
        if names & normalized:
            enabled.add(key)
    return enabled


def is_enabled_profile(
    protocol: ConnectionProtocol | str,
    mode: ConnectionMode | str,
    variant: ConnectionVariant | str,
    enabled_profile_names: Iterable[str] | None,
) -> bool:
    key = profile_key_for(protocol, mode, variant)
    return key is not None and key in enabled_profile_keys(enabled_profile_names)


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
