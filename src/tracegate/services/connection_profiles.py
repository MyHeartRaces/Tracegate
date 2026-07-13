from __future__ import annotations

from collections.abc import Iterable

from tracegate.enums import ConnectionMode, ConnectionProtocol, ConnectionVariant

MAX_DEVICES_PER_USER = 4
MAX_CONNECTIONS_PER_DEVICE = 5
MAX_ACTIVE_REVISIONS_PER_CONNECTION = 2
RESERVE_REVISION_SLOT = MAX_ACTIVE_REVISIONS_PER_CONNECTION - 1

_PROFILE_LIST_ORDER = {
    "reality": 10,
    "hysteria": 20,
    "entry": 30,
    "entry-ws-legacy": 31,
    "backup-grpc": 110,
    "backup-ws": 120,
    "backup-shadowtls": 130,
    "backup-wgws": 140,
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
        if conn_variant == ConnectionVariant.V5 and conn_mode == ConnectionMode.CHAIN:
            return "v5-entry-ws"
        return "v0-ws-vless"
    if proto == ConnectionProtocol.VLESS_GRPC_TLS:
        if conn_variant == ConnectionVariant.V5 and conn_mode == ConnectionMode.CHAIN:
            return "v5-universal-entry"
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
    if conn_mode == ConnectionMode.CHAIN:
        return "Tracegate-Chain"
    if proto == ConnectionProtocol.VLESS_REALITY:
        return "Tracegate-Reality"
    if proto == ConnectionProtocol.HYSTERIA2:
        return "Tracegate-Hysteria"
    if proto == ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS:
        return "Tracegate-Experimental(SS2022)"
    if proto == ConnectionProtocol.VLESS_WS_TLS:
        return "Tracegate-Backup(WebSocket)"
    if proto == ConnectionProtocol.VLESS_GRPC_TLS:
        return "Tracegate-Backup(gRPC)"
    if proto == ConnectionProtocol.WIREGUARD_WSTUNNEL:
        return "Tracegate-Experimental(WGWS)"
    return f"{conn_variant.value}-{conn_mode.value.capitalize()}-{proto.value}"


def supported_profile_specs() -> dict[str, tuple[ConnectionProtocol, ConnectionMode, ConnectionVariant]]:
    return {
        "reality": (ConnectionProtocol.VLESS_REALITY, ConnectionMode.DIRECT, ConnectionVariant.V1),
        "hysteria": (ConnectionProtocol.HYSTERIA2, ConnectionMode.DIRECT, ConnectionVariant.V2),
        "entry": (ConnectionProtocol.VLESS_REALITY, ConnectionMode.CHAIN, ConnectionVariant.V1),
        # Existing WS Chain connections remain valid and can be reissued, but
        # the bot no longer offers this compatibility profile for new connections.
        "entry-ws-legacy": (ConnectionProtocol.VLESS_WS_TLS, ConnectionMode.CHAIN, ConnectionVariant.V5),
        "backup-grpc": (ConnectionProtocol.VLESS_GRPC_TLS, ConnectionMode.DIRECT, ConnectionVariant.V0),
        "backup-ws": (ConnectionProtocol.VLESS_WS_TLS, ConnectionMode.DIRECT, ConnectionVariant.V0),
        "backup-shadowtls": (
            ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS,
            ConnectionMode.DIRECT,
            ConnectionVariant.V3,
        ),
        "backup-wgws": (ConnectionProtocol.WIREGUARD_WSTUNNEL, ConnectionMode.DIRECT, ConnectionVariant.V0),
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
        aliases = {
            "reality": {"v1direct", "v1-direct-reality-vless"},
            "hysteria": {"v2direct", "v2-direct-quic-hysteria"},
            "entry": {"universal", "v1chain", "v1-chain-reality-vless"},
            "entry-ws-legacy": {"v5-universal-entry", "v5-entry-ws"},
            "backup-grpc": {"v0grpc", "v0-grpc-vless"},
            "backup-ws": {"v0ws", "v0-ws-vless"},
            "backup-shadowtls": {"v3direct", "v3-direct-shadowtls-shadowsocks"},
            "backup-wgws": {"v0wgws", "v0-wgws-wireguard"},
        }
        names.update(aliases.get(key, set()))
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
