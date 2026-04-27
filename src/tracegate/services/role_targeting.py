from __future__ import annotations

from tracegate.enums import ConnectionMode, ConnectionProtocol, ConnectionVariant, NodeRole


def target_roles_for_connection(
    protocol: ConnectionProtocol,
    variant: ConnectionVariant,
    mode: ConnectionMode | None = None,
) -> list[NodeRole]:
    """
    Return node roles that must receive control-plane events for this connection.

    Tracegate 2.2 uses the explicit connection mode to distinguish Direct from
    Chain because the same version number can now exist in both modes.
    """
    if mode == ConnectionMode.CHAIN:
        if protocol in {
            ConnectionProtocol.VLESS_REALITY,
            ConnectionProtocol.HYSTERIA2,
            ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS,
        }:
            return [NodeRole.ENTRY, NodeRole.TRANSIT]
        return [NodeRole.TRANSIT]

    if mode == ConnectionMode.DIRECT:
        return [NodeRole.TRANSIT]

    if protocol in {ConnectionProtocol.VLESS_WS_TLS, ConnectionProtocol.VLESS_GRPC_TLS}:
        # TLS/gRPC compatibility profiles are direct-only and terminate on Transit.
        return [NodeRole.TRANSIT]
    if protocol == ConnectionProtocol.HYSTERIA2 and variant == ConnectionVariant.V4:
        # Legacy V4 terminates Hysteria on Entry.
        return [NodeRole.ENTRY, NodeRole.TRANSIT]
    if protocol == ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS and variant == ConnectionVariant.V6:
        return [NodeRole.ENTRY, NodeRole.TRANSIT]
    if protocol == ConnectionProtocol.WIREGUARD_WSTUNNEL:
        return [NodeRole.TRANSIT]
    if variant == ConnectionVariant.V2:
        return [NodeRole.ENTRY, NodeRole.TRANSIT]
    return [NodeRole.TRANSIT]
