from __future__ import annotations

from tracegate.enums import ConnectionProtocol, ConnectionVariant, NodeRole


def target_roles_for_connection(protocol: ConnectionProtocol, variant: ConnectionVariant) -> list[NodeRole]:
    """
    Return node roles that must receive control-plane events for this connection.

    V2 chain events are sent to both Entry and Transit so the chain can be
    materialized on both nodes without dropping reconciliation.
    """
    if protocol in {ConnectionProtocol.VLESS_WS_TLS, ConnectionProtocol.VLESS_GRPC_TLS}:
        # TLS/gRPC compatibility profiles are direct-only and terminate on Transit.
        return [NodeRole.TRANSIT]
    if protocol == ConnectionProtocol.HYSTERIA2 and variant == ConnectionVariant.V4:
        # V4 terminates Hysteria on Entry, but the Entry -> Transit relay is
        # the same private link-crypto contract used by V2/V6.
        return [NodeRole.ENTRY, NodeRole.TRANSIT]
    if protocol == ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS and variant == ConnectionVariant.V6:
        return [NodeRole.ENTRY, NodeRole.TRANSIT]
    if protocol == ConnectionProtocol.WIREGUARD_WSTUNNEL:
        return [NodeRole.TRANSIT]
    if variant == ConnectionVariant.V2:
        return [NodeRole.ENTRY, NodeRole.TRANSIT]
    return [NodeRole.TRANSIT]
