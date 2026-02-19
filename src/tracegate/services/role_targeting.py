from __future__ import annotations

from tracegate.enums import ConnectionProtocol, ConnectionVariant, NodeRole


def target_roles_for_connection(protocol: ConnectionProtocol, variant: ConnectionVariant) -> list[NodeRole]:
    """
    Return node roles that must receive control-plane events for this connection.

    B2 chain events are sent to both VPS-E and VPS-T to support gradual migration
    between L4 forward mode and splitter mode without dropping reconciliation.
    """
    if protocol == ConnectionProtocol.WIREGUARD:
        return [NodeRole.VPS_T]
    if protocol == ConnectionProtocol.VLESS_WS_TLS:
        # WS+TLS is direct-only and terminates on VPS-T.
        return [NodeRole.VPS_T]
    if variant == ConnectionVariant.B2:
        return [NodeRole.VPS_E, NodeRole.VPS_T]
    return [NodeRole.VPS_T]
