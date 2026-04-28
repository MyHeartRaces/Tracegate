from tracegate.enums import ConnectionMode, ConnectionProtocol, ConnectionVariant, NodeRole
from tracegate.services.role_targeting import target_roles_for_connection


def test_chain_targets_entry_and_transit() -> None:
    roles = target_roles_for_connection(ConnectionProtocol.VLESS_REALITY, ConnectionVariant.V1, ConnectionMode.CHAIN)
    assert roles == [NodeRole.ENTRY, NodeRole.TRANSIT]


def test_direct_targets_only_transit() -> None:
    roles = target_roles_for_connection(ConnectionProtocol.VLESS_REALITY, ConnectionVariant.V1, ConnectionMode.DIRECT)
    assert roles == [NodeRole.TRANSIT]


def test_ws_tls_targets_only_transit_for_v0() -> None:
    roles = target_roles_for_connection(ConnectionProtocol.VLESS_WS_TLS, ConnectionVariant.V0, ConnectionMode.DIRECT)
    assert roles == [NodeRole.TRANSIT]


def test_grpc_tls_targets_only_transit_for_v0() -> None:
    roles = target_roles_for_connection(ConnectionProtocol.VLESS_GRPC_TLS, ConnectionVariant.V0, ConnectionMode.DIRECT)
    assert roles == [NodeRole.TRANSIT]


def test_hysteria_chain_v2_targets_entry_and_transit() -> None:
    roles = target_roles_for_connection(ConnectionProtocol.HYSTERIA2, ConnectionVariant.V2, ConnectionMode.CHAIN)
    assert roles == [NodeRole.ENTRY, NodeRole.TRANSIT]


def test_shadowsocks_chain_v3_targets_entry_and_transit() -> None:
    roles = target_roles_for_connection(
        ConnectionProtocol.SHADOWSOCKS2022_SHADOWTLS,
        ConnectionVariant.V3,
        ConnectionMode.CHAIN,
    )
    assert roles == [NodeRole.ENTRY, NodeRole.TRANSIT]


def test_wireguard_wstunnel_v0_targets_only_transit() -> None:
    roles = target_roles_for_connection(ConnectionProtocol.WIREGUARD_WSTUNNEL, ConnectionVariant.V0, ConnectionMode.DIRECT)
    assert roles == [NodeRole.TRANSIT]
